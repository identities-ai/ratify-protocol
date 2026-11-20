package verifyclient

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// exportedSymbols lists every exported identifier of the non-test Go files
// in each package directory under the module's verifyclient tree: types,
// functions, constants, variables, methods (Type.Method), struct fields
// (Type.Field), and interface methods. A field is part of the wire format,
// so a new one is a public change like any other.
func exportedSymbols(t *testing.T) []string {
	t.Helper()
	var symbols []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || d.Name() == "testdata" {
			if d != nil && d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return err
		}
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, path, func(info os.FileInfo) bool {
			return !strings.HasSuffix(info.Name(), "_test.go")
		}, 0)
		if err != nil {
			return err
		}
		// Symbols are keyed by directory, not by package name, so two
		// directories declaring the same package name stay distinct.
		dir := filepath.ToSlash(path)
		for _, pkg := range pkgs {
			for _, file := range pkg.Files {
				for _, decl := range file.Decls {
					symbols = append(symbols, declSymbols(dir, decl)...)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(symbols)
	return slices.Compact(symbols)
}

func declSymbols(pkg string, decl ast.Decl) []string {
	var out []string
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if !d.Name.IsExported() {
			return nil
		}
		if d.Recv == nil {
			return []string{pkg + "." + d.Name.Name}
		}
		// An exported method is reachable through any value of its
		// receiver, even an unexported or generic one, so it is listed
		// under the receiver's name either way.
		recv := d.Recv.List[0].Type
		if star, ok := recv.(*ast.StarExpr); ok {
			recv = star.X
		}
		switch generic := recv.(type) {
		case *ast.IndexExpr:
			recv = generic.X
		case *ast.IndexListExpr:
			recv = generic.X
		}
		if ident, ok := recv.(*ast.Ident); ok {
			out = append(out, pkg+"."+ident.Name+"."+d.Name.Name)
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, name := range s.Names {
					if name.IsExported() {
						out = append(out, pkg+"."+name.Name)
					}
				}
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					out = append(out, pkg+"."+s.Name.Name)
				}
				// Exported fields and interface methods are listed for
				// unexported types too: a caller can reach them through
				// a returned value.
				var fields *ast.FieldList
				switch typ := s.Type.(type) {
				case *ast.StructType:
					fields = typ.Fields
				case *ast.InterfaceType:
					fields = typ.Methods
				}
				if fields == nil {
					continue
				}
				for _, field := range fields.List {
					for _, name := range field.Names {
						if name.IsExported() {
							out = append(out, pkg+"."+s.Name.Name+"."+name.Name)
						}
					}
					if len(field.Names) == 0 {
						out = append(out, pkg+"."+s.Name.Name+".(embedded "+types.ExprString(field.Type)+")")
					}
				}
			}
		}
	}
	return out
}

func allowlist(t *testing.T) []string {
	t.Helper()
	file, err := os.Open("PUBLIC_API.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// Anything these packages export is public API that customers may build
// on, so the surface grows only by an explicit, reviewed edit to
// PUBLIC_API.txt, never as a side effect of another change.
func TestExportedSymbolsMatchAllowlist(t *testing.T) {
	exported, allowed := exportedSymbols(t), allowlist(t)
	for _, symbol := range exported {
		if _, found := slices.BinarySearch(allowed, symbol); !found {
			t.Errorf("exported symbol %s is not in PUBLIC_API.txt", symbol)
		}
	}
	for _, symbol := range allowed {
		if _, found := slices.BinarySearch(exported, symbol); !found {
			t.Errorf("PUBLIC_API.txt lists %s, which is not exported", symbol)
		}
	}
}

const module = "github.com/identities-ai/ratify-protocol/v2"

// tools are the customer-run commands built on these packages.
var tools = []string{
	module + "/cmd/ratify-keys",
	module + "/cmd/ratify-reference-receiver",
	module + "/cmd/ratify-iam-bridge",
	module + "/cmd/ratify-okta-status-source",
	module + "/cmd/ratify-entra-status-source",
	module + "/cmd/ratify-google-status-source",
}

// The client packages and the customer tools stay small and auditable.
// Every package they build with is the standard library (minus
// database/sql), the protocol package and its pinned time-zone data, these
// packages, the tools' shared internals, or the protocol module's own
// cryptography dependencies. No storage, database driver or cloud key
// service. A new dependency of the protocol package is not allowed here
// automatically: it is added to this list on purpose.
func TestDependenciesStayClientSide(t *testing.T) {
	allowedPackages := []string{module, module + "/internal/tzdbv2"}
	allowedTrees := []string{
		module + "/verifyclient",
		module + "/internal/statussource",
		module + "/internal/toolversion",
		"github.com/cloudflare/circl",
		"filippo.io/edwards25519",
		"golang.org/x/sys",
	}
	check := func(target string, patterns ...string) {
		t.Helper()
		args := append([]string{"-deps", "-test", "-f", "{{.ImportPath}} {{.Standard}}"}, patterns...)
		for _, line := range strings.Split(strings.TrimSpace(goList(t, target, args...)), "\n") {
			path, standard, _ := strings.Cut(line, " ")
			path, _, _ = strings.Cut(path, " [")
			path = strings.TrimSuffix(path, ".test")
			if standard == "true" {
				if inTree(path, "database/sql") {
					t.Errorf("%s: %v imports %s", target, patterns, path)
				}
				continue
			}
			if slices.Contains(patterns, path) || slices.Contains(allowedPackages, path) {
				continue
			}
			if !slices.ContainsFunc(allowedTrees, func(tree string) bool { return inTree(path, tree) }) {
				t.Errorf("%s: %v depends on %s", target, patterns, path)
			}
		}
	}
	for _, target := range targets {
		check(target, module+"/verifyclient/...")
		check(target, tools...)
	}
}

// targets are the supported build targets. Every dependency check runs for
// each, so a file behind a build constraint cannot hide an import.
var targets = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"}

// inTree reports whether path is tree or a package below it, matching whole
// path segments only.
func inTree(path, tree string) bool {
	return path == tree || strings.HasPrefix(path, tree+"/")
}

// The dependency points one way: verifyclient builds on the protocol, and
// the protocol packages, SDK examples and references never import
// verifyclient. Only commands and internal helpers may. The check runs for
// every supported build target.
func TestProtocolPackagesDoNotImportVerifyClient(t *testing.T) {
	for _, target := range targets {
		out := goList(t, target, "-deps", "-test", "-f", "{{.ImportPath}} {{join .Deps \" \"}}", module+"/...")
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			path, deps, _ := strings.Cut(line, " ")
			path, _, _ = strings.Cut(path, " [")
			path = strings.TrimSuffix(path, ".test")
			if !inTree(path, module) {
				continue
			}
			rest := strings.TrimPrefix(path, module)
			if inTree(rest, "/verifyclient") || strings.HasPrefix(rest, "/cmd/") || strings.HasPrefix(rest, "/internal/") {
				continue
			}
			for _, dep := range strings.Fields(deps) {
				if inTree(dep, module+"/verifyclient") {
					t.Errorf("%s: %s depends on %s", target, path, dep)
				}
			}
		}
	}
}

// The symbol inventory must see every way a member becomes reachable:
// methods on unexported and generic receivers, exported fields of
// unexported types, and each embedded type by name.
func TestDeclSymbolsSeesReachableMembers(t *testing.T) {
	const src = `package p
type hidden struct{ Field int }
func (hidden) Method() {}
type G[T any] struct{}
func (G[T]) M() {}
type L[K comparable, V any] struct{}
func (*L[K, V]) N() {}
type E struct{ hidden; *G[int] }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, decl := range file.Decls {
		got = append(got, declSymbols("p", decl)...)
	}
	for _, want := range []string{"p.hidden.Field", "p.hidden.Method", "p.G", "p.G.M", "p.L.N",
		"p.E", "p.E.(embedded hidden)", "p.E.(embedded *G[int])"} {
		if !slices.Contains(got, want) {
			t.Errorf("declSymbols missed %s (got %v)", want, got)
		}
	}
}

// goList runs go list for one GOOS/GOARCH target.
func goList(t *testing.T, target string, args ...string) string {
	t.Helper()
	goos, goarch, _ := strings.Cut(target, "/")
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list (%s): %v\n%s", target, err, out)
	}
	return string(out)
}
