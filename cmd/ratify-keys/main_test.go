package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

var testNow = time.Unix(1_800_000_000, 0)

func fixedNow() time.Time { return testNow }

// generateKey runs generate and returns the key path, the printed public
// key JSON, and the printed key ID.
func generateKey(t *testing.T, dir, name string) (string, []byte, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	var out, notes bytes.Buffer
	if err := run([]string{"generate", "--out", path}, &out, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(strings.TrimPrefix(notes.String(), "Key ID: "))
	return path, out.Bytes(), id
}

func writeChallenge(t *testing.T, dir string, c map[string]any) string {
	t.Helper()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "challenge.json")
	os.Remove(path)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// apiChallenge mirrors the enrollment challenge response the API returns.
func apiChallenge(keyID string) map[string]any {
	return map[string]any{"challenge_id": strings.Repeat("c", 32), "challenge": strings.Repeat("b", 64),
		"audience": "https://verify.example", "authority_id": strings.Repeat("a", 32), "key_id": keyID,
		"role": "organization_root", "custody_mode": "customer_held", "expires_at": testNow.Add(10 * time.Minute).UTC()}
}

// The public key output must be what the console posts as public_key and
// the proof file must be the exact bytes Verify's enrollment check accepts,
// including recomputing the key ID and comparing every challenge field.
func TestRatifyKeysRoundTripPassesServerPossessionCheck(t *testing.T) {
	dir := t.TempDir()
	keyPath, publicJSON, keyID := generateKey(t, dir, "root.key")
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions: %v %v", info, err)
	}
	var public ratify.HybridPublicKey
	decoder := json.NewDecoder(bytes.NewReader(publicJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&public); err != nil {
		t.Fatalf("public key JSON is not the console's public_key shape: %v", err)
	}
	if id, err := setup.V2KeyID(public); err != nil || id != keyID {
		t.Fatalf("printed key ID %q does not match the public key (%q, %v)", keyID, id, err)
	}
	var again, againNotes bytes.Buffer
	if err := run([]string{"public", "--key", keyPath}, &again, &againNotes, fixedNow); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Bytes(), publicJSON) || !strings.Contains(againNotes.String(), keyID) {
		t.Fatal("public does not reproduce the generated public key and key ID")
	}

	c := apiChallenge(keyID)
	challengePath := writeChallenge(t, dir, c)
	proofPath := filepath.Join(dir, "proof.json")
	var notes bytes.Buffer
	if err := run([]string{"prove", "--key", keyPath, "--challenge", challengePath, "--out", proofPath,
		"--role", "organization_root"}, &bytes.Buffer{}, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	// The console uploads the file bytes as base64 possession_proof; the
	// API decodes that field as []byte.
	var request struct {
		PossessionProof []byte `json:"possession_proof"`
	}
	body := `{"possession_proof":"` + base64.StdEncoding.EncodeToString(proof) + `"}`
	if err := json.Unmarshal([]byte(body), &request); err != nil || !bytes.Equal(request.PossessionProof, proof) {
		t.Fatalf("proof does not survive the upload encoding: %v", err)
	}
	expected := setup.V2KeyEnrollmentExpectation{Audience: c["audience"].(string), Challenge: c["challenge"].(string),
		ChallengeID: c["challenge_id"].(string), CustodyMode: "customer_held",
		OwnerID: c["authority_id"].(string), Role: "organization_root"}
	// Server time a little after signing, as when the customer uploads.
	enrolled, provedID, err := setup.VerifyV2KeyPossessionProof(request.PossessionProof, expected, testNow.Unix()+30)
	if err != nil {
		t.Fatalf("server possession check refused the proof: %v", err)
	}
	if provedID != keyID || !bytes.Equal(enrolled.Ed25519, public.Ed25519) || !bytes.Equal(enrolled.MLDSA65, public.MLDSA65) {
		t.Fatal("the proof enrolls a different key than the challenge names")
	}
	// A different challenge value or owner must not verify with this proof.
	other := expected
	other.OwnerID = strings.Repeat("d", 32)
	if _, _, err := setup.VerifyV2KeyPossessionProof(proof, other, testNow.Unix()); err == nil {
		t.Fatal("proof verified for a different owner")
	}
	if strings.Contains(notes.String(), "private") {
		t.Fatalf("output mentions private material: %s", notes.String())
	}
}

func TestRatifyKeysProveRefusals(t *testing.T) {
	dir := t.TempDir()
	keyPath, _, keyID := generateKey(t, dir, "mine.key")
	_, _, otherID := generateKey(t, dir, "other.key")
	cases := map[string]struct {
		edit func(map[string]any)
		args []string
		want string
	}{
		"wrong key":        {edit: func(c map[string]any) { c["key_id"] = otherID }, want: "your key file holds key"},
		"expired":          {edit: func(c map[string]any) { c["expires_at"] = testNow.Add(-time.Second).UTC() }, want: "expired"},
		"expires now":      {edit: func(c map[string]any) { c["expires_at"] = testNow.UTC() }, want: "expired"},
		"custodial":        {edit: func(c map[string]any) { c["custody_mode"] = "ratify_custodial" }, want: "customer_held"},
		"unknown role":     {edit: func(c map[string]any) { c["role"] = "superuser" }, want: "unknown role"},
		"role mismatch":    {edit: func(map[string]any) {}, args: []string{"--role", "issuer"}, want: `not "issuer"`},
		"missing field":    {edit: func(c map[string]any) { delete(c, "authority_id") }, want: "missing fields"},
		"bad challenge id": {edit: func(c map[string]any) { c["challenge_id"] = "nothex" }, want: "cannot be signed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := apiChallenge(keyID)
			tc.edit(c)
			challengePath := writeChallenge(t, dir, c)
			proofPath := filepath.Join(dir, "proof-"+strings.ReplaceAll(name, " ", "-")+".json")
			args := append([]string{"prove", "--key", keyPath, "--challenge", challengePath, "--out", proofPath}, tc.args...)
			err := run(args, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want refusal containing %q", err, tc.want)
			}
			if _, err := os.Stat(proofPath); !os.IsNotExist(err) {
				t.Fatal("a refused challenge still wrote a proof file")
			}
		})
	}
}

func TestRatifyKeysFilePermissionRefusals(t *testing.T) {
	dir := t.TempDir()
	keyPath, _, keyID := generateKey(t, dir, "mine.key")

	// Never overwrite an existing key, and leave it unchanged.
	before, _ := os.ReadFile(keyPath)
	if err := run([]string{"generate", "--out", keyPath}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("generate overwrote a key: %v", err)
	}
	if after, _ := os.ReadFile(keyPath); !bytes.Equal(before, after) {
		t.Fatal("existing key file changed")
	}
	// Never write through a symbolic link.
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(filepath.Join(dir, "target.key"), link); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"generate", "--out", link}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil {
		t.Fatal("generate followed a symbolic link")
	}
	if _, err := os.Stat(filepath.Join(dir, "target.key")); !os.IsNotExist(err) {
		t.Fatal("generate created the symbolic link's target")
	}
	// Refuse folders other users can write to.
	for _, mode := range []os.FileMode{0777, 0770, 0702} {
		shared := filepath.Join(dir, "shared"+mode.String())
		if err := os.Mkdir(shared, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(shared, mode); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(shared, "k.key")
		if err := run([]string{"generate", "--out", out}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil ||
			!strings.Contains(err.Error(), "other users can write") {
			t.Fatalf("generate accepted a %v folder: %v", mode, err)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("generate wrote into a shared folder")
		}
	}
	// Refuse a key file others can read, for public and prove alike.
	if err := os.Chmod(keyPath, 0640); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"public", "--key", keyPath}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil ||
		!strings.Contains(err.Error(), "readable only by you") {
		t.Fatalf("public accepted a group-readable key: %v", err)
	}
	challengePath := writeChallenge(t, dir, apiChallenge(keyID))
	if err := run([]string{"prove", "--key", keyPath, "--challenge", challengePath, "--out", filepath.Join(dir, "p.json")},
		&bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil || !strings.Contains(err.Error(), "readable only by you") {
		t.Fatalf("prove accepted a group-readable key: %v", err)
	}
	// A corrupt key file is refused without echoing its contents.
	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.key")
	secret := `{"ed25519_private_key":"SECRETSECRET","mldsa65_private_key":""}`
	if err := os.WriteFile(bad, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"public", "--key", bad}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("corrupt key file: %v", err)
	}
	// prove refuses to overwrite an existing proof file.
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"prove", "--key", keyPath, "--challenge", challengePath, "--out", existing},
		&bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("prove overwrote a file: %v", err)
	}
}

// A customer matches a downloaded binary to its release notes by version, so
// --version must print the version the release build embedded.
func TestVersionPrintsEmbeddedVersion(t *testing.T) {
	defer func(old string) { version = old }(version)
	version = "v1.2.3"
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--version"}, &stdout, &stderr, time.Now); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "ratify-keys v1.2.3\n" {
		t.Fatalf("stdout %q", stdout.String())
	}
}
