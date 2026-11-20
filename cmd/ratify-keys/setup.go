package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

var orgIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Combined setup files, inside the folder `setup` creates.
const (
	setupRootKey   = "root.key"
	setupIssuerKey = "issuer.key"
	setupStatusKey = "issuer-status.key"
	setupRequest   = "setup-request.json"
)

// setupCommand runs `ratify-keys setup issuer --offline`: it creates the
// issuer and issuer status keys (and the organization root, unless
// --root-key names the existing one), signs the issuer authorization with
// the root locally, and writes one request file to upload in the console.
// Nothing is sent anywhere.
func setupCommand(args []string, stderr io.Writer, now time.Time) error {
	if len(args) > 0 && args[0] == "renew-issuer" {
		return renewIssuerCommand(args[1:], stderr, now)
	}
	if len(args) == 0 || args[0] != "issuer" {
		return errors.New("use: ratify-keys setup issuer --offline --org ORGANIZATION_ID --out FOLDER [--root-key ROOTKEYFILE] [--valid-for 2160h], or ratify-keys setup renew-issuer --dir FOLDER --org ORGANIZATION_ID --out RENEWAL.json [--root-key ROOTKEYFILE] [--valid-for 2160h]")
	}
	fs := flag.NewFlagSet("ratify-keys setup issuer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	offline := fs.Bool("offline", false, "write a request file to upload in the console")
	outDir := fs.String("out", "", "new folder for the keys and the request file")
	orgID := fs.String("org", "", "the organization ID the console shows in this command")
	rootKeyPath := fs.String("root-key", "", "the organization's existing root key file")
	validFor := fs.Duration("valid-for", maxDelegationValidity, "how long the issuer authorization is valid")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !*offline {
		return errors.New("setup currently needs --offline: it writes a request file that you upload in the console")
	}
	if *outDir == "" {
		return errors.New("setup needs --out FOLDER, a folder that does not exist yet")
	}
	if !orgIDPattern.MatchString(*orgID) {
		return errors.New("setup needs --org ORGANIZATION_ID: copy the command from the console's setup page")
	}
	if *validFor <= 0 || *validFor > maxDelegationValidity {
		return fmt.Errorf("--valid-for must be more than 0 and at most %s", maxDelegationValidity)
	}
	var root ratify.HybridPrivateKey
	if *rootKeyPath != "" {
		var err error
		if root, err = loadKey(*rootKeyPath); err != nil {
			return err
		}
	}
	// A fresh folder only its owner can open; generate refuses to overwrite.
	if err := os.Mkdir(*outDir, 0700); err != nil {
		return fmt.Errorf("could not create %s (it must not exist yet): %w", *outDir, err)
	}
	if err := os.Chmod(*outDir, 0700); err != nil {
		return err
	}
	keyIn := func(name string) (ratify.HybridPrivateKey, error) {
		path := filepath.Join(*outDir, name)
		if err := generate(path, io.Discard, io.Discard); err != nil {
			return ratify.HybridPrivateKey{}, err
		}
		return loadKey(path)
	}
	newRoot := *rootKeyPath == ""
	if newRoot {
		var err error
		if root, err = keyIn(setupRootKey); err != nil {
			return err
		}
	}
	issuer, err := keyIn(setupIssuerKey)
	if err != nil {
		return err
	}
	status, err := keyIn(setupStatusKey)
	if err != nil {
		return err
	}
	rootID, err := setup.V2KeyID(root.Public())
	if err != nil {
		return err
	}
	issuerID, err := setup.V2KeyID(issuer.Public())
	if err != nil {
		return err
	}
	statusID, err := setup.V2KeyID(status.Public())
	if err != nil {
		return err
	}
	issued := now.Unix() - 60
	cert, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{Version: 2,
		CertID: "issuer-authorization-" + issuerID[:16], IssuerID: rootID, IssuerPubKey: root.Public(),
		SubjectID: issuerID, SubjectPubKey: issuer.Public(), Scope: []string{"identity:delegate"},
		Constraints: []ratify.ConstraintV2{}, IssuedAt: issued, ExpiresAt: issued + int64(validFor.Seconds())}, root)
	if err != nil {
		return fmt.Errorf("the issuer authorization cannot be signed: %v", err)
	}
	authorization, err := ratify.EncodeDelegationCertV2(cert)
	if err != nil {
		return err
	}
	request, err := ratify.CanonicalJSON(setup.V2KeySetupRequest{Version: 1, Kind: setup.V2KeySetupRequestKind,
		NewRoot: newRoot, OrganizationID: *orgID, RootPublicKey: root.Public(), IssuerPublicKey: issuer.Public(),
		StatusPublicKey: status.Public(), IssuerAuthorization: authorization, Epoch: 1})
	if err != nil {
		return err
	}
	// Check the request exactly as Verify will before writing it.
	if _, err := setup.ParseV2KeySetupRequest(request, now.Unix()); err != nil {
		return fmt.Errorf("the setup request did not pass Verify's check: %v", err)
	}
	dir, err := os.OpenRoot(*outDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	requestPath := filepath.Join(*outDir, setupRequest)
	if err := writeNew(dir, setupRequest, requestPath, request, 0644); err != nil {
		return err
	}
	rootLine := "existing root " + rootID
	if newRoot {
		rootLine = "new root      " + rootID + "  (" + filepath.Join(*outDir, setupRootKey) + ")"
	}
	_, err = fmt.Fprintf(stderr, `Created your keys for organization %s in %s:
  %s
  issuer        %s
  issuer status %s
The issuer authorization is valid until %s.

Next: in the console, open Signing keys > Set up issuer, upload
  %s
download the challenge bundle, then run
  ratify-keys prove --bundle BUNDLE.json --dir %s --out PROOFS.json%s
and upload PROOFS.json. Private keys never leave this folder.
`, *orgID, *outDir, rootLine, issuerID, statusID, time.Unix(cert.ExpiresAt, 0).UTC().Format(time.RFC3339),
		requestPath, *outDir, rootFlagHint(*rootKeyPath))
	if err == nil && newRoot {
		_, err = fmt.Fprintf(stderr, "After setup, move %s to offline storage; it is needed only to authorize issuers.\n",
			filepath.Join(*outDir, setupRootKey))
	}
	return err
}

func rootFlagHint(path string) string {
	if path == "" {
		return ""
	}
	return " --root-key " + path
}

// proveBundleCommand runs `ratify-keys prove --bundle`: it signs every
// challenge in the bundle with the matching key from the setup folder and
// writes one proof file. It refuses a bundle for another request, and any
// challenge that names a key or role other than the one the folder holds.
func proveBundleCommand(args []string, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("ratify-keys prove --bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	bundlePath := fs.String("bundle", "", "the challenge bundle from the console")
	dirPath := fs.String("dir", "", "the folder `ratify-keys setup` created")
	outPath := fs.String("out", "", "file to create")
	rootKeyPath := fs.String("root-key", "", "the existing root key file, if setup used --root-key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *bundlePath == "" || *dirPath == "" || *outPath == "" {
		return errors.New("prove --bundle needs --bundle BUNDLE.json, --dir FOLDER, and --out PROOFS.json")
	}
	request, err := readLimitedFile(filepath.Join(*dirPath, setupRequest), maxInputBytes)
	if err != nil {
		return err
	}
	var parsed setup.V2KeySetupRequest
	if err := json.Unmarshal(request, &parsed); err != nil {
		return fmt.Errorf("%s is not a setup request", filepath.Join(*dirPath, setupRequest))
	}
	bundleData, err := readLimitedFile(*bundlePath, maxInputBytes)
	if err != nil {
		return err
	}
	var bundle setup.V2KeySetupBundle
	dec := json.NewDecoder(bytes.NewReader(bundleData))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil || bundle.Version != 1 || bundle.Kind != setup.V2KeySetupBundleKind {
		return fmt.Errorf("%s is not a challenge bundle from the console", *bundlePath)
	}
	// The digest binds the bundle to exactly the request this folder wrote,
	// so a bundle for other keys or another setup is refused.
	if bundle.RequestDigest != setup.V2KeySetupDigest(request) {
		return errors.New("this bundle is for a different setup request than the one in --dir")
	}
	// The request names its organization; a bundle from any other
	// organization is refused, so these keys can be enrolled only there.
	if bundle.OrganizationID != parsed.OrganizationID {
		return fmt.Errorf("this bundle is for organization %s, but this setup is for %s", bundle.OrganizationID, parsed.OrganizationID)
	}
	if bundle.Epoch != parsed.Epoch {
		return fmt.Errorf("this bundle binds epoch %d, but the request proposed %d", bundle.Epoch, parsed.Epoch)
	}
	keyFor := map[string]string{"issuer": filepath.Join(*dirPath, setupIssuerKey),
		"issuer_status": filepath.Join(*dirPath, setupStatusKey)}
	if parsed.NewRoot {
		keyFor["organization_root"] = filepath.Join(*dirPath, setupRootKey)
	}
	if *rootKeyPath != "" && parsed.NewRoot {
		return errors.New("--root-key is only for a setup that used an existing root")
	}
	out := setup.V2KeySetupProofs{Version: 1, Kind: setup.V2KeySetupProofsKind, SetupID: bundle.SetupID,
		RequestDigest: bundle.RequestDigest, Proofs: []setup.V2KeySetupProof{}}
	if len(bundle.Challenges) == 0 || len(bundle.Challenges) > 3 {
		return errors.New("this bundle has no challenges to sign")
	}
	seen := map[string]bool{}
	for _, c := range bundle.Challenges {
		path, ok := keyFor[c.Role]
		if !ok || seen[c.Role] {
			return fmt.Errorf("this bundle asks for a %q key that this setup does not enroll", c.Role)
		}
		seen[c.Role] = true
		private, err := loadKey(path)
		if err != nil {
			return err
		}
		// The challenge value commits to the organization it was issued in;
		// a challenge from any other organization does not recompute.
		if c.Challenge != setup.V2KeySetupChallengeValue(parsed.OrganizationID, c.Role, c.KeyID, c.Nonce) {
			return fmt.Errorf("the %s challenge was not issued for organization %s", c.Role, parsed.OrganizationID)
		}
		proof, err := signChallenge(private, challenge{Audience: c.Audience, AuthorityID: c.AuthorityID,
			Challenge: c.Challenge, ChallengeID: c.ChallengeID, CustodyMode: c.CustodyMode,
			ExpiresAt: c.ExpiresAt, KeyID: c.KeyID, Role: c.Role}, c.Role, now)
		if err != nil {
			return fmt.Errorf("%s challenge: %w", c.Role, err)
		}
		out.Proofs = append(out.Proofs, setup.V2KeySetupProof{ChallengeID: c.ChallengeID, KeyID: c.KeyID,
			Role: c.Role, PossessionProof: proof})
	}
	wire, err := ratify.CanonicalJSON(out)
	if err != nil {
		return err
	}
	if _, err := setup.ParseV2KeySetupProofs(wire); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(*outPath))
	if err != nil {
		return fmt.Errorf("proof folder: %w", err)
	}
	defer root.Close()
	if err := writeNew(root, filepath.Base(*outPath), *outPath, wire, 0644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Wrote %s with %d proofs. Upload it before %s.\n",
		*outPath, len(out.Proofs), bundle.ExpiresAt.Local().Format(time.RFC1123))
	return err
}
