// ratify-keys creates and uses customer-held Protocol v2 hybrid keys on the
// customer's own machine. It signs the key-possession proof (Verify code
// 0x0114) for an enrollment challenge; the private key never leaves the key
// file and is never printed.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/internal/toolversion"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/exportsig"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

// keyFile is the private key file format ratify-keys writes and reads.
type keyFile struct {
	Ed25519 []byte `json:"ed25519_private_key"`
	MLDSA65 []byte `json:"mldsa65_private_key"`
}

// challenge is the enrollment challenge exactly as the API returns it and
// the console shows it.
type challenge struct {
	Audience    string    `json:"audience"`
	AuthorityID string    `json:"authority_id"`
	Challenge   string    `json:"challenge"`
	ChallengeID string    `json:"challenge_id"`
	CustodyMode string    `json:"custody_mode"`
	ExpiresAt   time.Time `json:"expires_at"`
	KeyID       string    `json:"key_id"`
	Role        string    `json:"role"`
}

const maxInputBytes = 64 << 10

// Roles a customer-held key can be enrolled for.
var customerRoles = map[string]bool{"organization_root": true, "issuer": true, "issuer_status": true,
	"approver": true, "receiver": true, "personal_root": true, "agent": true}

const usage = `ratify-keys creates and uses your own Ratify signing keys.
Your private key stays in a file on this machine. It is never printed or sent anywhere.

Commands:
  ratify-keys setup issuer --offline --org ORGANIZATION_ID --out FOLDER [--root-key ROOTKEYFILE] [--valid-for 2160h]
      Set up your organization's signing keys in one pass. Creates FOLDER
      (readable only by you) with a new organization root (root.key, unless
      --root-key names your existing root), an issuer key (issuer.key), and
      an issuer status key (issuer-status.key). Signs the issuer's
      authorization with the root on this machine and writes one request
      file, setup-request.json, usable only in organization ORGANIZATION_ID.
      Copy this command from the console's setup page and upload the file there,
      which shows the key IDs and the status-key epoch to confirm, and gives
      you one challenge bundle.

  ratify-keys setup renew-issuer --dir FOLDER --org ORGANIZATION_ID --out RENEWAL.json [--root-key ROOTKEYFILE] [--valid-for 2160h]
      Renew the issuer's authorization before it expires (at most 90 days).
      The root in FOLDER (or --root-key) signs a new identity:delegate
      authorization for the same issuer key on this machine and writes one
      request file. Upload it with Renew on the console's setup page. The
      issuer keeps working with its current authorization until Verify
      confirms the renewal. A new issuer key is a rotation, not a renewal.

  ratify-keys prove --bundle BUNDLE.json --dir FOLDER --out PROOFS.json [--root-key ROOTKEYFILE]
      Sign every challenge in a setup's challenge bundle with the matching
      key in FOLDER and write one proof file to upload. Refuses a bundle for
      a different request or organization, and any challenge for a key or
      role FOLDER does not hold.

  ratify-keys generate --out KEYFILE
      Create a new key pair. Saves the private key to KEYFILE, readable only
      by you, and prints the public key and key ID. Paste the public key into
      the console to request an enrollment challenge.

  ratify-keys public --key KEYFILE
      Print the public key and key ID for an existing key file.

  ratify-keys prove --key KEYFILE --challenge CHALLENGE.json --out PROOF.json [--role ROLE]
      Sign an enrollment challenge with your key. Save the challenge the
      console shows (or the API returns) as CHALLENGE.json. Submit the
      PROOF.json this writes before the challenge expires: in the console's
      upload field, or as possession_proof (the file's bytes in base64) when
      you call the API. Organization root and issuer keys are enrolled
      through their own signing root and signing issuer steps.
      With --role, the challenge must be for that role.

  ratify-keys delegate --key KEYFILE --subject PUBLIC.json --cert-id ID --scope SCOPES --valid-for DURATION --out CERT.json [--receiver-id ID]
      Sign a Protocol v2 delegation certificate from your key to the
      subject's public key. Use it as the organization root to authorize an
      issuer key (--scope identity:delegate; upload CERT.json as the
      issuer's root delegation), or as an issuer to grant an agent an exact
      certificate ID (the ID your IAM mapping names). At most 90 days.
      With --receiver-id, the certificate is usable only at that receiver,
      as the Verify MCP connect flow requires.

  ratify-keys sign-receiver-profile --key SIGNERKEYFILE --spec SPEC.json --out PROFILE.json [--previous INSTALLED.json] [--valid-for 720h]
      Sign a receiver profile from the unsigned spec the console gives you,
      for example the Verify MCP receiver's. Your key becomes the profile's
      configuration signer; a renewal names the installed profile with
      --previous and must be signed by the same key. Upload PROFILE.json on
      the console page that gave you the spec. At most 30 days.

  ratify-keys sign-status-list --key STATUSKEYFILE --draft DRAFT.json --out LIST.json [--lifetime-seconds N]
      Sign a status-list update with your issuer status key, for example the
      unsigned draft a delegation review gives you when a reviewer revokes a
      delegation. The update is valid from now for the draft's
      lifetime_seconds, or N seconds when a receiver's policy allows less. Submit LIST.json through the console's Withdraw
      authority page or the status-list API; Verify signs nothing for you.

  ratify-keys verify-export --keys KEYS.json --signature SIGNATURE.json --payload FILE
      Check a Verify export (feed batch, report bundle, or review record)
      offline. Save KEYS.json from GET /v1/verify/export-keys, SIGNATURE.json
      from the export's signature, and FILE as the exact exported bytes.
      Exits non-zero unless the signature verifies with a published key that
      was valid when the export was signed.

  ratify-keys verify-feed --keys FEED_KEYS.json --deliveries FILE [--from CHECKPOINT.json] [--batches-only]
      Check evidence feed deliveries offline. Save FEED_KEYS.json from
      GET /v1/verify/feed-keys. FILE holds the received lines
      (webhook NDJSON or exported Splunk HEC events). Exits non-zero unless
      every batch signature verifies, the batches link with no edit,
      reorder, missing batch, or skipped stream position, and every signed
      event arrived as its own event line (--batches-only checks the
      batch records alone, for a store that keeps only them). Prints a
      checkpoint to pass as --from next time. Repair a reported gap from
      GET /v1/orgs/{orgId}/activity?after_seq=N.

Safety checks:
  - generate refuses to overwrite a file, and refuses a folder that other
    users can write to.
  - Key files must be readable only by their owner.
  - prove refuses a challenge that is for a different key, has expired, or
    is not for a key you hold yourself (customer_held).
`

// version is set at release build time with -ldflags "-X main.version=...";
// otherwise toolversion falls back to the module version from go install.
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, time.Now); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "ratify-keys:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, "ratify-keys", toolversion.String(version))
		return nil
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		if len(args) == 0 {
			return errors.New("a command is required: setup, generate, public, prove, delegate, sign-receiver-profile, sign-status-list, verify-export, or verify-feed")
		}
		return flag.ErrHelp
	}
	if args[0] == "delegate" {
		return delegateCommand(args[1:], stderr, now())
	}
	if args[0] == "setup" {
		return setupCommand(args[1:], stderr, now())
	}
	if args[0] == "prove" && slices.ContainsFunc(args[1:], func(a string) bool {
		return a == "--bundle" || a == "-bundle" || strings.HasPrefix(a, "--bundle=") || strings.HasPrefix(a, "-bundle=")
	}) {
		return proveBundleCommand(args[1:], stderr, now())
	}
	if args[0] == "verify-export" {
		return verifyExportCommand(args[1:], stdout, stderr)
	}
	if args[0] == "verify-feed" {
		return verifyFeedCommand(args[1:], stdout, stderr)
	}
	if args[0] == "sign-receiver-profile" {
		return signReceiverProfileCommand(args[1:], stderr, now())
	}
	if args[0] == "sign-status-list" {
		return signStatusListCommand(args[1:], stderr, now())
	}
	fs := flag.NewFlagSet("ratify-keys "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	keyPath := fs.String("key", "", "your private key file")
	outPath := fs.String("out", "", "file to create")
	challengePath := fs.String("challenge", "", "enrollment challenge JSON file")
	role := fs.String("role", "", "the role you expect the challenge to be for")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch args[0] {
	case "generate":
		if *outPath == "" || *keyPath != "" || *challengePath != "" || *role != "" {
			return errors.New("generate takes only --out KEYFILE")
		}
		return generate(*outPath, stdout, stderr)
	case "public":
		if *keyPath == "" || *outPath != "" || *challengePath != "" || *role != "" {
			return errors.New("public takes only --key KEYFILE")
		}
		private, err := loadKey(*keyPath)
		if err != nil {
			return err
		}
		return printPublic(private.Public(), stdout, stderr)
	case "prove":
		if *keyPath == "" || *challengePath == "" || *outPath == "" {
			return errors.New("prove needs --key KEYFILE, --challenge CHALLENGE.json, and --out PROOF.json")
		}
		return prove(*keyPath, *challengePath, *outPath, *role, now(), stderr)
	default:
		return fmt.Errorf("unknown command %q (use generate, public, prove, delegate, sign-status-list, verify-export, or verify-feed)", args[0])
	}
}

func generate(path string, stdout, stderr io.Writer) error {
	// Open the folder once and create the key through that handle, so the
	// folder checked is the folder written to.
	dir := filepath.Dir(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("key folder: %w", err)
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("key folder: %w", err)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("refusing to save a private key in %s: other users can write to that folder", dir)
	}
	public, private, err := ratify.GenerateHybridKeypair()
	if err != nil {
		return err
	}
	ml, err := private.MLDSA65.MarshalBinary()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(keyFile{Ed25519: private.Ed25519, MLDSA65: ml})
	if err != nil {
		return err
	}
	if err := writeNew(root, filepath.Base(path), path, append(encoded, '\n'), 0600); err != nil {
		return err
	}
	return printPublic(public, stdout, stderr)
}

// writeNew creates name in root, refusing to replace anything already there
// (including a symbolic link), and removes it if the write fails.
func writeNew(root *os.Root, name, display string, data []byte, perm os.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("refusing to overwrite %s: it already exists", display)
	}
	if err != nil {
		return fmt.Errorf("could not create %s: %w", display, err)
	}
	if err := f.Chmod(perm); err == nil {
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			return nil
		}
	} else {
		f.Close()
	}
	root.Remove(name)
	return fmt.Errorf("could not write %s", display)
}

// printPublic writes the public key JSON the console's public key field
// accepts to stdout, and the key ID to stderr.
func printPublic(public ratify.HybridPublicKey, stdout, stderr io.Writer) error {
	id, err := setup.V2KeyID(public)
	if err != nil {
		return err
	}
	encoded, err := ratify.CanonicalJSON(public)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", encoded); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Key ID: %s\n", id)
	return err
}

// loadKey reads a private key file that only its owner can read. Parse
// errors are reported without their details so no key bytes reach output.
func loadKey(path string) (ratify.HybridPrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file %s must be a regular file readable only by you (run: chmod 600 %s)", path, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil || len(data) > maxInputBytes {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file %s could not be read", path)
	}
	invalid := fmt.Errorf("key file %s is not a valid ratify-keys private key", path)
	var file keyFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&file) != nil || len(file.Ed25519) != ed25519.PrivateKeySize {
		return ratify.HybridPrivateKey{}, invalid
	}
	edKey := ed25519.PrivateKey(file.Ed25519)
	if !bytes.Equal(ed25519.NewKeyFromSeed(edKey.Seed()), edKey) {
		return ratify.HybridPrivateKey{}, invalid
	}
	ml := new(mldsa65.PrivateKey)
	if ml.UnmarshalBinary(file.MLDSA65) != nil {
		return ratify.HybridPrivateKey{}, invalid
	}
	return ratify.HybridPrivateKey{Ed25519: edKey, MLDSA65: ml}, nil
}

func readChallenge(path string) (challenge, error) {
	f, err := os.Open(path)
	if err != nil {
		return challenge{}, fmt.Errorf("challenge file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil || len(data) > maxInputBytes {
		return challenge{}, fmt.Errorf("challenge file %s could not be read", path)
	}
	var c challenge
	if err := json.Unmarshal(data, &c); err != nil {
		return challenge{}, fmt.Errorf("challenge file %s is not the challenge JSON from the console: %v", path, err)
	}
	if c.ChallengeID == "" || c.Challenge == "" || c.Audience == "" || c.AuthorityID == "" ||
		c.KeyID == "" || c.Role == "" || c.CustodyMode == "" || c.ExpiresAt.IsZero() {
		return challenge{}, fmt.Errorf("challenge file %s is missing fields; save the whole challenge from the console", path)
	}
	return c, nil
}

func prove(keyPath, challengePath, outPath, wantRole string, now time.Time, stderr io.Writer) error {
	private, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	c, err := readChallenge(challengePath)
	if err != nil {
		return err
	}
	proof, err := signChallenge(private, c, wantRole, now)
	if err != nil {
		return err
	}
	keyID := c.KeyID
	// The file holds the exact signed bytes, with no trailing newline:
	// Verify accepts only those bytes.
	root, err := os.OpenRoot(filepath.Dir(outPath))
	if err != nil {
		return fmt.Errorf("proof folder: %w", err)
	}
	defer root.Close()
	if err := writeNew(root, filepath.Base(outPath), outPath, proof, 0644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Wrote %s for key %s, role %s. Upload it before %s.\n",
		outPath, keyID, c.Role, c.ExpiresAt.Local().Format(time.RFC1123))
	return err
}

// signChallenge signs one enrollment challenge after checking it names
// exactly this key, a customer-held custody mode, a known role (and
// wantRole when set), and has not expired, then checks the proof exactly as
// Verify will.
func signChallenge(private ratify.HybridPrivateKey, c challenge, wantRole string, now time.Time) ([]byte, error) {
	keyID, err := setup.V2KeyID(private.Public())
	if err != nil {
		return nil, err
	}
	// The key ID commits to both halves of the public key, so a matching
	// key ID means the challenge names exactly this public key.
	if c.KeyID != keyID {
		return nil, fmt.Errorf("this challenge is for key %s, but your key file holds key %s", c.KeyID, keyID)
	}
	if c.CustodyMode != "customer_held" {
		return nil, fmt.Errorf("this challenge is for custody %q; ratify-keys signs only for keys you hold yourself (customer_held)", c.CustodyMode)
	}
	if !customerRoles[c.Role] {
		return nil, fmt.Errorf("this challenge names an unknown role %q", c.Role)
	}
	if wantRole != "" && c.Role != wantRole {
		return nil, fmt.Errorf("this challenge is for role %q, not %q", c.Role, wantRole)
	}
	issued := now.Unix()
	if c.ExpiresAt.Unix() <= issued {
		return nil, fmt.Errorf("this challenge expired at %s; request a new one", c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	body := setup.V2KeyPossessionProof{Audience: c.Audience, Challenge: c.Challenge, ChallengeID: c.ChallengeID,
		CustodyMode: c.CustodyMode, IssuedAt: issued, ExpiresAt: min(c.ExpiresAt.Unix(), issued+15*60),
		OwnerID: c.AuthorityID, Role: c.Role}
	proof, err := setup.SignV2KeyPossessionProof(body, private)
	if err != nil {
		return nil, fmt.Errorf("this challenge cannot be signed: %v", err)
	}
	// Check the proof exactly as Verify will before writing it.
	expected := setup.V2KeyEnrollmentExpectation{Audience: c.Audience, Challenge: c.Challenge,
		ChallengeID: c.ChallengeID, CustodyMode: c.CustodyMode, OwnerID: c.AuthorityID, Role: c.Role}
	if _, proved, err := setup.VerifyV2KeyPossessionProof(proof, expected, issued); err != nil || proved != c.KeyID {
		return nil, fmt.Errorf("the signed proof did not pass the enrollment check: %v", err)
	}
	return proof, nil
}

const maxExportPayloadBytes = 256 << 20

func verifyExportCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ratify-keys verify-export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	keysPath := fs.String("keys", "", "export key set from GET /v1/verify/export-keys")
	sigPath := fs.String("signature", "", "the export's signature JSON")
	payloadPath := fs.String("payload", "", "the exported bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keysPath == "" || *sigPath == "" || *payloadPath == "" {
		return errors.New("verify-export needs --keys KEYS.json, --signature SIGNATURE.json, and --payload FILE")
	}
	var keys exportsig.KeySet
	if err := readJSONFile(*keysPath, maxInputBytes, &keys); err != nil {
		return err
	}
	var sig exportsig.Signature
	if err := readJSONFile(*sigPath, maxInputBytes, &sig); err != nil {
		return err
	}
	payload, err := readLimitedFile(*payloadPath, maxExportPayloadBytes)
	if err != nil {
		return err
	}
	if err := exportsig.Verify(keys, sig, payload); err != nil {
		return fmt.Errorf("export NOT verified: %w", err)
	}
	fmt.Fprintf(stdout, "verified: %s version %s, signed %s by %s\n",
		sig.ArtifactType, sig.Version, exportsig.FormatTime(sig.SignedAt), sig.KeyID)
	return nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s could not be read: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

func readJSONFile(path string, limit int64, v any) error {
	data, err := readLimitedFile(path, limit)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// statusListDraft is the unsigned status-list change a delegation review
// returns for one issuer.
type statusListDraft struct {
	Version         int                    `json:"version"`
	IssuerID        string                 `json:"issuer_id"`
	Sequence        int64                  `json:"sequence"`
	Revoked         []ratify.RevokedCertV2 `json:"revoked"`
	LifetimeSeconds int64                  `json:"lifetime_seconds"`
}

func signStatusListCommand(args []string, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("ratify-keys sign-status-list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	keyPath := fs.String("key", "", "your issuer status private key file")
	draftPath := fs.String("draft", "", "the unsigned status-list draft")
	outPath := fs.String("out", "", "file to create")
	lifetime := fs.Int64("lifetime-seconds", 0, "override the draft's lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keyPath == "" || *draftPath == "" || *outPath == "" {
		return errors.New("sign-status-list needs --key STATUSKEYFILE, --draft DRAFT.json, and --out LIST.json")
	}
	private, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	var draft statusListDraft
	data, err := readLimitedFile(*draftPath, 8<<20)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&draft); err != nil {
		return fmt.Errorf("%s: %w", *draftPath, err)
	}
	if *lifetime != 0 {
		draft.LifetimeSeconds = *lifetime
	}
	if draft.Version != 2 || draft.IssuerID == "" || draft.Sequence < 1 ||
		draft.LifetimeSeconds < 1 || draft.LifetimeSeconds > ratify.V2MaxStatusLifetimeSeconds {
		return fmt.Errorf("the draft is not a Protocol v2 status-list draft (version 2, issuer_id, sequence, lifetime_seconds 1 to %d)", ratify.V2MaxStatusLifetimeSeconds)
	}
	updated := now.Unix()
	list := &ratify.RevocationListV2{Version: 2, IssuerID: draft.IssuerID, UpdatedAt: updated,
		NextUpdate: updated + draft.LifetimeSeconds, Sequence: draft.Sequence, Revoked: draft.Revoked}
	if list.Revoked == nil {
		list.Revoked = []ratify.RevokedCertV2{}
	}
	// The list is bound to the key in the file; Verify accepts it only if
	// that key is the issuer's configured status key for the epoch.
	signed, err := ratify.SignRevocationListV2(list, draft.IssuerID, private.Public(), private)
	if err != nil {
		return fmt.Errorf("the draft cannot be signed: %v", err)
	}
	wire, err := ratify.EncodeRevocationListV2(signed)
	if err != nil {
		return err
	}
	if err := ratify.VerifyRevocationListV2Signature(signed, draft.IssuerID, private.Public()); err != nil {
		return fmt.Errorf("the signed list did not verify: %v", err)
	}
	keyID, err := setup.V2KeyID(private.Public())
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(*outPath))
	if err != nil {
		return fmt.Errorf("output folder: %w", err)
	}
	defer root.Close()
	if err := writeNew(root, filepath.Base(*outPath), *outPath, wire, 0644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Wrote %s: issuer %s, sequence %d, %d revoked, signed by status key %s, valid until %s.\n",
		*outPath, draft.IssuerID, draft.Sequence, len(list.Revoked), keyID,
		time.Unix(list.NextUpdate, 0).Local().Format(time.RFC1123))
	return err
}
