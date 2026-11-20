package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

const testOrg = "5d0a3a47-1111-4b4f-9a43-8f6b1c8c2d11"

// runSetup creates a setup folder and returns it with the parsed plan.
func runSetup(t *testing.T, extra ...string) (string, setup.V2KeySetupPlan) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	var out, notes bytes.Buffer
	if err := run(append([]string{"setup", "issuer", "--offline", "--org", testOrg, "--out", dir}, extra...), &out, &notes, fixedNow); err != nil {
		t.Fatalf("setup: %v\n%s", err, notes.String())
	}
	request, err := os.ReadFile(filepath.Join(dir, setupRequest))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := setup.ParseV2KeySetupRequest(request, testNow.Unix())
	if err != nil {
		t.Fatalf("Verify must accept the request ratify-keys writes: %v", err)
	}
	// The private keys never appear in anything the tool prints.
	for _, name := range []string{setupRootKey, setupIssuerKey, setupStatusKey} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		var file keyFile
		if err != nil || json.Unmarshal(data, &file) != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains(append(out.Bytes(), notes.Bytes()...), file.Ed25519[:16]) || bytes.Contains(request, file.Ed25519[:16]) {
			t.Fatalf("private key bytes of %s leaked into output or the request", name)
		}
	}
	return dir, plan
}

func setupBundle(plan setup.V2KeySetupPlan, roles ...string) setup.V2KeySetupBundle {
	ids := map[string]string{"organization_root": plan.RootKeyID, "issuer": plan.IssuerKeyID, "issuer_status": plan.StatusKeyID}
	b := setup.V2KeySetupBundle{Version: 1, Kind: setup.V2KeySetupBundleKind, SetupID: "0b7c5f0e-8f3c-4f55-9a43-8f6b1c8c2d11",
		OrganizationID: testOrg, RequestDigest: plan.RequestDigest, Epoch: 1,
		ExpiresAt: testNow.Add(15 * time.Minute).UTC()}
	for i, role := range roles {
		nonce := strings.Repeat(string(rune('a'+i)), 32)
		b.Challenges = append(b.Challenges, setup.V2KeySetupChallenge{Audience: "https://verify.example",
			AuthorityID: strings.Repeat(string(rune('a'+i)), 32),
			Challenge:   setup.V2KeySetupChallengeValue(testOrg, role, ids[role], nonce),
			ChallengeID: strings.Repeat(string(rune('1'+i)), 32), CustodyMode: "customer_held",
			ExpiresAt: b.ExpiresAt, KeyID: ids[role], Nonce: nonce, Role: role})
	}
	return b
}

func proveBundle(t *testing.T, dir string, bundle setup.V2KeySetupBundle, extra ...string) ([]byte, error) {
	t.Helper()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	bundlePath, outPath := filepath.Join(work, "bundle.json"), filepath.Join(work, "proofs.json")
	if err := os.WriteFile(bundlePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, notes bytes.Buffer
	err = run(append([]string{"prove", "--bundle", bundlePath, "--dir", dir, "--out", outPath}, extra...), &out, &notes, fixedNow)
	if err != nil {
		if _, statErr := os.Stat(outPath); statErr == nil {
			t.Fatal("a refused bundle must not leave a proof file")
		}
		return nil, err
	}
	return os.ReadFile(outPath)
}

// The whole customer side of a first setup: one request, one bundle, one
// proof file whose every proof passes Verify's possession check for its
// own challenge and key.
func TestSetupOfflineAndProveBundleRoundTrip(t *testing.T) {
	dir, plan := runSetup(t)
	if !plan.Request.NewRoot || plan.Request.Epoch != 1 {
		t.Fatalf("a first setup enrolls a new root at epoch 1: %+v", plan.Request)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("setup folder must be owner-only: %v %v", info.Mode(), err)
	}
	bundle := setupBundle(plan, "organization_root", "issuer", "issuer_status")
	wire, err := proveBundle(t, dir, bundle)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := setup.ParseV2KeySetupProofs(wire)
	if err != nil {
		t.Fatalf("Verify must accept the proof file ratify-keys writes: %v", err)
	}
	if proofs.SetupID != bundle.SetupID || proofs.RequestDigest != plan.RequestDigest || len(proofs.Proofs) != 3 {
		t.Fatalf("proof file does not answer this bundle: %+v", proofs)
	}
	for i, p := range proofs.Proofs {
		c := bundle.Challenges[i]
		_, proved, err := setup.VerifyV2KeyPossessionProof(p.PossessionProof, setup.V2KeyEnrollmentExpectation{
			Audience: c.Audience, Challenge: c.Challenge, ChallengeID: c.ChallengeID, CustodyMode: c.CustodyMode,
			OwnerID: c.AuthorityID, Role: c.Role}, testNow.Unix())
		if err != nil || proved != c.KeyID || p.KeyID != c.KeyID || p.Role != c.Role {
			t.Fatalf("%s proof does not pass the enrollment check: %v", c.Role, err)
		}
	}
}

// An existing root signs the authorization but is not enrolled again, and
// its key file stays where the owner keeps it.
func TestSetupWithExistingRoot(t *testing.T) {
	rootPath, _, rootID := generateKey(t, t.TempDir(), "root.key")
	dir, plan := runSetup(t, "--root-key", rootPath)
	if plan.Request.NewRoot || plan.RootKeyID != rootID {
		t.Fatalf("setup must use the existing root: %+v", plan.Request)
	}
	if _, err := os.Stat(filepath.Join(dir, setupRootKey)); !os.IsNotExist(err) {
		t.Fatal("setup must not create a new root next to an existing one")
	}
	// A bundle that asks to enroll a root for this setup is refused.
	if _, err := proveBundle(t, dir, setupBundle(plan, "organization_root", "issuer", "issuer_status")); err == nil {
		t.Fatal("a root challenge for a setup with an existing root must be refused")
	}
	if _, err := proveBundle(t, dir, setupBundle(plan, "issuer", "issuer_status")); err != nil {
		t.Fatal(err)
	}
}

// A bundle the folder did not ask for is refused before anything is signed:
// a substituted key, a bundle for another request, an expired challenge,
// a changed epoch, or a role asked twice.
func TestProveBundleRefusesSubstitutedOrForeignBundles(t *testing.T) {
	dir, plan := runSetup(t)
	other, _, otherID := generateKey(t, t.TempDir(), "other.key")
	_ = other
	cases := map[string]func(*setup.V2KeySetupBundle){
		"substituted issuer key": func(b *setup.V2KeySetupBundle) { b.Challenges[1].KeyID = otherID },
		"keys swapped between roles": func(b *setup.V2KeySetupBundle) {
			b.Challenges[1].KeyID, b.Challenges[2].KeyID = b.Challenges[2].KeyID, b.Challenges[1].KeyID
		},
		"another request": func(b *setup.V2KeySetupBundle) { b.RequestDigest = strings.Repeat("0", 64) },
		// Genuine challenges for these same keys, issued in another
		// organization that uploaded a copy of the request.
		"another organization": func(b *setup.V2KeySetupBundle) { b.OrganizationID = "6e1b4b58-2222-4c5f-8b54-9f7c2d9d3e22" },
		// Challenges Verify issued in another organization (for a relabeled
		// copy of the request), presented under this organization's label.
		"challenges from another organization": func(b *setup.V2KeySetupBundle) {
			for i := range b.Challenges {
				c := &b.Challenges[i]
				c.Challenge = setup.V2KeySetupChallengeValue("6e1b4b58-2222-4c5f-8b54-9f7c2d9d3e22", c.Role, c.KeyID, c.Nonce)
			}
		},
		"expired":           func(b *setup.V2KeySetupBundle) { b.Challenges[2].ExpiresAt = testNow.Add(-time.Second) },
		"recomputed epoch":  func(b *setup.V2KeySetupBundle) { b.Epoch = 2 },
		"role twice":        func(b *setup.V2KeySetupBundle) { b.Challenges[2] = b.Challenges[1] },
		"custodial":         func(b *setup.V2KeySetupBundle) { b.Challenges[0].CustodyMode = "ratify_custodial" },
		"unknown role":      func(b *setup.V2KeySetupBundle) { b.Challenges[0].Role = "agent" },
		"no challenges":     func(b *setup.V2KeySetupBundle) { b.Challenges = nil },
		"wrong bundle kind": func(b *setup.V2KeySetupBundle) { b.Kind = setup.V2KeySetupRequestKind },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := setupBundle(plan, "organization_root", "issuer", "issuer_status")
			mutate(&bundle)
			if _, err := proveBundle(t, dir, bundle); err == nil {
				t.Fatal("bundle must be refused")
			}
		})
	}
}

func TestSetupRefusesExistingFolderAndOnlineMode(t *testing.T) {
	dir := t.TempDir()
	var out, notes bytes.Buffer
	if err := run([]string{"setup", "issuer", "--offline", "--org", testOrg, "--out", dir}, &out, &notes, fixedNow); err == nil {
		t.Fatal("setup must refuse an existing folder")
	}
	if err := run([]string{"setup", "issuer", "--offline", "--out", filepath.Join(dir, "no-org")}, &out, &notes, fixedNow); err == nil {
		t.Fatal("setup must name the organization the request is for")
	}
	if err := run([]string{"setup", "issuer", "--org", testOrg, "--out", filepath.Join(dir, "new")}, &out, &notes, fixedNow); err == nil {
		t.Fatal("setup without --offline must be refused until console pairing exists")
	}
	if err := run([]string{"setup", "issuer", "--offline", "--org", testOrg, "--valid-for", "2161h", "--out", filepath.Join(dir, "x")}, &out, &notes, fixedNow); err == nil {
		t.Fatal("an authorization longer than 90 days must be refused")
	}
}

// Verify's request check refuses what a tampered request file would carry.
func TestParseSetupRequestRefusesTampering(t *testing.T) {
	dir, plan := runSetup(t)
	request, err := os.ReadFile(filepath.Join(dir, setupRequest))
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPriv
	cases := map[string]func(*setup.V2KeySetupRequest){
		"issuer key swapped": func(r *setup.V2KeySetupRequest) { r.IssuerPublicKey = otherPub },
		"root key swapped":   func(r *setup.V2KeySetupRequest) { r.RootPublicKey = otherPub },
		"status equals issuer": func(r *setup.V2KeySetupRequest) {
			r.StatusPublicKey = r.IssuerPublicKey
		},
		"epoch 2":           func(r *setup.V2KeySetupRequest) { r.Epoch = 2 },
		"no authorization":  func(r *setup.V2KeySetupRequest) { r.IssuerAuthorization = nil },
		"version 2 request": func(r *setup.V2KeySetupRequest) { r.Version = 2 },
		"no organization":   func(r *setup.V2KeySetupRequest) { r.OrganizationID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := plan.Request
			mutate(&r)
			wire, err := ratify.CanonicalJSON(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := setup.ParseV2KeySetupRequest(wire, testNow.Unix()); err == nil {
				t.Fatal("tampered request must be refused")
			}
		})
	}
	if _, err := setup.ParseV2KeySetupRequest(append(request, '\n'), testNow.Unix()); err == nil {
		t.Fatal("a non-canonical request must be refused")
	}
	if _, err := setup.ParseV2KeySetupRequest(request, testNow.Add(91*24*time.Hour).Unix()); err == nil {
		t.Fatal("an expired authorization must be refused")
	}
}
