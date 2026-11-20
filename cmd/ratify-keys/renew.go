package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

// renewIssuerCommand runs `ratify-keys setup renew-issuer`: the root signs a
// new identity:delegate authorization for the same issuer key on this
// machine, and one request file is written to upload from the console's
// setup health page. The issuer key never changes; that would be a rotation.
func renewIssuerCommand(args []string, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("ratify-keys setup renew-issuer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	dirPath := fs.String("dir", "", "the folder `ratify-keys setup issuer` created")
	orgID := fs.String("org", "", "the organization ID the console shows in this command")
	outPath := fs.String("out", "", "file to create")
	rootKeyPath := fs.String("root-key", "", "the root key file, if it is not in --dir")
	validFor := fs.Duration("valid-for", maxDelegationValidity, "how long the renewed authorization is valid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *dirPath == "" || *outPath == "" {
		return errors.New("setup renew-issuer needs --dir FOLDER, --org ORGANIZATION_ID, and --out RENEWAL.json")
	}
	if !orgIDPattern.MatchString(*orgID) {
		return errors.New("setup renew-issuer needs --org ORGANIZATION_ID: copy the command from the console's setup page")
	}
	if *validFor <= 0 || *validFor > maxDelegationValidity {
		return fmt.Errorf("--valid-for must be more than 0 and at most %s", maxDelegationValidity)
	}
	if *rootKeyPath == "" {
		*rootKeyPath = filepath.Join(*dirPath, setupRootKey)
	}
	root, err := loadKey(*rootKeyPath)
	if err != nil {
		return err
	}
	issuer, err := loadKey(filepath.Join(*dirPath, setupIssuerKey))
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
	// Backdated a minute against clock drift; the validity counts from then.
	issued := now.Unix() - 60
	cert, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{Version: 2,
		CertID:   "issuer-authorization-" + issuerID[:16] + "-" + strconv.FormatInt(issued, 10),
		IssuerID: rootID, IssuerPubKey: root.Public(), SubjectID: issuerID, SubjectPubKey: issuer.Public(),
		Scope: []string{"identity:delegate"}, Constraints: []ratify.ConstraintV2{},
		IssuedAt: issued, ExpiresAt: issued + int64(validFor.Seconds())}, root)
	if err != nil {
		return fmt.Errorf("the renewed authorization cannot be signed: %v", err)
	}
	authorization, err := ratify.EncodeDelegationCertV2(cert)
	if err != nil {
		return err
	}
	request, err := ratify.CanonicalJSON(setup.V2IssuerRenewalRequest{IssuerAuthorization: authorization,
		IssuerKeyID: issuerID, Kind: setup.V2IssuerRenewalRequestKind, OrganizationID: *orgID, Version: 1})
	if err != nil {
		return err
	}
	// Check the request exactly as Verify will before writing it.
	if _, _, err := setup.ParseV2IssuerRenewalRequest(request, now.Unix()); err != nil {
		return fmt.Errorf("the renewal request did not pass Verify's check: %v", err)
	}
	out, err := os.OpenRoot(filepath.Dir(*outPath))
	if err != nil {
		return fmt.Errorf("output folder: %w", err)
	}
	defer out.Close()
	if err := writeNew(out, filepath.Base(*outPath), *outPath, request, 0644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, `Signed a renewed authorization for issuer %s with root %s,
valid until %s. Upload %s with Renew on the console's setup page.
The issuer keeps working with its current authorization until Verify confirms the renewal.
`, issuerID, rootID, time.Unix(cert.ExpiresAt, 0).UTC().Format(time.RFC3339), *outPath)
	return err
}
