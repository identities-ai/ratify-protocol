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
	"strings"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

// maxDelegationValidity matches Verify's limit for a root-signed issuer
// authorization; agent certificates are usually much shorter.
const maxDelegationValidity = 90 * 24 * time.Hour

// delegateCommand signs a Protocol v2 delegation certificate with the
// holder's key: a root's issuer authorization (scope identity:delegate) or
// an issuer's agent certificate with an exact cert_id.
func delegateCommand(args []string, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("ratify-keys delegate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	keyPath := fs.String("key", "", "the signing (issuer) private key file")
	subjectPath := fs.String("subject", "", "the subject's public key JSON")
	certID := fs.String("cert-id", "", "the exact certificate ID")
	scopes := fs.String("scope", "", "comma-separated scopes")
	validFor := fs.Duration("valid-for", 0, "how long the certificate is valid")
	outPath := fs.String("out", "", "file to create")
	receiverID := fs.String("receiver-id", "", "limit the certificate to exactly this receiver (a receiver audience constraint)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *keyPath == "" || *subjectPath == "" || *certID == "" || *scopes == "" || *outPath == "" {
		return errors.New("delegate needs --key, --subject, --cert-id, --scope, --valid-for, and --out (and optionally --receiver-id)")
	}
	if *validFor <= 0 || *validFor > maxDelegationValidity {
		return fmt.Errorf("--valid-for must be more than 0 and at most %s", maxDelegationValidity)
	}
	scope := strings.Split(*scopes, ",")
	if err := ratify.ValidateScopesV2(scope); err != nil {
		return fmt.Errorf("--scope: %v", err)
	}
	private, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	subjectData, err := readLimitedFile(*subjectPath, maxInputBytes)
	if err != nil {
		return err
	}
	subject, err := readPublic(subjectData)
	if err != nil {
		return fmt.Errorf("--subject %s: %v", *subjectPath, err)
	}
	issuerID, err := setup.V2KeyID(private.Public())
	if err != nil {
		return err
	}
	subjectID, err := setup.V2KeyID(subject)
	if err != nil {
		return err
	}
	constraints := []ratify.ConstraintV2{}
	if *receiverID != "" {
		// Usable only at this receiver: every other receiver rejects it
		// before a claim (SPEC-v2 5.2).
		constraints = append(constraints, ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience,
			Params: map[string]any{"exact_receiver_ids": []string{*receiverID}, "trust_domain_ids": []string{}}})
	}
	// Backdate a minute so ordinary clock drift cannot make it future-dated;
	// the validity period counts from that time, so it never exceeds --valid-for.
	issued := now.Unix() - 60
	signed, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{Version: 2, CertID: *certID,
		IssuerID: issuerID, IssuerPubKey: private.Public(), SubjectID: subjectID, SubjectPubKey: subject,
		Scope: scope, Constraints: constraints, IssuedAt: issued,
		ExpiresAt: issued + int64(validFor.Seconds())}, private)
	if err != nil {
		return fmt.Errorf("the certificate cannot be signed: %v", err)
	}
	wire, err := ratify.EncodeDelegationCertV2(signed)
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
	_, err = fmt.Fprintf(stderr, "Wrote certificate %s: issuer %s -> subject %s, scope %s, expires %s.\n",
		*certID, issuerID, subjectID, *scopes, time.Unix(signed.ExpiresAt, 0).UTC().Format(time.RFC3339))
	return err
}

// readPublic decodes the public key JSON that generate and public print.
func readPublic(data []byte) (ratify.HybridPublicKey, error) {
	var public ratify.HybridPublicKey
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&public); err != nil {
		return ratify.HybridPublicKey{}, errors.New("not a public key printed by ratify-keys")
	}
	if _, err := setup.V2KeyID(public); err != nil {
		return ratify.HybridPublicKey{}, errors.New("not a valid hybrid public key")
	}
	return public, nil
}
