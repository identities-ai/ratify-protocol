package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

// receiverSpec is the unsigned receiver configuration the console provides
// (for example the Verify MCP receiver's spec); the signer key and schema
// fields are filled in when it is signed.
type receiverSpec struct {
	Anchors          []setup.V2TrustAnchor       `json:"anchors"`
	IssuerStatusKeys []setup.V2IssuerStatusKey   `json:"issuer_status_keys"`
	Operations       []setup.V2ReceiverOperation `json:"operations"`
	ReceiverID       string                      `json:"receiver_id"`
	StatusPolicy     setup.V2StatusPolicy        `json:"status_policy"`
	WorkspaceID      string                      `json:"workspace_id"`
}

const maxReceiverProfileValidity = 30 * 24 * time.Hour

// signReceiverProfileCommand signs a receiver profile from a spec with the
// holder's key as the configuration signer. A successor names the installed
// profile with --previous and must be signed by the same key.
func signReceiverProfileCommand(args []string, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("ratify-keys sign-receiver-profile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	keyPath := fs.String("key", "", "the configuration signer's private key file")
	specPath := fs.String("spec", "", "the receiver spec JSON")
	previousPath := fs.String("previous", "", "the installed profile, for a successor")
	outPath := fs.String("out", "", "file to create")
	validFor := fs.Duration("valid-for", maxReceiverProfileValidity, "how long the profile head is valid (at most 720h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keyPath == "" || *specPath == "" || *outPath == "" {
		return errors.New("sign-receiver-profile needs --key, --spec, and --out")
	}
	if *validFor <= 0 || *validFor > maxReceiverProfileValidity {
		return errors.New("--valid-for must be more than 0 and at most 720h")
	}
	signer, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	data, err := readLimitedFile(*specPath, 1<<20)
	if err != nil {
		return err
	}
	var spec receiverSpec
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return fmt.Errorf("%s: %w", *specPath, err)
	}
	content := setup.V2ReceiverConfigContent{Anchors: spec.Anchors, ConfigSignerKey: signer.Public(),
		IssuerStatusKeys: spec.IssuerStatusKeys, Operations: spec.Operations, ReceiverID: spec.ReceiverID,
		StatusPolicy: spec.StatusPolicy, WorkspaceID: spec.WorkspaceID}
	if content.Anchors == nil {
		content.Anchors = []setup.V2TrustAnchor{}
	}
	if content.IssuerStatusKeys == nil {
		content.IssuerStatusKeys = []setup.V2IssuerStatusKey{}
	}
	head := setup.V2ReceiverConfigHead{IssuedAt: now.Unix() - 30, NotAfter: now.Add(*validFor).Unix() - 30,
		ReceiverID: spec.ReceiverID, Sequence: 1}
	var previous *setup.V2ReceiverConfig
	if *previousPath != "" {
		prior, err := readLimitedFile(*previousPath, 1<<20)
		if err != nil {
			return err
		}
		var doc struct {
			Head struct {
				Body json.RawMessage `json:"body"`
			} `json:"head"`
		}
		var priorHead setup.V2ReceiverConfigHead
		if err := json.Unmarshal(prior, &doc); err != nil || json.Unmarshal(doc.Head.Body, &priorHead) != nil {
			return errors.New("--previous is not a receiver profile")
		}
		previous = &setup.V2ReceiverConfig{Bytes: prior}
		if err := json.Unmarshal(doc.Head.Body, &previous.Head); err != nil {
			return errors.New("--previous is not a receiver profile")
		}
		sum := sha512.Sum384(doc.Head.Body)
		head.Sequence, head.PriorHeadDigest = priorHead.Sequence+1, "sha384:"+hex.EncodeToString(sum[:])
	}
	profile, err := setup.SignV2ReceiverConfig(content, head, signer)
	if err != nil {
		return fmt.Errorf("the profile cannot be signed: %v", err)
	}
	if previous == nil {
		// Check it exactly as Verify will before writing it.
		if _, err := setup.ParseV2ReceiverConfig(profile, nil, now.Unix()); err != nil {
			return fmt.Errorf("the signed profile does not pass Verify's check: %v", err)
		}
	}
	root, err := os.OpenRoot(filepath.Dir(*outPath))
	if err != nil {
		return fmt.Errorf("output folder: %w", err)
	}
	defer root.Close()
	if err := writeNew(root, filepath.Base(*outPath), *outPath, profile, 0644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Wrote receiver profile %s, sequence %d, for receiver %s, valid until %s.\n",
		*outPath, head.Sequence, spec.ReceiverID, time.Unix(head.NotAfter, 0).UTC().Format(time.RFC3339))
	return err
}
