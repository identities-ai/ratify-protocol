// Ratify Protocol v2 external signer: a signing provider holds the private
// key; the SDK prepares each typed statement and verifies every returned
// signature before using it.
//
// The provider here is an in-process stand-in for a remote signing service.
// The interface makes no claim about any particular KMS or HSM.
//
// Run from the repository root: go run ./examples/v2/go/external_signer
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	ratify "github.com/identities-ai/ratify-protocol/v2"
)

const start = int64(1800000000)

// provider is a signing service. Its private key never leaves it. It signs
// in direct mode: Ed25519 over the 77-byte message M and ML-DSA-65 over M
// with the SDK-chosen context string.
type provider struct {
	name string
	pub  ratify.HybridPublicKey
	ed   ed25519.PrivateKey
	ml   *mldsa65.PrivateKey
	log  []string
}

func newProvider(name string) (*provider, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mlPub, mlPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mlBytes, err := mlPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &provider{name: name, pub: ratify.HybridPublicKey{Ed25519: edPub, MLDSA65: mlBytes}, ed: edPriv, ml: mlPriv}, nil
}

func (p *provider) PublicKeyV2() ratify.HybridPublicKey { return p.pub }

func (p *provider) ModeV2() ratify.SignerModeV2 { return ratify.SignerModeDirectV2 }

func (p *provider) SignV2(ctx context.Context, req ratify.SignRequestV2) (ratify.HybridSignature, error) {
	// A provider refuses any request for a key it does not hold.
	if !bytes.Equal(req.PublicKey.Ed25519, p.pub.Ed25519) || !bytes.Equal(req.PublicKey.MLDSA65, p.pub.MLDSA65) {
		return ratify.HybridSignature{}, fmt.Errorf("%s: request names a key this provider does not hold", p.name)
	}
	p.log = append(p.log, fmt.Sprintf("%s signed: mode=direct message=%d bytes context=%s", p.name, len(req.Message), req.MLDSAContext))
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(p.ml, req.Message, req.MLDSAContext, true, ml); err != nil {
		return ratify.HybridSignature{}, err
	}
	return ratify.HybridSignature{Ed25519: ed25519.Sign(p.ed, req.Message), MLDSA65: ml}, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	fmt.Println("Ratify Protocol v2 external signer")

	issuer, err := newProvider("issuer provider")
	if err != nil {
		return err
	}
	agent, err := newProvider("agent provider")
	if err != nil {
		return err
	}
	verifierPub, _, err := ratify.GenerateHybridKeypair()
	if err != nil {
		return err
	}
	issuerID, _ := ratify.KeyIDV2(issuer.pub)
	agentID, _ := ratify.KeyIDV2(agent.pub)
	verifierID, _ := ratify.KeyIDV2(verifierPub)

	cert, err := ratify.SignDelegationCertV2WithSigner(ctx, &ratify.DelegationCertV2{
		Version: 2, CertID: "external-signer-cert-1",
		IssuerID: issuerID, IssuerPubKey: issuer.pub, SubjectID: agentID, SubjectPubKey: agent.pub,
		Scope: []string{"files:read"}, Constraints: []ratify.ConstraintV2{},
		IssuedAt: start, ExpiresAt: start + 86400,
	}, issuer)
	if err != nil {
		return err
	}
	fmt.Println(issuer.log[0])
	fmt.Printf("delegation: signature verified by the SDK (%v)\n", ratify.VerifyDelegationCertV2Signature(cert) == nil)

	challenge := bytes.Repeat([]byte{0x42}, 32)
	unsigned := ratify.ProofBundleV2{
		Version: 2, VerifierID: verifierID, AgentID: agentID, AgentPubKey: agent.pub,
		Delegations: []ratify.DelegationCertV2{*cert}, Challenge: challenge, ChallengeAt: start,
	}
	bundle, err := ratify.SignProofBundleV2WithSigner(ctx, &unsigned, agent)
	if err != nil {
		return err
	}
	fmt.Println(agent.log[0])
	fmt.Printf("proof bundle: signatures verified by the SDK (%v)\n", ratify.VerifyProofBundleV2Signatures(bundle) == nil)

	// A faulty provider returns an ML-DSA-65 signature from a different key.
	// The SDK verifies before use, so nothing is signed.
	_, wrong, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	agent.ml = wrong
	_, err = ratify.SignProofBundleV2WithSigner(ctx, &unsigned, agent)
	fmt.Printf("faulty provider: refused (%s)\n", ratify.V2ErrorClassOf(err))
	return nil
}
