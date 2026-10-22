"""Ratify Protocol v2 external signer: a signing provider holds the private
key; the SDK prepares each typed statement and verifies every returned
signature before using it.

The provider here is an in-process stand-in for a remote signing service.
The interface makes no claim about any particular KMS or HSM.

The stand-in needs an Ed25519 and ML-DSA-65 (FIPS 204, with a context string)
signing primitive. The SDK's runtime dependencies expose none publicly, so
this example borrows the key type of the ratify-protocol-native-v2
extension. A real provider uses its own signing service instead.

Run: python examples/v2/python/external_signer.py
"""
import os

import ratify_protocol_native_v2 as native

from ratify_protocol_v2 import HybridPublicKey, HybridSignature, SignerModeV2, background, error_class_of, key_id_v2
from ratify_protocol_v2.protocol_v2 import (
    DelegationCertV2,
    ProofBundleV2,
    sign_delegation_cert_v2_with_signer,
    sign_proof_bundle_v2_with_signer,
    verify_delegation_cert_v2_signature,
    verify_proof_bundle_v2_signatures,
)
from ratify_protocol_v2.signing_v2 import generate_keypair_v2

START = 1800000000


def new_key():
    return native.HybridSigningKey.from_seeds(os.urandom(32), os.urandom(32))


class Provider:
    """A signing service. Its private key never leaves it. It signs in direct
    mode: Ed25519 over the 77-byte message M and ML-DSA-65 over M with the
    SDK-chosen context string. Implements the SignerV2 protocol."""

    def __init__(self, name: str):
        self.name = name
        self.key = new_key()
        self.ml_key = self.key  # the key used for ML-DSA-65; differs only for a faulty provider
        ed, ml = self.key.public_key()
        self.pub = HybridPublicKey(ed25519=bytes(ed), ml_dsa_65=bytes(ml))
        self.log = []

    def public_key_v2(self) -> HybridPublicKey:
        return self.pub

    def mode_v2(self) -> SignerModeV2:
        return SignerModeV2.DIRECT

    def sign_v2(self, ctx, req) -> HybridSignature:
        # A provider refuses any request for a key it does not hold.
        if bytes(req.public_key.ed25519) != self.pub.ed25519 or bytes(req.public_key.ml_dsa_65) != self.pub.ml_dsa_65:
            raise ValueError(f"{self.name}: request names a key this provider does not hold")
        self.log.append(f"{self.name} signed: mode=direct message={len(req.message)} bytes "
                        f"context={req.mldsa_context.decode('ascii')}")
        ed_sig, _ = self.key._sign(req.message, req.mldsa_context)
        _, ml_sig = self.ml_key._sign(req.message, req.mldsa_context)
        return HybridSignature(ed25519=bytes(ed_sig), ml_dsa_65=bytes(ml_sig))


def verified(check, obj) -> str:
    try:
        check(obj)
        return "true"
    except Exception:  # noqa: BLE001
        return "false"


def main() -> None:
    ctx = background()
    print("Ratify Protocol v2 external signer")

    issuer = Provider("issuer provider")
    agent = Provider("agent provider")
    verifier_pub, _ = generate_keypair_v2()
    issuer_id, agent_id, verifier_id = key_id_v2(issuer.pub), key_id_v2(agent.pub), key_id_v2(verifier_pub)

    cert = sign_delegation_cert_v2_with_signer(ctx, DelegationCertV2(
        version=2, cert_id="external-signer-cert-1",
        issuer_id=issuer_id, issuer_pub_key=issuer.pub, subject_id=agent_id, subject_pub_key=agent.pub,
        scope=["files:read"], constraints=[], issued_at=START, expires_at=START + 86400,
    ), issuer)
    print(issuer.log[0])
    print(f"delegation: signature verified by the SDK ({verified(verify_delegation_cert_v2_signature, cert)})")

    unsigned = ProofBundleV2(
        version=2, verifier_id=verifier_id, agent_id=agent_id, agent_pub_key=agent.pub,
        delegations=[cert], challenge=bytes([0x42]) * 32, challenge_at=START,
        delegation_digest=b"", challenge_sig=None,  # computed by the signing function
    )
    bundle = sign_proof_bundle_v2_with_signer(ctx, unsigned, agent)
    print(agent.log[0])
    print(f"proof bundle: signatures verified by the SDK ({verified(verify_proof_bundle_v2_signatures, bundle)})")

    # A faulty provider returns an ML-DSA-65 signature from a different key.
    # The SDK verifies before use, so nothing is signed.
    agent.ml_key = new_key()
    try:
        sign_proof_bundle_v2_with_signer(ctx, unsigned, agent)
        refused = ""
    except Exception as exc:  # noqa: BLE001 - the example prints the error class
        refused = error_class_of(exc)
    print(f"faulty provider: refused ({refused})")


if __name__ == "__main__":
    main()
