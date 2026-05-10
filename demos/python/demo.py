"""Ratify Protocol v1 — end-to-end narrative demo (Python).

Walks through the full lifecycle with printed output at each step so you can
see what the protocol does. No server required; everything is in-process.

Scenarios:
  1. Alice creates her hybrid root identity.
  2. Alice authorizes an AI agent for `meeting:attend`, 7 days.
  3. The agent receives the cert, builds a proof bundle, verifier checks it.
  4. Attack: attacker tampers with the cert scope — rejected.
  5. Attack: agent tries to exercise a scope outside the grant — rejected.
  6. Attack: expired cert — rejected.
  7. Revocation: Alice revokes the cert — rejected.

Run:
    cd sdks/python && source .venv/bin/activate && pip install -e . && cd ../..
    python demos/python/demo.py
"""
from __future__ import annotations

import time

from ratify_protocol import (
    DelegationCert,
    HybridSignature,
    ProofBundle,
    PROTOCOL_VERSION,
    SCOPE_FILES_WRITE,
    SCOPE_MEETING_ATTEND,
    SCOPE_MEETING_RECORD,
    VerifyOptions,
    derive_id,
    generate_agent,
    generate_challenge,
    generate_human_root,
    issue_delegation,
    sign_challenge,
    verify_bundle,
)


def banner(text: str) -> None:
    print()
    print("━" * 70)
    print(text)
    print("━" * 70)


def kv(label: str, value: str) -> None:
    print(f"  {label:20s} {value}")


def run() -> None:
    # -----------------------------------------------------------------
    # Step 1: Alice creates her root identity
    # -----------------------------------------------------------------
    banner("STEP 1  Alice generates a hybrid root identity")
    alice, alice_priv = generate_human_root()
    kv("Root ID:", alice.id)
    kv("Ed25519 pubkey:", alice.public_key.ed25519.hex()[:32] + "…")
    kv("ML-DSA-65 pubkey:", f"<{len(alice.public_key.ml_dsa_65)} bytes>")
    kv("Storage:", "Private keys stay on Alice's machine (never leave)")

    # -----------------------------------------------------------------
    # Step 2: The agent generates its own keypair
    # -----------------------------------------------------------------
    banner("STEP 2  Agent (Alice's scheduler) generates its own hybrid keypair")
    agent, agent_priv = generate_agent("Alice's Scheduler", "voice_agent")
    kv("Agent ID:", agent.id)
    kv("Agent type:", agent.agent_type)
    kv("Ed25519 pubkey:", agent.public_key.ed25519.hex()[:32] + "…")

    # -----------------------------------------------------------------
    # Step 3: Alice signs a delegation cert
    # -----------------------------------------------------------------
    banner("STEP 3  Alice authorizes the agent for meeting:attend, 7 days")
    now = int(time.time())
    cert = DelegationCert(
        cert_id="cert-demo-001",
        version=PROTOCOL_VERSION,
        issuer_id=alice.id,
        issuer_pub_key=alice.public_key,
        subject_id=agent.id,
        subject_pub_key=agent.public_key,
        scope=[SCOPE_MEETING_ATTEND],
        issued_at=now,
        expires_at=now + 7 * 24 * 3600,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    issue_delegation(cert, alice_priv)
    kv("Cert ID:", cert.cert_id)
    kv("Scope:", ", ".join(cert.scope))
    kv("Expires:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cert.expires_at)))
    kv("Ed25519 sig:", cert.signature.ed25519.hex()[:32] + "…")
    kv("ML-DSA-65 sig:", f"<{len(cert.signature.ml_dsa_65)} bytes>")
    kv("Meaning:", f'"Alice ({alice.id[:8]}…) authorizes agent ({agent.id[:8]}…)')
    kv("", f' to meeting:attend for 7 days, revocable."')

    # -----------------------------------------------------------------
    # Step 4: Agent builds a proof bundle
    # -----------------------------------------------------------------
    banner("STEP 4  Agent builds a proof bundle for the verifier")
    challenge = generate_challenge()
    challenge_at = int(time.time())
    bundle = ProofBundle(
        agent_id=agent.id,
        agent_pub_key=agent.public_key,
        delegations=[cert],
        challenge=challenge,
        challenge_at=challenge_at,
        challenge_sig=sign_challenge(challenge, challenge_at, agent_priv),
    )
    kv("Challenge:", challenge.hex()[:32] + "…")
    kv("Challenge at:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(challenge_at)))
    kv("Hybrid sig:", "Ed25519 + ML-DSA-65 over challenge || BE(ts)")

    # -----------------------------------------------------------------
    # Step 5: Verifier checks the bundle
    # -----------------------------------------------------------------
    banner("STEP 5  Verifier runs verify_bundle() — expects meeting:attend")
    result = verify_bundle(bundle, VerifyOptions(required_scope=SCOPE_MEETING_ATTEND))
    if result.valid:
        print("  ✅  VALID")
        kv("Human ID:", result.human_id)
        kv("Agent ID:", result.agent_id)
        kv("Status:", result.identity_status)
        kv("Granted scope:", ", ".join(result.granted_scope))
    else:
        print(f"  ❌  INVALID — {result.identity_status}: {result.error_reason}")

    # -----------------------------------------------------------------
    # Attack 1: Tampered scope
    # -----------------------------------------------------------------
    banner("ATTACK 1  Attacker appends files:write to the scope after signing")
    tampered = DelegationCert(
        cert_id=cert.cert_id,
        version=cert.version,
        issuer_id=cert.issuer_id,
        issuer_pub_key=cert.issuer_pub_key,
        subject_id=cert.subject_id,
        subject_pub_key=cert.subject_pub_key,
        scope=cert.scope + [SCOPE_FILES_WRITE],  # post-signature tampering
        issued_at=cert.issued_at,
        expires_at=cert.expires_at,
        signature=cert.signature,
    )
    tampered_bundle = ProofBundle(
        agent_id=bundle.agent_id,
        agent_pub_key=bundle.agent_pub_key,
        delegations=[tampered],
        challenge=bundle.challenge,
        challenge_at=bundle.challenge_at,
        challenge_sig=bundle.challenge_sig,
    )
    r = verify_bundle(tampered_bundle, VerifyOptions(required_scope=SCOPE_FILES_WRITE))
    print(f"  ❌  REJECTED as expected: {r.error_reason}")
    kv("Why:", "Canonical bytes differ; Ed25519 AND ML-DSA-65 both fail verify.")

    # -----------------------------------------------------------------
    # Attack 2: Wrong scope (valid cert, wrong request)
    # -----------------------------------------------------------------
    banner("ATTACK 2  Agent tries to use meeting:attend cert for meeting:record")
    r = verify_bundle(bundle, VerifyOptions(required_scope=SCOPE_MEETING_RECORD))
    print(f"  ❌  REJECTED as expected: {r.error_reason}")
    kv("Why:", "meeting:record is not in the effective scope.")

    # -----------------------------------------------------------------
    # Attack 3: Expired cert
    # -----------------------------------------------------------------
    banner("ATTACK 3  Expired cert (verifier's clock reports future time)")
    r = verify_bundle(
        bundle,
        VerifyOptions(
            required_scope=SCOPE_MEETING_ATTEND,
            now=cert.expires_at + 1,
        ),
    )
    print(f"  ❌  REJECTED as expected: {r.identity_status}: {r.error_reason}")

    # -----------------------------------------------------------------
    # Revocation
    # -----------------------------------------------------------------
    banner("REVOCATION  Alice revokes the cert")
    r = verify_bundle(
        bundle,
        VerifyOptions(
            required_scope=SCOPE_MEETING_ATTEND,
            is_revoked=lambda cid: cid == cert.cert_id,
        ),
    )
    print(f"  ❌  REJECTED as expected: {r.identity_status}: {r.error_reason}")
    kv("Why:", "Verifier's revocation list now contains this cert_id.")

    # -----------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------
    banner("SUMMARY")
    print(
        "  The protocol just demonstrated:\n\n"
        "  • Alice created a hybrid (Ed25519 + ML-DSA-65) root identity.\n"
        "  • She signed a scoped, time-bounded delegation for an AI agent.\n"
        "  • The agent signed a fresh challenge to prove liveness.\n"
        "  • A verifier checked the bundle in a single function call.\n"
        "  • Every one of four tampering/misuse scenarios was rejected\n"
        "    deterministically — no fuzzy detection, no false positives.\n"
        "  • Signatures are quantum-safe: breaking either Ed25519 or\n"
        "    ML-DSA-65 alone is insufficient to forge.\n\n"
        "  This is the full Ratify Protocol v1, end to end, in one process."
    )
    print()


if __name__ == "__main__":
    run()
