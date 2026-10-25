"""Ratify Protocol v2 quickstart: delegate, present, verify, publish, release.

DEVELOPMENT ONLY. This program uses the in-memory reference stores from
ratify_protocol_v2.v2reference (claim store, receipt log, checkpoint, journal
and challenge issuance store). They exist for tests and examples. A
production verifier supplies durable Part B stores and an independent
checkpoint (SPEC-v2 §7).

Run: python examples/v2/python/quickstart.py
"""
from ratify_protocol_v2 import background, key_id_v2
from ratify_protocol_v2.challenge_issuance_v2 import V2ChallengeIssuer, V2ChallengeIssueRequest, load_expected_challenge_v2
from ratify_protocol_v2.constraints_v2 import CONSTRAINT_MAX_AMOUNT, TZDB_VERSION_V2, ConstraintContextV2, ConstraintV2
from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol_v2.protocol_v2 import (
    DelegationCertV2,
    ProofBundleV2,
    encode_proof_bundle_v2,
    encode_revocation_list_v2,
    sign_delegation_cert_v2,
    sign_proof_bundle_v2,
)
from ratify_protocol_v2.release_v2 import V2_RELEASE_RELEASED, V2ReleaseConfig, release_v2_decision
from ratify_protocol_v2.security_journal_v2 import configure_status_key_epoch_v2, record_security_key_role_v2
from ratify_protocol_v2.signing_v2 import generate_keypair_v2
from ratify_protocol_v2.status_batch_v2 import V2StatusEvidenceBatch, V2StatusEvidenceObject
from ratify_protocol_v2.status_provenance_v2 import V2StatusKeyConfig
from ratify_protocol_v2.status_publisher_v2 import new_v2_status_publisher_with_key
from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol_v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol_v2.v2reference.journal import new_journal_store
from ratify_protocol_v2.v2reference.store import Store
from ratify_protocol_v2.verification_receipt_v2 import decode_verification_receipt_v2
from ratify_protocol_v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)

START = 1800000000  # fixed clock so the output is reproducible
NAMESPACE = "quickstart"
EPOCH = 1
LOG_ID = "00000000000000000000000000000001"


def b(value: bool) -> str:
    return "true" if value else "false"


def main() -> None:
    ctx = background()
    print("Ratify Protocol v2 quickstart")
    print("development only: in-memory reference stores")

    # 1. Keys. Every party holds a hybrid Ed25519 + ML-DSA-65 key. The status
    # key is separate from the root key that issues delegations.
    root_pub, root_priv = generate_keypair_v2()
    agent_pub, agent_priv = generate_keypair_v2()
    status_pub, status_priv = generate_keypair_v2()
    verifier_pub, verifier_priv = generate_keypair_v2()
    root_id, agent_id, verifier_id = key_id_v2(root_pub), key_id_v2(agent_pub), key_id_v2(verifier_pub)
    print(f"keys: root, agent, status and verifier generated (key IDs are {len(root_id)} hex characters)")

    # 2. The root delegates payments:send to the agent, capped at 50.00 USD
    # per action (amounts are integer micro-units in v2).
    cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2, cert_id="quickstart-cert-1",
        issuer_id=root_id, issuer_pub_key=root_pub, subject_id=agent_id, subject_pub_key=agent_pub,
        scope=["payments:send"],
        constraints=[ConstraintV2(type=CONSTRAINT_MAX_AMOUNT, currency="USD", max_amount_micros=50_000_000)],
        issued_at=START, expires_at=START + 86400,
    ), root_priv)
    print("delegation: scope=payments:send max_amount=50000000 USD micros lifetime=86400s")

    # 3. Verifier state: the reference store is the claim store, receipt log,
    # checkpoint and authoritative clock. The journal records key roles and
    # the root's status key.
    store = Store(START, 30, LOG_ID, verifier_priv)
    journal = new_journal_store()
    for role, pub in (("issuer", root_pub), ("delegation", agent_pub), ("verifier", verifier_pub)):
        record_security_key_role_v2(ctx, journal, role, pub)
    configure_status_key_epoch_v2(ctx, journal, root_id, 1, status_pub)

    # 4. The root's status publisher signs a genesis revocation list (no
    # revocations) under the separate status key.
    publisher = new_v2_status_publisher_with_key(ctx, journal, root_pub, status_priv, 3600)
    genesis = publisher.genesis(ctx, START)
    status_wire = encode_revocation_list_v2(genesis.list)
    print(f"status: genesis list signed by the status key (sequence {genesis.state.sequence}, {len(genesis.state.revoked)} revoked)")

    # 5. The verifier issues a challenge. The helper persists the record
    # before it returns the challenge.
    issuance = TestOnlyChallengeIssuanceStore()
    challenge = V2ChallengeIssuer(clock=store, store=issuance).issue_challenge_v2(ctx, V2ChallengeIssueRequest(
        verifier_namespace=NAMESPACE, replay_epoch=EPOCH, verifier_id=verifier_id,
        lifetime_seconds=120, expected_agent_id=agent_id, expected_agent_public_key=agent_pub,
    ))
    print(f"challenge: issued and persisted, expires in {challenge.expires_at - challenge.issued_at}s")

    # 6. The agent signs a proof bundle over the challenge.
    store.set_time(START + 2)
    bundle = sign_proof_bundle_v2(ProofBundleV2(
        version=2, verifier_id=verifier_id, agent_id=agent_id, agent_pub_key=agent_pub,
        delegations=[cert], challenge=challenge.value, challenge_at=challenge.issued_at,
        delegation_digest=b"", challenge_sig=None,  # computed by sign_proof_bundle_v2
    ), agent_priv)
    bundle_wire = encode_proof_bundle_v2(bundle)
    print(f"proof: agent signed the presentation ({len(bundle.delegations)} delegation)")

    # 7. Verify. The verifier loads the issuance record for the presented
    # challenge, then runs the full v2 decision path.
    def trust(_ctx, chain):
        # Trust is pinned to the complete root public key, never a key ID.
        if chain[-1].issuer_id == root_id:
            return V2TrustResolution(outcome="trusted", root_key=root_pub)
        return V2TrustResolution(outcome="untrusted")

    def status_evidence(_ctx, _req):
        return V2StatusEvidenceBatch(objects=[V2StatusEvidenceObject(object_type=3, wire=status_wire)])

    def verify():
        expected = load_expected_challenge_v2(ctx, issuance, NAMESPACE, EPOCH, bundle.challenge)
        req = V2VerifyRequest(
            bundle=bundle_wire, expected=expected,
            context_policy=new_v2_context_policy("example.quickstart/v1", False, [], None),
            required_scope="payments:send", verifier_namespace=NAMESPACE, replay_epoch=EPOCH, verifier_id=verifier_id,
            now=store.now(), max_challenge_age_seconds=300, future_skew_seconds=5,
            context=ConstraintContextV2(has_amount=True, requested_amount_micros=12_500_000, requested_currency="USD"),
            tzdb_version=TZDB_VERSION_V2,
            status_keys={root_id: V2StatusKeyConfig(epoch=1, key=status_pub)},
            status_policy=RevocationStatusPolicyV2(max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5),
        )
        cb = V2VerifyCallbacks(claim_store=store, trust=trust, status_evidence=status_evidence, status_journal=journal)
        return verify_proof_bundle_v2(ctx, req, cb)

    outcome = verify()
    if outcome.stage != V2_STAGE_COMMITTED:
        raise SystemExit(f"verify stopped at {outcome.stage}: {outcome.error}")
    print("verify: stage=committed (not actionable until released)")

    # 8. Publish the signed receipt to the log; the checkpoint acknowledges it.
    receipt_wire = store.publish_v2_receipt(ctx, outcome.committed.claim_id(), outcome.committed.receipt_body())
    receipt = decode_verification_receipt_v2(receipt_wire)
    print(f"receipt: published at log sequence {receipt.sequence}")
    ack = store.get_v2_acknowledgement(ctx, LOG_ID, receipt.sequence)
    print(f"checkpoint: acknowledged sequence {ack.sequence}")

    # 9. Release. Only a released decision is actionable.
    result = release_v2_decision(ctx, outcome.committed, receipt_wire, V2ReleaseConfig(
        verifier_public_key=verifier_pub, log_id=LOG_ID, claim_store=store, checkpoint=store,
    ))
    if result.status != V2_RELEASE_RELEASED:
        raise SystemExit(f"release {result.status}: {result.reason}")
    decision = result.decision
    print(f"release: status={result.status} decision={decision.decision()} reason={decision.reason()}")
    print(f"granted scope: {','.join(decision.granted_scope())}")

    # 10. Gate the side effect on allowed() at the receiver's authoritative time.
    print(f"allowed now: {b(decision.allowed(ctx, store))}")

    # 11. Presenting the same proof again is a replay and is never evaluated.
    store.set_time(START + 3)
    replay = verify()
    print(f"replay: stage={replay.stage} disposition={replay.disposition}")

    # 12. The released allow ends at the challenge expiry (an exclusive deadline).
    store.set_time(challenge.expires_at)
    print(f"allowed at challenge expiry: {b(decision.allowed(ctx, store))}")


if __name__ == "__main__":
    main()
