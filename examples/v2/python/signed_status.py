"""Ratify Protocol v2 signed status: a status publisher under a separate
status key, journal ingestion, and a revocation that turns a later
verification into deny.

DEVELOPMENT ONLY. This program uses the in-memory reference stores from
ratify_protocol_v2.v2reference. A production verifier supplies durable Part B
stores, an anchored journal store and an independent checkpoint (SPEC-v2 §7).

Run: python examples/v2/python/signed_status.py
"""
from ratify_protocol_v2 import background, error_class_of, key_id_v2
from ratify_protocol_v2.challenge_issuance_v2 import V2ChallengeIssuer, V2ChallengeIssueRequest, load_expected_challenge_v2
from ratify_protocol_v2.constraints_v2 import TZDB_VERSION_V2
from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol_v2.protocol_v2 import (
    DelegationCertV2,
    ProofBundleV2,
    encode_proof_bundle_v2,
    encode_revocation_list_v2,
    encode_revocation_push_v2,
    sign_delegation_cert_v2,
    sign_proof_bundle_v2,
)
from ratify_protocol_v2.release_v2 import V2_RELEASE_RELEASED, V2ReleaseConfig, release_v2_decision
from ratify_protocol_v2.security_journal_v2 import (
    apply_revocation_list_to_journal_v2,
    apply_revocation_push_to_journal_v2,
    configure_status_key_epoch_v2,
    record_security_key_role_v2,
    revocation_status_from_journal_v2,
)
from ratify_protocol_v2.signing_v2 import generate_keypair_v2
from ratify_protocol_v2.status_batch_v2 import V2StatusEvidenceBatch, V2StatusEvidenceObject
from ratify_protocol_v2.status_provenance_v2 import V2StatusKeyConfig
from ratify_protocol_v2.status_publisher_v2 import new_v2_status_publisher_with_key
from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol_v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol_v2.v2reference.journal import new_journal_store
from ratify_protocol_v2.v2reference.store import Store
from ratify_protocol_v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)

START = 1800000000
NAMESPACE = "signed-status"
EPOCH = 1
LOG_ID = "00000000000000000000000000000002"
CERT_ID = "status-demo-cert-1"


def b(value: bool) -> str:
    return "true" if value else "false"


def main() -> None:
    ctx = background()
    print("Ratify Protocol v2 signed status")
    print("development only: in-memory reference stores")

    root_pub, root_priv = generate_keypair_v2()
    agent_pub, agent_priv = generate_keypair_v2()
    status_pub, status_priv = generate_keypair_v2()
    verifier_pub, verifier_priv = generate_keypair_v2()
    root_id, agent_id, verifier_id = key_id_v2(root_pub), key_id_v2(agent_pub), key_id_v2(verifier_pub)

    cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2, cert_id=CERT_ID,
        issuer_id=root_id, issuer_pub_key=root_pub, subject_id=agent_id, subject_pub_key=agent_pub,
        scope=["data:read"], constraints=[], issued_at=START, expires_at=START + 86400,
    ), root_priv)
    print(f"delegation: {CERT_ID} scope=data:read")

    # The journal is the verifier's anchored record of key roles, status-key
    # epochs and accepted status. Roles are recorded once, when the
    # deployment authenticates its trust configuration.
    journal = new_journal_store()
    for role, pub in (("issuer", root_pub), ("delegation", agent_pub), ("verifier", verifier_pub)):
        record_security_key_role_v2(ctx, journal, role, pub)
    configure_status_key_epoch_v2(ctx, journal, root_id, 1, status_pub)
    print("journal: key roles recorded; status key configured for the root at epoch 1")

    # Role separation: the root key can never sign status for itself.
    try:
        new_v2_status_publisher_with_key(ctx, journal, root_pub, root_priv, 3600)
        refused = ""
    except Exception as exc:  # noqa: BLE001 - the example prints the error class
        refused = error_class_of(exc)
    print(f"publisher with the root key as status key: refused ({refused})")

    publisher = new_v2_status_publisher_with_key(ctx, journal, root_pub, status_priv, 3600)
    policy = RevocationStatusPolicyV2(max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5)

    # Genesis: sequence 1, nothing revoked. The caller persists the returned
    # state before publishing the signed list.
    genesis = publisher.genesis(ctx, START)
    genesis_wire = encode_revocation_list_v2(genesis.list)
    print(f"publisher: genesis list sequence {genesis.list.sequence}")
    apply_revocation_list_to_journal_v2(ctx, journal, genesis.list, root_id, 1, status_pub, policy, START)
    status = revocation_status_from_journal_v2(ctx, journal, root_id, CERT_ID, 1, status_pub, policy, START)
    print(f"journal: ingested list sequence {genesis.list.sequence}; {CERT_ID} is {status.status}")

    store = Store(START, 30, LOG_ID, verifier_priv)
    issuance = TestOnlyChallengeIssuanceStore()
    evidence = [V2StatusEvidenceObject(object_type=3, wire=genesis_wire)]

    def trust(_ctx, chain):
        if chain[-1].issuer_id == root_id:
            return V2TrustResolution(outcome="trusted", root_key=root_pub)
        return V2TrustResolution(outcome="untrusted")

    # The provider returns signed objects only; the verifier checks each
    # signature against the configured status key and applies it to the
    # journal before it derives a status.
    def status_evidence(_ctx, _req):
        return V2StatusEvidenceBatch(objects=evidence)

    def verify_and_release(label: str) -> None:
        """One complete live verification at the store's current time."""
        challenge = V2ChallengeIssuer(clock=store, store=issuance).issue_challenge_v2(ctx, V2ChallengeIssueRequest(
            verifier_namespace=NAMESPACE, replay_epoch=EPOCH, verifier_id=verifier_id,
            lifetime_seconds=120, expected_agent_id=agent_id, expected_agent_public_key=agent_pub,
        ))
        bundle = sign_proof_bundle_v2(ProofBundleV2(
            version=2, verifier_id=verifier_id, agent_id=agent_id, agent_pub_key=agent_pub,
            delegations=[cert], challenge=challenge.value, challenge_at=challenge.issued_at,
            delegation_digest=b"", challenge_sig=None,  # computed by sign_proof_bundle_v2
        ), agent_priv)
        expected = load_expected_challenge_v2(ctx, issuance, NAMESPACE, EPOCH, bundle.challenge)
        outcome = verify_proof_bundle_v2(ctx, V2VerifyRequest(
            bundle=encode_proof_bundle_v2(bundle), expected=expected,
            context_policy=new_v2_context_policy("example.signed-status/v1", False, [], None),
            required_scope="data:read", verifier_namespace=NAMESPACE, replay_epoch=EPOCH, now=store.now(),
            max_challenge_age_seconds=300, future_skew_seconds=5, tzdb_version=TZDB_VERSION_V2,
            status_keys={root_id: V2StatusKeyConfig(epoch=1, key=status_pub)}, status_policy=policy,
        ), V2VerifyCallbacks(claim_store=store, trust=trust, status_evidence=status_evidence, status_journal=journal))
        if outcome.stage != V2_STAGE_COMMITTED:
            raise SystemExit(f"verify stopped at {outcome.stage}: {outcome.error}")
        receipt_wire = store.publish_v2_receipt(ctx, outcome.committed.claim_id(), outcome.committed.receipt_body())
        result = release_v2_decision(ctx, outcome.committed, receipt_wire, V2ReleaseConfig(
            verifier_public_key=verifier_pub, log_id=LOG_ID, claim_store=store, checkpoint=store,
        ))
        if result.status != V2_RELEASE_RELEASED:
            raise SystemExit(f"release {result.status}: {result.reason}")
        d = result.decision
        receipt = d.receipt()
        print(f"{label}: decision={d.decision()} reason={d.reason()} "
              f"status_assessment={receipt.status_assessment} allowed={b(d.allowed(ctx, store))}")

    store.set_time(START + 5)
    verify_and_release("verify before revocation")

    # Revoke: a push with the newly revoked ID and the cumulative list, both
    # at sequence 2.
    revoked = publisher.revoke(ctx, genesis.state, [CERT_ID], START + 10)
    push_wire = encode_revocation_push_v2(revoked.push)
    list_wire = encode_revocation_list_v2(revoked.list)
    print(f"publisher: revoked {CERT_ID} (push sequence {revoked.push.sequence}, list sequence {revoked.list.sequence})")
    apply_revocation_push_to_journal_v2(ctx, journal, revoked.push, root_id, 1, status_pub, policy, START + 10)
    status = revocation_status_from_journal_v2(ctx, journal, root_id, CERT_ID, 1, status_pub, policy, START + 10)
    print(f"journal: ingested push sequence {revoked.push.sequence}; {CERT_ID} is {status.status}")

    evidence = [V2StatusEvidenceObject(object_type=5, wire=push_wire), V2StatusEvidenceObject(object_type=3, wire=list_wire)]
    store.set_time(START + 15)
    verify_and_release("verify after revocation")


if __name__ == "__main__":
    main()
