"""Ratify Protocol v2 custom scope and the standard max_count evaluator
profile (com.ratifyprotocol.max_count/v1).

DEVELOPMENT ONLY. This program uses the in-memory reference stores from
ratify_protocol_v2.v2reference. A production verifier supplies durable Part B
stores and an independent checkpoint (SPEC-v2 §7).

Run: python examples/v2/python/custom_scope.py
"""
from dataclasses import replace

from ratify_protocol_v2 import background, error_class_of, key_id_v2
from ratify_protocol_v2.challenge_issuance_v2 import V2ChallengeIssuer, V2ChallengeIssueRequest, load_expected_challenge_v2
from ratify_protocol_v2.constraint_evaluator_v2 import (
    CONSTRAINT_MAX_COUNT_V2,
    PROFILE_MAX_COUNT_V2,
    constraint_profile_digest_v2,
    new_constraint_evaluator_registry_v2,
    standard_max_count_evaluator_v2,
)
from ratify_protocol_v2.constraints_v2 import TZDB_VERSION_V2, ConstraintContextV2, ConstraintV2
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
from ratify_protocol_v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)

START = 1800000000
NAMESPACE = "custom-scope"
EPOCH = 1
LOG_ID = "00000000000000000000000000000003"
CUSTOM_SCOPE = "custom:acme:deploy"


def b(value: bool) -> str:
    return "true" if value else "false"


def main() -> None:
    ctx = background()
    print("Ratify Protocol v2 custom scope and max_count profile")
    print("development only: in-memory reference stores")

    root_pub, root_priv = generate_keypair_v2()
    agent_pub, agent_priv = generate_keypair_v2()
    status_pub, status_priv = generate_keypair_v2()
    verifier_pub, verifier_priv = generate_keypair_v2()
    root_id, agent_id, verifier_id = key_id_v2(root_pub), key_id_v2(agent_pub), key_id_v2(verifier_pub)

    template = DelegationCertV2(
        version=2, cert_id="custom-scope-cert-1",
        issuer_id=root_id, issuer_pub_key=root_pub, subject_id=agent_id, subject_pub_key=agent_pub,
        scope=[], constraints=[], issued_at=START, expires_at=START + 86400,
    )

    # A custom scope is one exact name. Wildcards are invalid.
    try:
        sign_delegation_cert_v2(replace(template, scope=["custom:*"]), root_priv)
        refused = ""
    except Exception as exc:  # noqa: BLE001 - the example prints the error class
        refused = error_class_of(exc)
    print(f"issue scope custom:*: refused ({refused})")

    # The certificate carries an extension constraint. Only a verifier that
    # registered the max_count/v1 profile for this type can evaluate it.
    cert = sign_delegation_cert_v2(replace(
        template, scope=[CUSTOM_SCOPE],
        constraints=[ConstraintV2(type=CONSTRAINT_MAX_COUNT_V2, params={"counter": "nodes", "max": 5})],
    ), root_priv)
    print(f"delegation: scope={CUSTOM_SCOPE} constraint={CONSTRAINT_MAX_COUNT_V2}(counter=nodes, max=5)")

    max_count = standard_max_count_evaluator_v2()
    digest = constraint_profile_digest_v2(max_count.descriptor)
    print(f"profile: {PROFILE_MAX_COUNT_V2} digest={digest}")
    registry = new_constraint_evaluator_registry_v2(1.0, max_count)

    journal = new_journal_store()
    record_security_key_role_v2(ctx, journal, "issuer", root_pub)
    configure_status_key_epoch_v2(ctx, journal, root_id, 1, status_pub)
    publisher = new_v2_status_publisher_with_key(ctx, journal, root_pub, status_priv, 3600)
    status_wire = encode_revocation_list_v2(publisher.genesis(ctx, START).list)

    store = Store(START, 30, LOG_ID, verifier_priv)
    issuance = TestOnlyChallengeIssuanceStore()

    def trust(_ctx, chain):
        if chain[-1].issuer_id == root_id:
            return V2TrustResolution(outcome="trusted", root_key=root_pub)
        return V2TrustResolution(outcome="untrusted")

    def status_evidence(_ctx, _req):
        return V2StatusEvidenceBatch(objects=[V2StatusEvidenceObject(object_type=3, wire=status_wire)])

    def attempt(label: str, nodes: int, evaluators) -> None:
        """Verify one request for `nodes` nodes and release the result."""
        store.set_time(store.now() + 1)
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
            context_policy=new_v2_context_policy("example.custom-scope/v1", False, [], None),
            required_scope=CUSTOM_SCOPE, verifier_namespace=NAMESPACE, replay_epoch=EPOCH, verifier_id=verifier_id, now=store.now(),
            max_challenge_age_seconds=300, future_skew_seconds=5, tzdb_version=TZDB_VERSION_V2,
            # The requested quantity comes from the authenticated request,
            # never from the proof.
            context=ConstraintContextV2(extension_counts={"nodes": nodes}),
            constraint_evaluators=evaluators,
            status_keys={root_id: V2StatusKeyConfig(epoch=1, key=status_pub)},
            status_policy=RevocationStatusPolicyV2(max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5),
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
        print(f"{label}: decision={d.decision()} reason={d.reason()} allowed={b(d.allowed(ctx, store))}")
        for ref in d.receipt().constraint_evaluators or []:
            print(f"  receipt constraint_evaluators: {ref.type} {ref.profile_digest}")

    attempt("request nodes=3", 3, registry)
    attempt("request nodes=8", 8, registry)
    attempt("request nodes=3 without the profile registered", 3, None)


if __name__ == "__main__":
    main()
