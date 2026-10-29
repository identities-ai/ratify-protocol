"""Finalization binds the receipt body to the sealed claim (SPEC-v2 §7.5).
Mirrors Go TestFinalizeClaimProofBundleV2BindsReceiptBodyToSealedClaim: a
capability holder that changes any bound member of the receipt body could
otherwise get a signed, log-appended receipt naming another proof, agent, or
scope."""
from __future__ import annotations

import copy

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, build_verify_request

from ratify_protocol.v2.authorization_v2 import V2LocalAuthorizationOptions, evaluate_proof_bundle_v2_local_authorization
from ratify_protocol.v2.claim_store_v2 import (
    V2_CLAIM_CREATED,
    V2ClaimResult,
    claim_proof_bundle_v2,
    finalize_claim_proof_bundle_v2,
    validate_v2_finalization_payload,
)
from ratify_protocol.v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol.v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol.v2.evaluation_progress_v2 import initial_v2_evaluation_progress, v2_evaluation_interrupted_result
from ratify_protocol.v2.protocol_v2 import decode_proof_bundle_v2
from ratify_protocol.v2.types_v2 import ConstraintEvaluatorRefV2
from ratify_protocol.v2.verification_receipt_v2 import decode_verification_receipt_body_v2, verification_receipt_v2_body
from ratify_protocol.v2.verify_v2_preflight import preflight_proof_bundle_v2

LIFECYCLE = load("lifecycle-scenarios.json")


class RecordingClaimStore:
    """Creates every claim and counts finalization calls."""

    def __init__(self):
        self.finalize_calls = 0

    def claim_v2(self, ctx, claim):
        return V2ClaimResult(disposition=V2_CLAIM_CREATED, claimed_at=LIFECYCLE["requests"]["A"]["now"],
                             owner_token=bytes(range(32)))

    def finalize_v2_claim(self, ctx, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until):
        self.finalize_calls += 1
        return True


def interrupted_fixture():
    request = copy.deepcopy(LIFECYCLE["requests"]["A"])
    now = request["now"]
    bundle = decode_proof_bundle_v2(b64(LIFECYCLE["bundles_b64"][request["bundle"]]))
    req, _, _ = build_verify_request(request, None, Counts())
    pre = preflight_proof_bundle_v2(bundle, req.expected, req.context_policy, req.required_scope, req.verifier_namespace,
                                    req.replay_epoch, req.verifier_id, now, req.max_challenge_age_seconds, req.future_skew_seconds)
    store = RecordingClaimStore()
    claim, _, token = claim_proof_bundle_v2(BACKGROUND, store, bundle, pre, req.verifier_namespace, req.replay_epoch, now)
    # A context policy other than the sealed one interrupts the evaluation.
    other_policy = new_v2_context_policy("ratify.test.other-context/v1", False, [], None)
    root = bundle.delegations[-1]
    assessment = evaluate_proof_bundle_v2_local_authorization(bundle, V2LocalAuthorizationOptions(
        future_skew_seconds=req.future_skew_seconds, required_scope=req.required_scope, context=req.context,
        tzdb_version=req.tzdb_version, context_policy=other_policy, claim_token=token, trust_configured=True,
        trusted_root_id=root.issuer_id, trusted_root_key=root.issuer_pub_key, expected_challenge=req.expected))
    assert assessment.reason == "evaluation_interrupted", assessment
    terminal, body = v2_evaluation_interrupted_result(claim, now, initial_v2_evaluation_progress())
    return store, claim, token, terminal, body, other_policy


def mutate(body: bytes, edit) -> bytes:
    receipt = decode_verification_receipt_body_v2(body)
    edit(receipt)
    return verification_receipt_v2_body(receipt)


def _issuers(r):
    r.issuer_ids = r.issuer_ids[:-1]


EDITS = {
    "verifier_id": lambda r: setattr(r, "verifier_id", "e" * 64),
    "agent_id": lambda r: setattr(r, "agent_id", "e" * 64),
    "bundle_hash": lambda r: setattr(r, "bundle_hash", "sha384:" + "0" * 96),
    "issuer_ids": _issuers,
    "required_scope": lambda r: setattr(r, "required_scope", "data:write"),
    "constraint_evaluators": lambda r: setattr(r, "constraint_evaluators", [ConstraintEvaluatorRefV2(
        profile_digest="sha384:" + "1" * 96, type="com.ratifyprotocol.max_count")]),
}


@pytest.mark.parametrize("name", [*EDITS, "context_policy_digest"])
def test_finalize_refuses_body_bound_to_another_claim(name):
    store, claim, token, terminal, genuine, other_policy = interrupted_fixture()
    if name == "context_policy_digest":
        def edit(r):
            r.trust_assessment, r.context_assessment, r.context_policy_digest = "trusted", "bound", other_policy._digest
    else:
        edit = EDITS[name]
    body = mutate(genuine, edit)
    with pytest.raises(Exception) as raised:
        finalize_claim_proof_bundle_v2(BACKGROUND, store, token, terminal, body)
    assert error_class_of(raised.value) == V2ErrorClass.CONFIGURATION_INVALID, raised.value
    assert store.finalize_calls == 0
    with pytest.raises(Exception) as raised:
        validate_v2_finalization_payload(claim, terminal, body)
    assert error_class_of(raised.value) == V2ErrorClass.CONFIGURATION_INVALID, raised.value
    # The genuine body still finalizes after the refused attempt.
    assert finalize_claim_proof_bundle_v2(BACKGROUND, store, token, terminal, genuine) is True
    assert store.finalize_calls == 1


def test_finalize_refuses_a_body_that_is_not_a_receipt_body():
    store, _, token, terminal, _, _ = interrupted_fixture()
    with pytest.raises(Exception) as raised:
        finalize_claim_proof_bundle_v2(BACKGROUND, store, token, terminal,
                                       b'{"decision":"indeterminate","decision_reason":"evaluation_interrupted"}')
    assert error_class_of(raised.value) == V2ErrorClass.MALFORMED, raised.value
    assert store.finalize_calls == 0
