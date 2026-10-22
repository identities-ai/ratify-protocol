"""challenge-issuance.json: the issuance helper persists before exposure,
never overwrites, and the presented challenge claims exactly once even
under concurrent presentation (mirrors Go TestV2ConformanceChallengeIssuance)."""
from __future__ import annotations

import threading

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, keys

from ratify_protocol_v2.challenge_issuance_v2 import (
    V2ChallengeIssuer,
    V2ChallengeIssueRequest,
    load_expected_challenge_v2,
)
from ratify_protocol_v2.claim_store_v2 import ClaimProofConflictError, claim_proof_bundle_v2
from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.protocol_v2 import decode_proof_bundle_v2
from ratify_protocol_v2.v2reference.challenges import (
    PERSIST_FAIL_AFTER_COMMIT,
    PERSIST_FAIL_BEFORE_COMMIT,
    TestOnlyChallengeIssuanceStore,
)
from ratify_protocol_v2.v2reference.store import Store
from ratify_protocol_v2.verify_v2_preflight import preflight_proof_bundle_v2

from ratify_protocol_v2 import _native  # noqa: E402

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

FILE = load("challenge-issuance.json")
SCENARIOS = FILE["scenarios"]
NAMESPACE = "verify-test"
EPOCH = 3


def test_issuance_corpus_shape():
    assert len(SCENARIOS) == 10
    assert sum(len(s["steps"]) for s in SCENARIOS) == 36


class ScriptedRandom:
    def __init__(self, chunks):
        self.data = b"".join(chunks)
        self.offset = 0

    def __call__(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise EOFError("scripted random source exhausted")
        out = self.data[self.offset:self.offset + n]
        self.offset += n
        return out


def present_issued(issuance, claims, wire: bytes, now: int) -> str:
    try:
        bundle = decode_proof_bundle_v2(wire)
    except Exception as exc:  # noqa: BLE001
        return "preflight:" + error_class_of(exc)
    try:
        expected = load_expected_challenge_v2(BACKGROUND, issuance, NAMESPACE, EPOCH, bundle.challenge)
    except Exception as exc:  # noqa: BLE001
        return "preflight:" + error_class_of(exc)
    if expected.expected_session_context is not None:
        policy = new_v2_context_policy("ratify.verify.session-context/v1", True,
                                       ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"],
                                       expected.expected_session_context)
    else:
        policy = new_v2_context_policy("ratify.conformance.context-not-required/v1", False, [], None)
    try:
        preflight = preflight_proof_bundle_v2(bundle, expected, policy, "data:read", NAMESPACE, EPOCH, now, 300, 5)
    except Exception as exc:  # noqa: BLE001
        return "preflight:" + error_class_of(exc)
    try:
        _, disposition, _ = claim_proof_bundle_v2(BACKGROUND, claims, bundle, preflight, NAMESPACE, EPOCH, now)
    except ClaimProofConflictError:
        return "proof_conflict"
    except Exception as exc:  # noqa: BLE001
        return f"claim error: {exc!r}"
    return disposition


@pytest.mark.parametrize("sc", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_challenge_issuance(sc):
    fx = keys()
    claims = Store(sc["steps"][0]["at"], 60, "0123456789abcdef0123456789abcdef", fx.priv("verifier"))
    issuance = TestOnlyChallengeIssuanceStore()
    issuer = V2ChallengeIssuer(clock=claims, store=issuance, random=ScriptedRandom([b64(r) for r in sc.get("random_b64") or []]))
    for i, step in enumerate(sc["steps"]):
        if step.get("at"):
            claims.set_time(step["at"])
        exp = step.get("expect", {})
        op = step["op"]
        if op == "issue":
            r = step["request"]
            req = V2ChallengeIssueRequest(verifier_namespace=r["verifier_namespace"], replay_epoch=r["replay_epoch"],
                                          verifier_id=r["verifier_id"], lifetime_seconds=r["lifetime_seconds"])
            if r.get("expected_agent") is not None:
                req.expected_agent_id, req.expected_agent_public_key = fx.id[r["expected_agent"]], fx.pub[r["expected_agent"]]
            if r.get("expected_receiver_id") is not None:
                req.expected_receiver_id = r["expected_receiver_id"]
            if r.get("expected_session_context_b64") is not None:
                req.expected_session_context = b64(r["expected_session_context_b64"])
            fault = step.get("persist_fault", "")
            if fault == "fail_before_commit":
                issuance.fail_next_persist(PERSIST_FAIL_BEFORE_COMMIT)
            elif fault == "fail_after_commit":
                issuance.fail_next_persist(PERSIST_FAIL_AFTER_COMMIT)
            try:
                got, err = issuer.issue_challenge_v2(BACKGROUND, req), None
            except Exception as exc:  # noqa: BLE001
                got, err = None, exc
            if exp["result"] == "issued":
                assert err is None, (i, err)
                assert (got.value, got.issued_at, got.expires_at) == (b64(exp["challenge_b64"]), exp["issued_at"], exp["expires_at"]), i
                stored = load_expected_challenge_v2(BACKGROUND, issuance, req.verifier_namespace, req.replay_epoch, got.value)
                assert stored.expected_agent_id == req.expected_agent_id
                assert stored.expected_session_context == req.expected_session_context
            elif exp["result"] == "error":
                assert err is not None and got is None, i
                if exp.get("error_class"):
                    assert error_class_of(err) == exp["error_class"], (i, err)
            else:
                raise AssertionError(f"unknown issue result {exp['result']}")
            if exp.get("records_after") is not None:
                assert len(issuance) == exp["records_after"], i
        elif op == "load":
            try:
                got, err = load_expected_challenge_v2(BACKGROUND, issuance, NAMESPACE, EPOCH, b64(step["challenge_b64"])), None
            except Exception as exc:  # noqa: BLE001
                got, err = None, exc
            if exp["result"] == "found":
                assert err is None and got.issued_at == exp["issued_at"] and got.expires_at == exp["expires_at"], (i, err)
            else:
                assert error_class_of(err) == exp["result"], (i, err)
        elif op in ("present", "present_concurrent"):
            wires = [b64(b) for b in step["bundles_b64"]]
            outcomes = [None] * len(wires)

            def run(j, wire):
                outcomes[j] = present_issued(issuance, claims, wire, step["at"])

            threads = [threading.Thread(target=run, args=(j, w)) for j, w in enumerate(wires)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            if exp["result"] == "preflight":
                want = ["preflight:" + exp["error_class"]]
            elif exp["result"] == "claimed":
                want = sorted(exp["dispositions"])
            else:
                raise AssertionError(f"unknown present result {exp['result']}")
            assert sorted(outcomes) == want, (i, outcomes)
        else:
            raise AssertionError(f"unknown op {op}")
