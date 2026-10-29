"""Configuration and wire bounds from the pre-release review: verifier step 2
(SPEC-v2 §2.5, §6.1, §6.2), rotation clock inputs, revoked cert_id length
(§2.6), transaction receipt nested bundles (§2.1, §5.7), classified key-ID
helpers (§2.7), and hook and provider containment. Mirrors Go
verify_v2_order_test.go, key_rotation_v2_test.go, protocol_v2_wire_test.go
and transaction_receipt_v2_test.go."""
from __future__ import annotations

import base64

import pytest

from corpus import b64, load, pubkey
from v2_harness import BACKGROUND, Counts, ScriptedClaimStore, build_verify_request

from ratify_protocol.v2 import key_rotation_v2 as kr
from ratify_protocol.v2 import protocol_v2 as pv2
from ratify_protocol.v2.clock_bounds_v2 import V2_MAX_TIMESTAMP_SECONDS
from ratify_protocol.v2.crypto_v2 import derive_key_id_v2
from ratify_protocol.v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol.v2.limits_v2 import MAX_IDENTIFIER_LENGTH_BYTES
from ratify_protocol.v2.signing_v2 import key_id_v2
from ratify_protocol.v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol.v2.transaction_receipt_v2 import decode_transaction_receipt_v2
from ratify_protocol.v2.types import HybridPublicKey, HybridSignature
from ratify_protocol.v2.verification_receipt_v2 import decode_verification_receipt_body_v2
from ratify_protocol.v2.verify_v2 import V2_STAGE_PREFLIGHT, V2VerifyCallbacks, V2VerifyRequest, verify_proof_bundle_v2
from ratify_protocol.v2.verify_v2_preflight import ExpectedChallengeV2, validate_proof_bundle_v2_preflight

LIFECYCLE = load("lifecycle-scenarios.json")
ORDERING = load("verifier-ordering.json")
OBJECTS = load("objects.json")
ROTATION = load("rotation-sequences.json")
KEYS = load("keys.json")
BUNDLE_WIRE = b64(LIFECYCLE["bundles_b64"][LIFECYCLE["requests"]["A"]["bundle"]])
MAX_SAFE_INTEGER = 2**53 - 1


class CountingClaimStore:
    def __init__(self):
        self.calls = 0

    def claim_v2(self, ctx, claim):
        self.calls += 1
        raise AssertionError("the claim store must not be reached")


def _base_request() -> V2VerifyRequest:
    return V2VerifyRequest(bundle=BUNDLE_WIRE, now=1800000000, max_challenge_age_seconds=60, future_skew_seconds=5,
                           verifier_namespace="ns", verifier_id="a" * 64,
                           status_policy=RevocationStatusPolicyV2(max_list_lifetime_seconds=3600,
                                                                  max_status_age_seconds=3600, clock_skew_seconds=5))


def _skew_below(r):
    r.status_policy.clock_skew_seconds = 0


def _skew_above(r):
    r.future_skew_seconds = 0


def _epoch(value):
    def edit(r):
        r.replay_epoch = value
    return edit


def _session_context(value):
    def edit(r):
        r.expected = ExpectedChallengeV2(expected_session_context=value)
    return edit


# Without the fault each request stops later (expected challenge missing, or
# an invalid required scope), so the class proves where the check runs.
STEP_TWO = {
    "status skew below future skew": _skew_below,
    "status skew above future skew": _skew_above,
    "replay epoch above 2^53-1": _epoch(MAX_SAFE_INTEGER + 1),
    "replay epoch negative": _epoch(-1),
    "31-byte expected session context without a policy": _session_context(bytes(31)),
    "empty expected session context without a policy": _session_context(b""),
}


@pytest.mark.parametrize("name", STEP_TWO)
def test_configuration_rejected_at_step_two(name):
    req = _base_request()
    STEP_TWO[name](req)
    store = CountingClaimStore()
    outcome = verify_proof_bundle_v2(BACKGROUND, req, V2VerifyCallbacks(claim_store=store))
    assert (outcome.stage, outcome.error_class, store.calls) == (V2_STAGE_PREFLIGHT, V2ErrorClass.CONFIGURATION_INVALID, 0), outcome.error


@pytest.mark.parametrize("epoch", [-1, MAX_SAFE_INTEGER + 1])
def test_standalone_preflight_replay_epoch_bound(epoch):
    # The standalone preflight applies the same step 2 bound as the verifier,
    # so a caller that runs preflight itself sees configuration_invalid, not
    # stale_replay_epoch.
    bundle = pv2.decode_proof_bundle_v2(BUNDLE_WIRE)
    with pytest.raises(Exception) as raised:
        validate_proof_bundle_v2_preflight(bundle, ExpectedChallengeV2(replay_epoch=epoch), "data:read", "ns", epoch,
                                           bundle.verifier_id, 1800000000, 60, 5)
    assert error_class_of(raised.value) == V2ErrorClass.CONFIGURATION_INVALID, raised.value


def test_rotation_clock_configuration_bounds():
    # A skew of 301 must not admit what 300 rejects (SPEC-v2 §2.5).
    sc = next(s for s in ROTATION["scenarios"] if s["name"] == "clock_now_bounds")
    step = next(s for s in sc["steps"] if s["expect"] == "appended")
    stmt = kr.decode_key_rotation_statement_v2(b64(step["wire_b64"]))
    genesis = pubkey(next(k for k in KEYS["keys"] if k["name"] == sc["genesis_key"])["public_key"])
    state = kr.new_key_rotation_v2_journal(sc["authority_id"], sc["recovery_epoch"], sc["role"], genesis).state
    for now, skew in ((stmt.issued_at, 301), (stmt.issued_at, -1), (-1, 2), (V2_MAX_TIMESTAMP_SECONDS + 1, 2)):
        with pytest.raises(Exception) as raised:
            kr.verify_key_rotation_statement_v2(stmt, state, now, skew)
        assert error_class_of(raised.value) == V2ErrorClass.CONFIGURATION_INVALID, (now, skew, raised.value)
    with pytest.raises(Exception) as raised:
        kr.verify_key_rotation_statement_v2(stmt, state, stmt.not_before - 301, 300)
    assert error_class_of(raised.value) == V2ErrorClass.ROTATION_FUTURE_DATED, raised.value
    kr.verify_key_rotation_statement_v2(stmt, state, stmt.not_before - 300, 300)
    kr.verify_key_rotation_statement_v2(stmt, state, V2_MAX_TIMESTAMP_SECONDS, 0)


@pytest.mark.parametrize("cert_id,ok", [
    ("a" * MAX_IDENTIFIER_LENGTH_BYTES, True),
    ("a" * (MAX_IDENTIFIER_LENGTH_BYTES + 1), False),
    ("é" * (MAX_IDENTIFIER_LENGTH_BYTES // 2), True),
    ("é" * (MAX_IDENTIFIER_LENGTH_BYTES // 2) + "a", False),
])
def test_revoked_cert_id_length_bound(cert_id, ok):
    # SPEC-v2 §2.6: every cert_id, including a revoked reference in a list or
    # a push, is at most MAX_IDENTIFIER_LENGTH_BYTES UTF-8 bytes.
    sig = HybridSignature(ed25519=bytes(64), ml_dsa_65=bytes(3309))
    issuer = "a" * 64
    small_list = pv2.RevocationListV2(version=2, issuer_id=issuer, updated_at=1800000000, next_update=1800003600,
                                      sequence=1, revoked=["x"], signature=sig)
    small_push = pv2.RevocationPushV2(version=2, issuer_id=issuer, sequence=1, pushed_at=1800000000, revoked=["x"],
                                      signature=sig)
    encoded = '"cert_id":"' + cert_id + '"'
    list_wire = pv2.encode_revocation_list_v2(small_list).replace(b'"cert_id":"x"', encoded.encode("utf-8"), 1)
    push_wire = pv2.encode_revocation_push_v2(small_push).replace(b'"cert_id":"x"', encoded.encode("utf-8"), 1)
    full_list = pv2.RevocationListV2(version=2, issuer_id=issuer, updated_at=1800000000, next_update=1800003600,
                                     sequence=1, revoked=[cert_id], signature=sig)
    full_push = pv2.RevocationPushV2(version=2, issuer_id=issuer, sequence=1, pushed_at=1800000000, revoked=[cert_id],
                                     signature=sig)
    for name, call in {
        "decode list": lambda: pv2.decode_revocation_list_v2(list_wire),
        "decode push": lambda: pv2.decode_revocation_push_v2(push_wire),
        "encode list": lambda: pv2.encode_revocation_list_v2(full_list),
        "encode push": lambda: pv2.encode_revocation_push_v2(full_push),
    }.items():
        try:
            call()
            err = None
        except Exception as exc:  # noqa: BLE001
            err = exc
        assert (err is None) == ok, (name, err)
        if not ok:
            assert error_class_of(err) == V2ErrorClass.MALFORMED, (name, err)


@pytest.mark.parametrize("old,new", [
    (b'"challenge_at":1799999990', b'"challenge_at":"1799999990"'),
    (b'"proof_bundle":{', b'"proof_bundle":{ '),
])
def test_transaction_receipt_decodes_bundle_before_hash(old, new):
    # SPEC-v2 §2.1, §5.7: a nested bundle that does not strictly decode, or is
    # not canonical, is malformed even though its hash no longer matches.
    obj = next(o for o in OBJECTS["objects"] if o["name"] == "transaction_receipt_two_parties")
    wire = base64.b64decode(obj["wire_b64"])
    mutated = wire.replace(old, new, 1)
    assert mutated != wire
    with pytest.raises(Exception) as raised:
        decode_transaction_receipt_v2(mutated)
    assert error_class_of(raised.value) == V2ErrorClass.MALFORMED, raised.value


@pytest.mark.parametrize("helper", [key_id_v2, derive_key_id_v2])
def test_key_id_helpers_raise_classified_malformed(helper):
    # SPEC-v2 §2.7: no public v2 API leaves an error unclassified. The error
    # stays a ValueError for callers that already catch one.
    for pub in (HybridPublicKey(ed25519=bytes(31), ml_dsa_65=bytes(1952)),
                HybridPublicKey(ed25519=bytes(32), ml_dsa_65=bytes(1951))):
        with pytest.raises(ValueError) as raised:
            helper(pub)
        assert error_class_of(raised.value) == V2ErrorClass.MALFORMED


# ---------------------------------------------------------------------------
# Hook and provider containment


class ProviderFailure(BaseException):
    """Not an Exception: the Python counterpart of a Go panic that ordinary
    ``except Exception`` would let escape."""


def _ordering_vector(name: str) -> dict:
    return next(v for v in ORDERING["vectors"] if v["name"] == name)


def _raising(exc_type):
    def call(*args):
        raise exc_type("scripted provider failure")
    return call


def _run(v: dict, attribute: str, exc_type):
    counts = Counts()
    req, cb, _ = build_verify_request(v, b64(ORDERING["bundles_b64"][v["bundle"]]), counts)
    claimed_at = v["now"] + v.get("claim_time_offset", 0)
    cb.claim_store = ScriptedClaimStore(v.get("claim_store", ""), claimed_at,
                                        claimed_at + v.get("finalize_time_offset", 0), counts)
    if attribute == "status_evidence":
        inner = cb.status_evidence
        failing = set(issuer for issuer, script in v["status_evidence"].items() if script.get("mode") == "panic")

        def status(ctx, request):
            if request.issuer_id in failing:
                raise exc_type("scripted status provider failure")
            return inner(ctx, request)

        cb.status_evidence = status
    else:
        setattr(cb, attribute, _raising(exc_type))
    return verify_proof_bundle_v2(BACKGROUND, req, cb)


# Each vector scripts a Go panic; a BaseException must give the same result.
CONTAINMENT = {
    "receiver_binding": "receiver_binding_hook_rejects",
    "trust": "trust_provider_panic",
    "status_evidence": "status_provider_panic",
    "audience": "audience_provider_panic",
}


@pytest.mark.parametrize("attribute", CONTAINMENT)
def test_base_exception_from_hook_or_provider_fails_closed(attribute):
    v = _ordering_vector(CONTAINMENT[attribute])
    want = v["expected"]
    outcome = _run(v, attribute, ProviderFailure)
    assert (outcome.stage, outcome.error_class) == (want["stage"], want.get("error_class", "")), outcome.error
    if want["stage"] == "committed":
        body = decode_verification_receipt_body_v2(outcome.committed.receipt_body())
        assert (body.decision, body.decision_reason) == (want["decision"], want["decision_reason"])


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("attribute", CONTAINMENT)
def test_interpreter_cancellation_propagates(attribute, exc_type):
    # KeyboardInterrupt and SystemExit are the caller's own cancellation, not a
    # provider failure, so they are never turned into a committed result.
    with pytest.raises(exc_type):
        _run(_ordering_vector(CONTAINMENT[attribute]), attribute, exc_type)
