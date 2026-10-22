"""The released decision is unforgeable, the committed outcome is opaque,
the error classes equal SPEC-v2 §2.7 exactly, status is issuer-scoped, and
the live verifier never crashes on arbitrary input."""
from __future__ import annotations

import copy
import copyreg
import pickle
import re
import weakref
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from corpus import V2_DIR, b64, load
from v2_harness import BACKGROUND, Counts, FixedClock, ScriptedClaimStore, build_verify_request, keys

from ratify_protocol_v2 import _native, release_v2
from ratify_protocol_v2.claim_store_v2 import V2EvaluationToken, terminal_payload_matches_v2
from ratify_protocol_v2.errors_v2 import ALL_ERROR_CLASSES, V2ErrorClass
from ratify_protocol_v2.protocol_v2 import RevocationListV2, sign_revocation_list_v2
from ratify_protocol_v2.release_v2 import CommittedV2Outcome, V2ReleasedDecision, V2ReleaseConfig, release_v2_decision
from ratify_protocol_v2.verify_v2 import verify_proof_bundle_v2
from ratify_protocol_v2.verify_v2_preflight import V2PreflightResult

SPEC = V2_DIR.parents[1] / "SPEC-v2.md"


def test_error_classes_equal_the_spec_table():
    text = SPEC.read_text(encoding="utf-8")
    section = text[text.index("### 2.7 Error classes"):text.index("## 3. Typed signing contract")]
    table = [line for line in section.splitlines() if line.startswith("| `")]
    spec = set()
    for line in table:
        spec.update(re.findall(r"`([a-z_]+)`", line.split("|")[1]))
    assert len(spec) == 49
    assert "The list has 49 classes." in section
    assert ALL_ERROR_CLASSES == spec
    assert V2ErrorClass.UNCLASSIFIED not in ALL_ERROR_CLASSES


def test_released_decision_has_no_public_constructor():
    with pytest.raises(TypeError):
        V2ReleasedDecision()
    with pytest.raises(TypeError):
        V2ReleasedDecision(object(), claim_id="c", decision="allow")
    with pytest.raises(TypeError):
        CommittedV2Outcome()
    with pytest.raises(TypeError):
        V2EvaluationToken()
    with pytest.raises(TypeError):
        V2PreflightResult()


def test_importers_find_no_seal_or_factory():
    """No module attribute lets an importer register a released decision:
    the former sentinel and factory are gone, and the registry exists only
    in the closure behind release_v2_decision."""
    for name in ("_SEAL", "_create", "_seal", "_token"):
        assert not hasattr(release_v2, name)
        assert not hasattr(V2ReleasedDecision, name)
    for value in vars(release_v2).values():
        assert not isinstance(value, weakref.WeakKeyDictionary)
        assert not isinstance(value, weakref.WeakSet)
    with pytest.raises(TypeError):
        type("Sub", (V2ReleasedDecision,), {})
    with pytest.raises(TypeError):
        type("Sub", (CommittedV2Outcome,), {})


def _forgeries():
    cls = V2ReleasedDecision
    yield object.__new__(cls)
    yield cls.__new__(cls)
    yield copy.copy(object.__new__(cls))
    yield copy._reconstruct(object.__new__(cls), None, copyreg.__newobj__, (cls,), None)


def test_zero_or_decoded_decision_is_never_actionable():
    clock = FixedClock(1)
    for forged in _forgeries():
        assert forged.decision() == "" and forged.claim_id() == "" and not forged.allowed(BACKGROUND, clock)
        assert forged.allow_horizon() == (0, False) and forged.receipt_wire() == b""
        with pytest.raises(AttributeError):
            forged._decision = "allow"
        # The instance has no storage of its own to fill in.
        with pytest.raises(AttributeError):
            object.__setattr__(forged, "_decision", "allow")
        with pytest.raises(AttributeError):
            object.__setattr__(forged, "_unknown", 1)
        with pytest.raises(TypeError):
            pickle.dumps(forged)
        assert copy.copy(forged) is forged and copy.deepcopy(forged) is forged
        assert not forged.allowed(BACKGROUND, clock)
    # Calling the accessor on an unrelated object with the right-looking
    # fields does not help either.
    class LooksReleased:
        _decision, _receipt_wire, _allow_horizon, _challenge_expires_at = "allow", b"x", 100, 100
    assert not V2ReleasedDecision.allowed(LooksReleased(), BACKGROUND, clock)


def test_forged_result_wrapper_is_not_actionable():
    forged = release_v2.V2ReleaseResult(status="released", decision=object.__new__(V2ReleasedDecision))
    assert not forged.decision.allowed(BACKGROUND, FixedClock(1))


def test_forged_committed_outcome_is_rejected():
    config = V2ReleaseConfig(verifier_public_key=keys().pub["verifier"], log_id="0" * 32, claim_store=object(), checkpoint=object())
    result = release_v2_decision(BACKGROUND, object.__new__(CommittedV2Outcome), b"wire", config)
    assert (result.status, result.reason, result.decision) == ("rejected", "release_state_mismatch", None)
    with pytest.raises(AttributeError):
        object.__new__(CommittedV2Outcome)._claim_id = "x"


def test_release_requires_a_typed_committed_outcome():
    config = V2ReleaseConfig(verifier_public_key=keys().pub["verifier"], log_id="0" * 32, claim_store=object(), checkpoint=object())
    for bogus in (None, "outcome", {"claim_id": "c"}):
        assert release_v2_decision(BACKGROUND, bogus, b"wire", config).status == "rejected"


@pytest.mark.skipif(not _native.AVAILABLE, reason="signing the status lists needs ratify-protocol-native-v2")
def test_status_is_issuer_scoped_for_colliding_cert_ids():
    """Two issuers using the same cert_id: a revocation by one issuer never
    affects the other's certificate (issuer collision)."""
    from ratify_protocol_v2.security_journal_v2 import (
        apply_revocation_list_to_journal_v2,
        configure_status_key_epoch_v2,
        revocation_status_from_journal_v2,
    )
    from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2
    from ratify_protocol_v2.v2reference.journal import JournalStore

    fx = keys()
    issuer_a, issuer_b = fx.id["root"], fx.id["intermediate"]
    status_a, status_b = "status_root", "status_intermediate"
    store = JournalStore()
    configure_status_key_epoch_v2(BACKGROUND, store, issuer_a, 1, fx.pub[status_a])
    configure_status_key_epoch_v2(BACKGROUND, store, issuer_b, 1, fx.pub[status_b])
    policy = RevocationStatusPolicyV2(max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5)
    now = 1800000000
    revoking = sign_revocation_list_v2(RevocationListV2(version=2, issuer_id=issuer_a, updated_at=now, next_update=now + 600,
                                                       sequence=1, revoked=["shared-cert"]),
                                       issuer_a, fx.pub[status_a], fx.priv(status_a))
    clean = sign_revocation_list_v2(RevocationListV2(version=2, issuer_id=issuer_b, updated_at=now, next_update=now + 600,
                                                    sequence=1, revoked=[]),
                                    issuer_b, fx.pub[status_b], fx.priv(status_b))
    apply_revocation_list_to_journal_v2(BACKGROUND, store, revoking, issuer_a, 1, fx.pub[status_a], policy, now)
    apply_revocation_list_to_journal_v2(BACKGROUND, store, clean, issuer_b, 1, fx.pub[status_b], policy, now)
    a = revocation_status_from_journal_v2(BACKGROUND, store, issuer_a, "shared-cert", 1, fx.pub[status_a], policy, now + 1)
    b = revocation_status_from_journal_v2(BACKGROUND, store, issuer_b, "shared-cert", 1, fx.pub[status_b], policy, now + 1)
    assert a.status == "revoked"
    assert b.status == "not_revoked"
    # A list signed by issuer A's status key cannot be applied as issuer B's.
    with pytest.raises(Exception):
        apply_revocation_list_to_journal_v2(BACKGROUND, store, revoking, issuer_b, 1, fx.pub[status_b], policy, now)


ORDERING = load("verifier-ordering.json")
BASE = next(v for v in ORDERING["vectors"] if v["expected"]["stage"] == "committed")


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=4096))
def test_verifier_rejects_arbitrary_bundles_before_claim(data):
    counts = Counts()
    req, cb, _ = build_verify_request(BASE, data, counts)
    cb.claim_store = ScriptedClaimStore("create", BASE["now"], BASE["now"], counts)
    outcome = verify_proof_bundle_v2(BACKGROUND, req, cb)
    assert outcome.stage == "preflight" and outcome.error_class == "malformed"
    assert counts.claim == 0 and counts.trust == 0 and counts.status == 0


@settings(max_examples=150, deadline=None)
@given(st.binary(max_size=4096))
def test_verifier_mutated_bundle_never_crashes(mutation):
    bundle = bytearray(b64(ORDERING["bundles_b64"][BASE["bundle"]]))
    for i, byte in enumerate(mutation[:64]):
        bundle[(i * 7919 + byte) % len(bundle)] ^= byte
    counts = Counts()
    req, cb, _ = build_verify_request(BASE, bytes(bundle), counts)
    cb.claim_store = ScriptedClaimStore("create", BASE["now"], BASE["now"], counts)
    outcome = verify_proof_bundle_v2(BACKGROUND, req, cb)
    assert outcome.stage in ("preflight", "committed")
    if outcome.stage == "preflight":
        assert outcome.error_class in ALL_ERROR_CLASSES and counts.claim == 0


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=512), st.binary(max_size=512))
def test_terminal_payload_reader_never_crashes(a, b):
    assert terminal_payload_matches_v2(a, b, "deny", "unauthorized") in (True, False)
