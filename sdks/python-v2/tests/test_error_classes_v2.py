"""SPEC-v2 §2.7: every error a public v2 API raises carries exactly one class
from the closed list, never ``unclassified``.

Mirrors Go TestV2PublicAPIErrorsAreClassified (errors_v2_public_test.go):
the same entry points are called with the same inputs they must reject, and
where the reference fixes the class it is asserted exactly, so a port reports
the reference class for the same input.
"""
from __future__ import annotations

import pytest

from ratify_protocol_v2 import archival_v2 as arch
from ratify_protocol_v2 import challenge_claim_v2 as cc
from ratify_protocol_v2 import challenge_issuance_v2 as ci
from ratify_protocol_v2 import checkpoint_ack_v2 as ack
from ratify_protocol_v2 import claim_store_v2 as cs
from ratify_protocol_v2 import constraint_evaluator_v2 as ce
from ratify_protocol_v2 import constraints_v2 as cons
from ratify_protocol_v2 import context_policy_v2 as cp
from ratify_protocol_v2 import context_v2
from ratify_protocol_v2 import evaluation_progress_v2 as ep
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import operation_context_v2 as oc
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import rate_reservation_v2 as rr
from ratify_protocol_v2 import release_v2 as rel
from ratify_protocol_v2 import security_journal_snapshot_v2 as snap
from ratify_protocol_v2 import security_journal_v2 as sj
from ratify_protocol_v2 import signing_v2 as sig
from ratify_protocol_v2 import status_batch_v2 as sb
from ratify_protocol_v2 import status_publisher_v2 as sp
from ratify_protocol_v2 import status_state_v2 as ss
from ratify_protocol_v2 import stream_sequence_v2 as seq
from ratify_protocol_v2 import transaction_receipt_v2 as tx
from ratify_protocol_v2 import transaction_verify_v2 as tv
from ratify_protocol_v2 import verification_receipt_v2 as vr
from ratify_protocol_v2 import verify_v2
from ratify_protocol_v2 import verify_v2_preflight as pre
from ratify_protocol_v2 import witness_v2 as wv
from ratify_protocol_v2 import _native
from ratify_protocol_v2.audience_v2 import evaluate_receiver_audience_v2
from ratify_protocol_v2.authorization_v2 import (
    resolve_claim_proof_bundle_v2_after_audience,
    resolve_claim_proof_bundle_v2_after_rate,
)
from ratify_protocol_v2.constraints_v2 import CONSTRAINT_MAX_RATE, CONSTRAINT_TIME_WINDOW
from ratify_protocol_v2.errors_v2 import ALL_ERROR_CLASSES, V2ErrorClass as C, error_class_of
from ratify_protocol_v2.types import HybridPrivateKey, HybridPublicKey, HybridSignature

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")

CTX = context_v2.background()
GARBAGE = b'{"version":2}'
BAD_KEY = HybridPublicKey(ed25519=bytes(3), ml_dsa_65=b"")
POLICY = ss.RevocationStatusPolicyV2(max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5)


class FailingJournalStore:
    """Fails every load and commit."""

    def load(self, ctx):
        raise RuntimeError("journal backend down")

    def compare_and_swap(self, ctx, expected, next_journal):
        raise RuntimeError("journal backend down")


class FailingSigner:
    """Reports a key and then fails every signing request."""

    def __init__(self, pub):
        self._pub = pub

    def public_key_v2(self):
        return self._pub

    def mode_v2(self):
        return sig.SignerModeV2.DIRECT

    def sign_v2(self, ctx, req):
        raise RuntimeError("hardware signer unavailable")


def _fixtures():
    pub, priv = sig.generate_keypair_v2()
    other, _ = sig.generate_keypair_v2()
    key_id = sig.key_id_v2(pub)
    cancelled = context_v2.with_cancel(CTX)
    cancelled.cancel()
    lst = pv2.RevocationListV2(version=2, issuer_id=key_id, updated_at=100, next_update=200, sequence=1, revoked=[])
    push = pv2.RevocationPushV2(version=2, issuer_id=key_id, sequence=1, pushed_at=100, revoked=["c1"])
    state = ss.RevocationStatusStateV2(issuer_id=key_id, status_key_epoch=1, status_key_id=key_id)
    return pub, priv, other, key_id, cancelled, lst, push, state


def _empty_cert():
    return pv2.DelegationCertV2(version=0, cert_id="", issuer_id="", issuer_pub_key=HybridPublicKey(b"", b""),
                                subject_id="", subject_pub_key=HybridPublicKey(b"", b""), scope=None,
                                constraints=None, issued_at=0, expires_at=0)


def _empty_bundle():
    return pv2.ProofBundleV2(version=0, verifier_id="", agent_id="", agent_pub_key=HybridPublicKey(b"", b""),
                             delegations=[], delegation_digest=b"", challenge=b"", challenge_at=0,
                             challenge_sig=HybridSignature(b"", b""))


def _empty_list():
    return pv2.RevocationListV2(version=0, issuer_id="", updated_at=0, next_update=0, sequence=0, revoked=None)


def _empty_push():
    return pv2.RevocationPushV2(version=0, issuer_id="", sequence=0, pushed_at=0, revoked=None)


def _empty_rotation():
    return kr.KeyRotationStatementV2(version=0, authority_id="", recovery_epoch=0, role="", sequence=0,
                                     previous_statement_hash=b"", old_key=HybridPublicKey(b"", b""),
                                     new_key=HybridPublicKey(b"", b""), old_key_id="", new_key_id="",
                                     issued_at=0, not_before=0)


def _empty_witness():
    return wv.WitnessEntryV2(version=0, log_id="", sequence=0, prev_hash=b"", entry_data=None, timestamp=0,
                             witness_id="", signature=HybridSignature(b"", b""))


def _empty_transaction():
    return tx.TransactionReceiptV2(version=0, transaction_id="", created_at=0, terms_schema_uri="",
                                   terms_canonical_json=b"", parties=[])


def _calls():
    pub, priv, other, key_id, cancelled, lst, push, state = _fixtures()
    empty_head = vr.ReceiptV2Head(log_id="", verifier_id="")
    return [
        # Decoders and archival verification.
        ("decode_delegation_cert_v2", C.MALFORMED, lambda: pv2.decode_delegation_cert_v2(GARBAGE)),
        ("decode_proof_bundle_v2", C.MALFORMED, lambda: pv2.decode_proof_bundle_v2(GARBAGE)),
        ("decode_revocation_list_v2", C.MALFORMED, lambda: pv2.decode_revocation_list_v2(GARBAGE)),
        ("decode_revocation_push_v2", C.MALFORMED, lambda: pv2.decode_revocation_push_v2(GARBAGE)),
        ("decode_key_rotation_statement_v2", C.MALFORMED, lambda: kr.decode_key_rotation_statement_v2(GARBAGE)),
        ("decode_witness_entry_v2", C.MALFORMED, lambda: wv.decode_witness_entry_v2(GARBAGE)),
        ("decode_transaction_receipt_v2", C.MALFORMED, lambda: tx.decode_transaction_receipt_v2(GARBAGE)),
        ("decode_verification_receipt_v2", C.MALFORMED, lambda: vr.decode_verification_receipt_v2(GARBAGE)),
        ("decode_verification_receipt_body_v2", C.MALFORMED, lambda: vr.decode_verification_receipt_body_v2(GARBAGE)),
        ("decode_v2_checkpoint_acknowledgement", C.MALFORMED, lambda: ack.decode_v2_checkpoint_acknowledgement(GARBAGE)),
        ("decode_v2_status_evidence_batch", C.MALFORMED, lambda: sb.decode_v2_status_evidence_batch(GARBAGE)),
        ("import_security_journal_snapshot_v2", C.MALFORMED,
         lambda: snap.import_security_journal_snapshot_v2(GARBAGE, sj.SecurityJournalHeadV2())),
        ("constraint_v2_from_fields", C.MALFORMED, lambda: cons.constraint_v2_from_fields({"type": "time_window"})),
        ("ConstraintV2.to_canonical_dict", C.MALFORMED,
         lambda: cons.ConstraintV2(type=CONSTRAINT_TIME_WINDOW).to_canonical_dict()),
        ("verify_archival_delegation_cert_v2", C.MALFORMED, lambda: arch.verify_archival_delegation_cert_v2(GARBAGE)),
        ("verify_archival_revocation_list_v2", C.MALFORMED,
         lambda: arch.verify_archival_revocation_list_v2(GARBAGE, key_id, pub)),
        ("verify_archival_revocation_push_v2", C.MALFORMED,
         lambda: arch.verify_archival_revocation_push_v2(GARBAGE, key_id, pub)),
        ("verify_archival_key_rotation_statement_v2", C.MALFORMED,
         lambda: arch.verify_archival_key_rotation_statement_v2(GARBAGE)),
        ("verify_archival_witness_entry_v2", C.MALFORMED, lambda: arch.verify_archival_witness_entry_v2(GARBAGE, pub)),
        ("verify_archival_verification_receipt_v2", C.MALFORMED,
         lambda: arch.verify_archival_verification_receipt_v2(GARBAGE, pub)),
        ("verify_archival_transaction_receipt_v2", C.MALFORMED,
         lambda: arch.verify_archival_transaction_receipt_v2(GARBAGE)),

        # Encoders, digests and identifiers.
        ("key_id_v2_classified", C.MALFORMED, lambda: sig.key_id_v2_classified(BAD_KEY)),
        ("bundle_hash_v2", C.MALFORMED, lambda: pv2.bundle_hash_v2(_empty_bundle())),
        ("encode_delegation_cert_v2", C.MALFORMED, lambda: pv2.encode_delegation_cert_v2(_empty_cert())),
        ("encode_proof_bundle_v2", C.MALFORMED, lambda: pv2.encode_proof_bundle_v2(_empty_bundle())),
        ("encode_revocation_list_v2", C.MALFORMED, lambda: pv2.encode_revocation_list_v2(_empty_list())),
        ("encode_revocation_push_v2", C.MALFORMED, lambda: pv2.encode_revocation_push_v2(_empty_push())),
        ("encode_key_rotation_statement_v2", C.MALFORMED, lambda: kr.encode_key_rotation_statement_v2(_empty_rotation())),
        ("encode_witness_entry_v2", C.MALFORMED, lambda: wv.encode_witness_entry_v2(_empty_witness())),
        ("encode_transaction_receipt_v2", None, lambda: tx.encode_transaction_receipt_v2(_empty_transaction())),
        ("encode_verification_receipt_v2", C.MALFORMED,
         lambda: vr.encode_verification_receipt_v2(vr.VerificationReceiptV2())),
        ("encode_v2_checkpoint_acknowledgement", C.MALFORMED,
         lambda: ack.encode_v2_checkpoint_acknowledgement(ack.V2CheckpointAcknowledgement("", 0, b"", 0))),
        ("encode_v2_status_evidence_batch", C.MALFORMED,
         lambda: sb.encode_v2_status_evidence_batch(sb.V2StatusEvidenceBatch([sb.V2StatusEvidenceObject(9, b"")]))),
        ("verification_receipt_v2_body", C.MALFORMED,
         lambda: vr.verification_receipt_v2_body(vr.VerificationReceiptV2())),
        ("verification_receipt_v2_digest", C.MALFORMED,
         lambda: vr.verification_receipt_v2_digest(vr.VerificationReceiptV2())),
        ("witness_entry_v2_digest", C.MALFORMED, lambda: wv.witness_entry_v2_digest(_empty_witness())),
        ("key_rotation_statement_v2_digest", C.MALFORMED,
         lambda: kr.key_rotation_statement_v2_digest(_empty_rotation())),
        ("transaction_receipt_v2_sign_bytes", C.MALFORMED,
         lambda: tx.transaction_receipt_v2_sign_bytes(_empty_transaction())),
        ("statement_body_digest_v2 unregistered code", C.UNSUPPORTED_OBJECT_TYPE,
         lambda: wv.statement_body_digest_v2(0x0001, b"{}")),
        ("statement_body_digest_v2 bad body", C.MALFORMED, lambda: wv.statement_body_digest_v2(0x0006, b"{}")),
        ("status_evidence_digest unregistered code", C.UNSUPPORTED_OBJECT_TYPE,
         lambda: pv2.status_evidence_digest(0x0001, lst)),
        ("status_evidence_digest wrong value", C.MALFORMED, lambda: pv2.status_evidence_digest(0x0003, push)),
        ("challenge_claim_digest_v2", C.MALFORMED, lambda: cc.challenge_claim_digest_v2(b"short")),
        ("protocol_claim_id_v2 namespace", C.CONFIGURATION_INVALID, lambda: cc.protocol_claim_id_v2("", 0, bytes(32))),
        ("protocol_claim_id_v2 challenge", C.MALFORMED, lambda: cc.protocol_claim_id_v2("ns", 0, b"short")),
        ("protocol_claim_id_from_digest_v2", C.MALFORMED,
         lambda: cc.protocol_claim_id_from_digest_v2("ns", 0, b"short")),
        ("decode_payload_digest", C.MALFORMED, lambda: oc.decode_payload_digest("!")),
        ("operation_context_v2_bytes", None, lambda: oc.operation_context_v2_bytes("")),
        ("session_context_v2_bytes", C.CONFIGURATION_INVALID,
         lambda: oc.session_context_v2_bytes("", "", "", "", "", b"")),
        ("build_v2_rate_reservation_batch", C.MALFORMED,
         lambda: rr.build_v2_rate_reservation_batch([cp.V2DeferredConstraint(0, 0, "", "", CONSTRAINT_MAX_RATE, GARBAGE)])),

        # Signing.
        ("new_local_signer_v2", C.CONFIGURATION_INVALID, lambda: sig.new_local_signer_v2(HybridPrivateKey(b"", b""))),
        ("sign_delegation_cert_v2", C.MALFORMED, lambda: pv2.sign_delegation_cert_v2(_empty_cert(), priv)),
        ("sign_delegation_cert_v2_with_signer failing signer", None,
         lambda: pv2.sign_delegation_cert_v2_with_signer(CTX, _empty_cert(), FailingSigner(pub))),
        ("sign_proof_bundle_v2", C.MALFORMED, lambda: pv2.sign_proof_bundle_v2(_empty_bundle(), priv)),
        ("sign_revocation_list_v2 issuer binding", C.STATUS_KEY_BINDING_MISMATCH,
         lambda: pv2.sign_revocation_list_v2(lst, "other", pub, priv)),
        ("sign_revocation_list_v2 status key binding", C.STATUS_KEY_BINDING_MISMATCH,
         lambda: pv2.sign_revocation_list_v2(lst, key_id, other, priv)),
        ("sign_revocation_list_v2_with_signer failing signer", C.CONFIGURATION_INVALID,
         lambda: pv2.sign_revocation_list_v2_with_signer(CTX, lst, key_id, pub, FailingSigner(pub))),
        ("sign_revocation_list_v2_with_signer cancelled", C.EVALUATION_CANCELLED,
         lambda: pv2.sign_revocation_list_v2_with_signer(cancelled, lst, key_id, pub, FailingSigner(pub))),
        ("sign_revocation_push_v2 issuer binding", C.STATUS_KEY_BINDING_MISMATCH,
         lambda: pv2.sign_revocation_push_v2(push, "other", pub, priv)),
        ("sign_key_rotation_statement_v2", C.MALFORMED,
         lambda: kr.sign_key_rotation_statement_v2(_empty_rotation(), priv, priv)),
        ("sign_witness_entry_v2", C.MALFORMED, lambda: wv.sign_witness_entry_v2(_empty_witness(), priv)),
        ("sign_verification_receipt_v2", C.MALFORMED,
         lambda: vr.sign_verification_receipt_v2(vr.VerificationReceiptV2(), priv)),
        ("sign_prepared_verification_receipt_v2", C.CONFIGURATION_INVALID,
         lambda: vr.sign_prepared_verification_receipt_v2(GARBAGE, empty_head, priv)),
        ("bind_verification_receipt_body_v2", C.CONFIGURATION_INVALID,
         lambda: vr.bind_verification_receipt_body_v2(GARBAGE, empty_head)),
        ("sign_transaction_receipt_party_v2", None,
         lambda: tx.sign_transaction_receipt_party_v2(_empty_transaction(), "p", priv)),

        # Signature and object verification.
        ("verify_delegation_cert_v2_signature", C.MALFORMED,
         lambda: pv2.verify_delegation_cert_v2_signature(_empty_cert())),
        ("verify_proof_bundle_v2_signatures", C.MALFORMED,
         lambda: pv2.verify_proof_bundle_v2_signatures(_empty_bundle())),
        ("verify_revocation_list_v2_signature", C.MALFORMED,
         lambda: pv2.verify_revocation_list_v2_signature(_empty_list(), key_id, pub)),
        ("verify_revocation_push_v2_signature", C.STATUS_KEY_BINDING_MISMATCH,
         lambda: pv2.verify_revocation_push_v2_signature(push, "other", pub)),
        ("verify_key_rotation_statement_v2", None,
         lambda: kr.verify_key_rotation_statement_v2(
             _empty_rotation(), kr.KeyRotationV2State("", 0, "", 0, b"", HybridPublicKey(b"", b""), []), 0, 0)),
        ("verify_witness_entry_v2", C.MALFORMED,
         lambda: wv.verify_witness_entry_v2(_empty_witness(), wv.WitnessV2Head(log_id=""), pub)),
        ("verify_verification_receipt_v2", C.MALFORMED,
         lambda: vr.verify_verification_receipt_v2(vr.VerificationReceiptV2(), pub, empty_head)),
        ("verify_transaction_receipt_v2_signatures", None,
         lambda: tx.verify_transaction_receipt_v2_signatures(_empty_transaction())),
        ("check_verification_receipt_v2_bundle_binding", None,
         lambda: vr.check_verification_receipt_v2_bundle_binding(vr.VerificationReceiptV2(), _empty_bundle())),

        # Key rotation journal.
        ("new_key_rotation_v2_journal", None, lambda: kr.new_key_rotation_v2_journal("", -1, "", BAD_KEY)),
        ("accept_key_rotation_statement_v2", None,
         lambda: kr.accept_key_rotation_statement_v2(
             _empty_rotation(),
             kr.KeyRotationV2Journal(kr.KeyRotationV2State("", 0, "", 0, b"", HybridPublicKey(b"", b""), [])), 0, 0)),
        ("recover_key_rotation_v2", None,
         lambda: kr.recover_key_rotation_v2(
             kr.KeyRotationV2Journal(kr.KeyRotationV2State("", 0, "", 0, b"", HybridPublicKey(b"", b""), [])), 0,
             BAD_KEY)),

        # Status reducer and SecurityJournalV2 operations (§5.4, §6.6).
        ("transition_revocation_status_epoch_v2", C.STATUS_OBJECT_REJECTED,
         lambda: ss.transition_revocation_status_epoch_v2(state, key_id, 3, other)),
        ("transition_revocation_status_epoch_v2 reused key", C.STATUS_OBJECT_REJECTED,
         lambda: ss.transition_revocation_status_epoch_v2(state, key_id, 2, pub)),
        ("apply_revocation_list_v2 unsigned", C.INVALID_SIGNATURE,
         lambda: ss.apply_revocation_list_v2(state, lst, key_id, 1, pub, POLICY, 150)),
        ("apply_revocation_push_v2 unsigned", C.INVALID_SIGNATURE,
         lambda: ss.apply_revocation_push_v2(state, push, key_id, 1, pub, POLICY, 150)),
        ("revocation_status_for_cert_v2", None,
         lambda: ss.revocation_status_for_cert_v2(state, key_id, "", 1, pub, POLICY, 150)),
        ("record_security_key_role_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.record_security_key_role_v2(CTX, FailingJournalStore(), "verifier", pub)),
        ("record_security_key_role_v2 status role", C.STATUS_OBJECT_REJECTED,
         lambda: sj.record_security_key_role_v2(CTX, None, "status", pub)),
        ("configure_status_key_epoch_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.configure_status_key_epoch_v2(CTX, FailingJournalStore(), key_id, 1, pub)),
        ("apply_revocation_list_to_journal_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.apply_revocation_list_to_journal_v2(CTX, FailingJournalStore(), lst, key_id, 1, pub, POLICY, 150)),
        ("apply_revocation_push_to_journal_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.apply_revocation_push_to_journal_v2(CTX, None, push, key_id, 1, pub, POLICY, 150)),
        ("revocation_status_from_journal_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.revocation_status_from_journal_v2(CTX, FailingJournalStore(), key_id, "c1", 1, pub, POLICY, 150)),
        ("register_key_role_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.register_key_role_v2(sj.empty_security_journal_v2(), "nonsense", pub)),
        ("register_status_key_epoch_v2", C.STATUS_OBJECT_REJECTED,
         lambda: sj.register_status_key_epoch_v2(sj.empty_security_journal_v2(), key_id, 0, pub)),
        ("validate_security_journal_v2", C.MALFORMED, lambda: sj.validate_security_journal_v2(sj.SecurityJournalV2())),
        ("validate_security_journal_transition_v2", None,
         lambda: sj.validate_security_journal_transition_v2(sj.empty_security_journal_v2(), sj.SecurityJournalV2())),
        ("export_security_journal_snapshot_v2", C.CONFIGURATION_INVALID,
         lambda: snap.export_security_journal_snapshot_v2(sj.SecurityJournalV2())),
        ("migrate_security_journal_v2", C.CONFIGURATION_INVALID,
         lambda: snap.migrate_security_journal_v2(sj.SecurityJournalV2())),
        ("new_v2_status_publisher", C.CONFIGURATION_INVALID, lambda: sp.new_v2_status_publisher(CTX, None, pub, None, 0)),
        ("V2StatusPublisher.heartbeat", C.CONFIGURATION_INVALID,
         lambda: sp.V2StatusPublisher.heartbeat(_zero_publisher(), CTX, sp.V2StatusPublisherState(), 1)),
        ("V2StatusPublisher.revoke", C.CONFIGURATION_INVALID,
         lambda: sp.V2StatusPublisher.revoke(_zero_publisher(), CTX, sp.V2StatusPublisherState(), None, 1)),
        ("V2StatusPublisher.genesis", C.CONFIGURATION_INVALID,
         lambda: sp.V2StatusPublisher.genesis(_zero_publisher(), CTX, -1)),

        # Verifier configuration, preflight, claim and evaluation (§6, §7).
        ("new_v2_context_policy", C.CONFIGURATION_INVALID, lambda: cp.new_v2_context_policy("", True, None, None)),
        ("new_constraint_evaluator_registry_v2", C.CONFIGURATION_INVALID,
         lambda: ce.new_constraint_evaluator_registry_v2(-1.0)),
        ("constraint_profile_digest_v2", C.CONFIGURATION_INVALID,
         lambda: ce.constraint_profile_digest_v2(ce.ConstraintProfileDescriptorV2("", ""))),
        ("evaluate_receiver_audience_v2", C.CONFIGURATION_INVALID,
         lambda: evaluate_receiver_audience_v2(None, "", None, -1, 0)),
        ("preflight_proof_bundle_v2", None,
         lambda: pre.preflight_proof_bundle_v2(_empty_bundle(), None, None, "data:read", "ns", 0, 0, 0, 0)),
        ("validate_proof_bundle_v2_preflight", None,
         lambda: pre.validate_proof_bundle_v2_preflight(_empty_bundle(), pre.ExpectedChallengeV2(), "data:read", "ns",
                                                        0, 0, 0, 0)),
        ("claim_proof_bundle_v2", C.CONFIGURATION_INVALID,
         lambda: cs.claim_proof_bundle_v2(CTX, None, _empty_bundle(), None, "ns", 0, 0)),
        ("finalize_claim_proof_bundle_v2", C.CONFIGURATION_INVALID,
         lambda: cs.finalize_claim_proof_bundle_v2(CTX, None, None, None, None)),
        ("resolve_claim_proof_bundle_v2_after_audience", C.CONFIGURATION_INVALID,
         lambda: resolve_claim_proof_bundle_v2_after_audience(None, None)),
        ("resolve_claim_proof_bundle_v2_after_rate", C.CONFIGURATION_INVALID,
         lambda: resolve_claim_proof_bundle_v2_after_rate(CTX, None, None)),
        ("validate_v2_evaluation_progress", C.MALFORMED,
         lambda: ep.validate_v2_evaluation_progress(_zero_progress())),
        ("v2_evaluation_interrupted_result", C.CONFIGURATION_INVALID,
         lambda: ep.v2_evaluation_interrupted_result(cs.V2ChallengeClaim(), -1, ep.V2EvaluationProgress())),
        ("recover_interrupted_claim_v2", C.CONFIGURATION_INVALID, lambda: ep.recover_interrupted_claim_v2(CTX, None, "")),
        ("issue_challenge_v2", C.CONFIGURATION_INVALID,
         lambda: ci.V2ChallengeIssuer().issue_challenge_v2(CTX, ci.V2ChallengeIssueRequest())),
        ("load_expected_challenge_v2", C.CONFIGURATION_INVALID,
         lambda: ci.load_expected_challenge_v2(CTX, None, "ns", 0, None)),
        ("check_v2_stream_sequence", C.STREAM_SEQUENCE_MISMATCH, lambda: seq.check_v2_stream_sequence(True, 5, 5)),
        ("V2ReleasedDecision.receipt", C.CONFIGURATION_INVALID, lambda: rel.V2ReleasedDecision.receipt(_zero_released())),
        ("verify_transaction_receipt_v2", C.CONFIGURATION_INVALID,
         lambda: tv.verify_transaction_receipt_v2(CTX, tv.TransactionVerifyRequestV2(now=-1),
                                                  tv.TransactionVerifySourcesV2())),
    ]


def _zero_progress():
    """Go's zero ``V2EvaluationProgress{}``: every assessment empty. The
    Python default is the valid initial progress."""
    return ep.V2EvaluationProgress(trust_assessment="", status_assessment="", context_assessment="")


def _zero_publisher():
    """A publisher value that no constructor produced (Go ``&V2StatusPublisher{}``)."""
    return object.__new__(sp.V2StatusPublisher)


def _zero_released():
    """A released decision that no release produced (Go ``&V2ReleasedDecision{}``)."""
    return object.__new__(rel.V2ReleasedDecision)


CALLS = _calls() if _native.AVAILABLE else []


def test_call_list_matches_the_reference():
    # Go TestV2PublicAPIErrorsAreClassified calls 116 entry points and the
    # live verifier (below).
    assert len(CALLS) == 116
    assert len({name for name, _, _ in CALLS}) == len(CALLS)


@pytest.mark.parametrize("name,want,run", CALLS, ids=[c[0] for c in CALLS])
def test_public_api_error_is_classified(name, want, run):
    with pytest.raises(Exception) as info:
        run()
    got = error_class_of(info.value)
    assert got in ALL_ERROR_CLASSES, f"{name}: class {got!r} is not in the SPEC-v2 §2.7 list: {info.value!r}"
    if want is not None:
        assert got == want, f"{name}: class {got!r}, want {want!r}: {info.value!r}"


def test_live_verifier_without_claim_store_is_configuration_invalid():
    outcome = verify_v2.verify_proof_bundle_v2(CTX, verify_v2.V2VerifyRequest(bundle=GARBAGE), verify_v2.V2VerifyCallbacks())
    assert outcome.stage == "preflight"
    assert outcome.error_class == C.CONFIGURATION_INVALID
