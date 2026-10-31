"""Protocol v2 evaluation progress and lease-expiry recovery (mirrors Go
evaluation_progress_v2.go, SPEC-v2 §6.7, §7.5)."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Optional

from . import context_v2
from ._v2json import canonical
from .challenge_claim_v2 import protocol_claim_id_from_digest_v2
from .clock_bounds_v2 import V2_MAX_TIMESTAMP_SECONDS, valid_v2_timestamp
from .errors_v2 import V2Error, V2ErrorClass, classify, error_class_of, classified
from .types_v2 import StatusEvidenceEntryV2, clone_constraint_evaluator_refs_v2, is_int, valid_prefixed_digest_v2
from .verification_receipt_v2 import (
    VerificationReceiptV2,
    decode_verification_receipt_body_v2,
    verification_receipt_v2_body,
)


@dataclass
class V2EvaluationProgress:
    """Per-dimension progress of one claimed evaluation. Its canonical JSON
    form is {"context_assessment","context_policy_digest","status_assessment",
    "status_evidence_digests","trust_assessment"}."""

    trust_assessment: str = "not_evaluated"
    status_assessment: str = "not_evaluated"
    context_assessment: str = "not_evaluated"
    context_policy_digest: Optional[str] = None
    status_evidence: Optional[list] = field(default_factory=list)

    def to_canonical_dict(self) -> dict:
        return {
            "context_assessment": self.context_assessment,
            "context_policy_digest": self.context_policy_digest,
            "status_assessment": self.status_assessment,
            "status_evidence_digests": None if self.status_evidence is None else [e.to_canonical_dict() for e in self.status_evidence],
            "trust_assessment": self.trust_assessment,
        }


@dataclass
class V2InterruptedClaim:
    """What a claim store returns to lease-expiry recovery."""

    claim: object = None  # claim_store_v2.V2ChallengeClaim
    claimed_at: int = 0
    progress: V2EvaluationProgress = field(default_factory=V2EvaluationProgress)


def initial_v2_evaluation_progress() -> V2EvaluationProgress:
    """Go ``InitialV2EvaluationProgress``."""
    return V2EvaluationProgress(trust_assessment="not_evaluated", status_assessment="not_evaluated",
                                context_assessment="not_evaluated", context_policy_digest=None, status_evidence=[])


def clone_v2_evaluation_progress(p: V2EvaluationProgress) -> V2EvaluationProgress:
    """Go ``cloneV2EvaluationProgress``: a nil evidence list becomes empty."""
    return V2EvaluationProgress(trust_assessment=p.trust_assessment, status_assessment=p.status_assessment,
                                context_assessment=p.context_assessment, context_policy_digest=p.context_policy_digest,
                                status_evidence=list(p.status_evidence or []))


@classified(V2ErrorClass.MALFORMED)
def validate_v2_evaluation_progress(p: V2EvaluationProgress) -> None:
    """Go ``ValidateV2EvaluationProgress`` (raises ValueError)."""
    if not isinstance(p, V2EvaluationProgress):
        raise ValueError("v2 evaluation progress has the wrong type")
    if p.trust_assessment not in ("not_evaluated", "unavailable", "trusted", "untrusted"):
        raise ValueError("v2 evaluation progress trust_assessment is invalid")
    if p.status_assessment not in ("not_evaluated", "unavailable", "current", "revoked", "stale"):
        raise ValueError("v2 evaluation progress status_assessment is invalid")
    if p.context_assessment not in ("not_evaluated", "bound", "not_required"):
        raise ValueError("v2 evaluation progress context_assessment is invalid")
    if (p.context_assessment == "not_evaluated") != (p.context_policy_digest is None) or (
            p.context_policy_digest is not None and not valid_prefixed_digest_v2(p.context_policy_digest)):
        raise ValueError("v2 evaluation progress context_policy_digest does not match context_assessment")
    if p.trust_assessment != "trusted" and (p.status_assessment != "not_evaluated" or p.context_assessment != "not_evaluated"):
        raise ValueError("v2 evaluation progress records status or context without a trusted root")
    if p.status_evidence is None or (p.status_assessment == "not_evaluated" and len(p.status_evidence) != 0):
        raise ValueError("v2 evaluation progress status evidence is inconsistent with status_assessment")
    if not all(isinstance(e, StatusEvidenceEntryV2) for e in p.status_evidence):
        raise ValueError("v2 evaluation progress status evidence has the wrong type")


_INTERRUPTED_TERMINAL = {"decision": "indeterminate", "decision_reason": "evaluation_interrupted",
                         "identity_status": "authorization_unverified"}


@classified(V2ErrorClass.MALFORMED)
def v2_evaluation_interrupted_result(claim, verified_at: int, progress: V2EvaluationProgress) -> tuple[bytes, bytes]:
    """Go ``V2EvaluationInterruptedResult``: the canonical terminal result and
    receipt outbox body for indeterminate/evaluation_interrupted."""
    if not valid_v2_timestamp(verified_at):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 recovery time is outside the timestamp domain")
    try:
        validate_v2_evaluation_progress(progress)
    except ValueError as exc:
        raise V2Error(V2ErrorClass.MALFORMED, str(exc)) from exc
    issuers = sorted(set(claim.issuer_ids or []), key=lambda s: s.encode("utf-8"))
    progress = clone_v2_evaluation_progress(progress)
    receipt = VerificationReceiptV2(
        version=2, verifier_id=claim.verifier_id, agent_id=claim.agent_id, bundle_hash=claim.bundle_hash,
        issuer_ids=issuers, decision="indeterminate", decision_reason="evaluation_interrupted",
        identity_status="authorization_unverified", trust_assessment=progress.trust_assessment,
        status_assessment=progress.status_assessment, challenge_assessment="current",
        context_assessment=progress.context_assessment, context_policy_digest=progress.context_policy_digest,
        verified_at=verified_at, required_scope=claim.required_scope, granted_scope=[],
        status_evidence=progress.status_evidence,
        constraint_evaluators=clone_constraint_evaluator_refs_v2(claim.constraint_evaluators),
    )
    try:
        body = verification_receipt_v2_body(receipt)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    return canonical(_INTERRUPTED_TERMINAL), body


@classified(V2ErrorClass.CLAIM_STORE_UNAVAILABLE)
def recover_interrupted_claim_v2(ctx: context_v2.Context, store, claim_id: str):
    """Go ``RecoverInterruptedClaimV2``: lease-expiry recovery. Returns the
    committed (non-actionable) outcome; an identical repeat returns the same."""
    from .release_v2 import _new_committed_v2_outcome

    if not isinstance(ctx, context_v2.Context) or store is None or not isinstance(claim_id, str) or claim_id == "":
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 recovery requires a context, claim store and claim ID")

    def classify_store(exc: BaseException) -> BaseException:
        if error_class_of(exc) == V2ErrorClass.UNCLASSIFIED:
            return classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, exc)
        return exc

    try:
        interrupted = store.load_v2_interrupted_claim(ctx, claim_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - a store failure or panic is unavailability
        raise classify_store(exc) from exc
    if not isinstance(interrupted, V2InterruptedClaim) or getattr(interrupted.claim, "claim_id", None) != claim_id:
        raise V2Error(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, "v2 claim store returned a different claim for recovery")
    terminal, body = v2_evaluation_interrupted_result(interrupted.claim, interrupted.claimed_at, interrupted.progress)
    try:
        store.recover_interrupted_v2_claim(ctx, claim_id, terminal, body)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001
        raise classify_store(exc) from exc
    return _new_committed_v2_outcome(interrupted.claim, body, 0)


@dataclass
class V2CommittedClaim:
    """A terminal claim as the claim store's terminal compare-and-set
    persisted it: the sealed claim values, the terminal result, the sealed
    receipt outbox body, and the allow horizon (0 unless the result is an
    allow)."""

    claim: object = None  # claim_store_v2.V2ChallengeClaim
    terminal_result: bytes = b""
    receipt_body: bytes = b""
    allow_horizon: int = 0


class V2CommittedClaimStore(abc.ABC):
    """Loads a terminal claim's persisted record for resumption (Go
    ``V2CommittedClaimStore``, SPEC-v2 §7.11). ``load_v2_committed_claim``
    answers ``claim_not_found`` for a claim the store does not hold,
    ``claim_lease_live`` for a claim still evaluating under a live lease, and
    ``claim_lease_lost`` for a claim still evaluating after its lease expired
    (lease-expiry recovery runs first)."""

    @abc.abstractmethod
    def load_v2_committed_claim(self, ctx: context_v2.Context, claim_id: str) -> V2CommittedClaim:
        ...


@classified(V2ErrorClass.CLAIM_STORE_UNAVAILABLE)
def resume_committed_claim_v2(ctx: context_v2.Context, store, claim_id: str):
    """Go ``ResumeCommittedClaimV2``: return the handoff of a claim's committed
    result from the claim store's persisted record (SPEC-v2 §7.11), for a
    service whose handoff was lost after the terminal commit, for example by a
    crash before the verifier returned. It checks the record as the terminal
    compare-and-set does and never builds or replaces a result; a record that
    fails a check is ``claim_store_unavailable``. Publication, checkpoint
    submission and release then proceed as for a returned handoff."""
    from .release_v2 import _new_committed_v2_outcome

    if not isinstance(ctx, context_v2.Context) or store is None or not isinstance(claim_id, str) or claim_id == "":
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 resumption requires a context, claim store and claim ID")
    try:
        committed = store.load_v2_committed_claim(ctx, claim_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - a store failure or panic is unavailability
        if error_class_of(exc) == V2ErrorClass.UNCLASSIFIED:
            raise classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, exc) from exc
        raise
    try:
        _validate_v2_committed_claim(committed, claim_id)
    except Exception as exc:  # noqa: BLE001 - any failed check is the store's failure
        raise V2Error(V2ErrorClass.CLAIM_STORE_UNAVAILABLE,
                      f"v2 claim store returned a committed record that fails its checks: {exc}") from exc
    return _new_committed_v2_outcome(committed.claim, committed.receipt_body, committed.allow_horizon)


def _validate_v2_committed_claim(committed, claim_id: str) -> None:
    """Go ``validateV2CommittedClaim``: apply the terminal compare-and-set's
    checks to a persisted record: the claim ID (§7.3), the finalization
    payload (§7.5), and the allow horizon (§6.8)."""
    from .claim_store_v2 import V2ChallengeClaim, validate_v2_finalization_payload

    if not isinstance(committed, V2CommittedClaim) or not isinstance(committed.claim, V2ChallengeClaim):
        raise ValueError("the record has the wrong type")
    claim = committed.claim
    if claim.claim_id != claim_id:
        raise ValueError("the record is for a different claim")
    if not valid_prefixed_digest_v2(claim.challenge_digest):
        raise ValueError("the challenge digest is not a sha384 digest")
    digest = bytes.fromhex(claim.challenge_digest[len("sha384:"):])
    try:
        derived = protocol_claim_id_from_digest_v2(claim.namespace, claim.replay_epoch, digest)
    except Exception:  # noqa: BLE001
        derived = None
    if derived != claim.claim_id:
        raise ValueError("the claim ID does not derive from the claim's replay key")
    validate_v2_finalization_payload(claim, committed.terminal_result, committed.receipt_body)
    body = decode_verification_receipt_body_v2(bytes(committed.receipt_body))
    horizon = committed.allow_horizon
    if not is_int(horizon):
        raise ValueError("the allow horizon is not an integer")
    if body.decision == "allow":
        if horizon <= 0 or horizon > V2_MAX_TIMESTAMP_SECONDS:
            raise ValueError("an allow has no allow horizon in the timestamp domain")
    elif horizon != 0:
        raise ValueError("a result that is not an allow has an allow horizon")


def _record_v2_progress_safely(ctx: context_v2.Context, store, token, progress: V2EvaluationProgress) -> None:
    """Go ``recordV2ProgressSafely``: any failure stops the evaluation."""
    from .claim_store_v2 import _token_state

    state = _token_state(token)
    try:
        validate_v2_evaluation_progress(progress)
    except ValueError as exc:
        raise exc
    try:
        store.record_v2_evaluation_progress(ctx, state.claim_id, bytes(state.owner_token), clone_v2_evaluation_progress(progress))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001
        if error_class_of(exc) == V2ErrorClass.UNCLASSIFIED:
            raise classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, exc) from exc
        raise
