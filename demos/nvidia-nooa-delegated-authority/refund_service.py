# SPDX-License-Identifier: Apache-2.0
"""The receiving service, where the authorization decision is made.

This process is operated by a different party from the agent. It holds the
principal's root public key and the principal's status key as configured
trust, and nothing else. Everything arriving over the wire is input to be
parsed, never a fact to be believed: the amount, the order, the operation, and
any opinion the agent has about whether it is allowed.

Protocol v2. The decision path is the v2 one end to end:

1. phase 1 issues a challenge with the SDK's issuance helper, which persists
   the expected-challenge record *before* the challenge is returned;
2. phase 2 runs ``verify_proof_bundle_v2``: a pre-claim preflight (challenge,
   freshness, expected agent, session binding, proof of possession), an atomic
   claim, trust, signed status, scope and constraints, then a committed result;
3. the committed result is published as a signed verification receipt to the
   receipt log, acknowledged by the checkpoint, and released;
4. money moves only when the released decision says ``allowed`` at the
   receiver's own authoritative time.

DEVELOPMENT ONLY. The claim store, receipt log, checkpoint, journal and
challenge issuance store are the SDK's in-memory reference stores
(``ratify_protocol_v2.v2reference``). They are not durable, do not survive a
restart, and do not span processes. A production receiver supplies durable
Part B stores and an *independent* checkpoint (SPEC-v2 §7).

Transport is the Python standard library. A protocol reference should not
require a web framework to be understood.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ratify_protocol_v2 import background, key_id_v2
from ratify_protocol_v2.challenge_issuance_v2 import (
    V2ChallengeIssuer,
    V2ChallengeIssueRequest,
    load_expected_challenge_v2,
)
from ratify_protocol_v2.constraints_v2 import TZDB_VERSION_V2, ConstraintContextV2
from ratify_protocol_v2.context_policy_v2 import (
    VERIFY_SESSION_CONTEXT_FIELDS_V2,
    new_v2_context_policy,
)
from ratify_protocol_v2.operation_context_v2 import (
    operation_context_v2_hash,
    session_context_v2_hash,
)
from ratify_protocol_v2.protocol_v2 import decode_public_key
from ratify_protocol_v2.release_v2 import (
    V2_RELEASE_RELEASED,
    V2ReleaseConfig,
    release_v2_decision,
)
from ratify_protocol_v2.scope import SCOPE_PAYMENTS_SEND
from ratify_protocol_v2.security_journal_v2 import (
    configure_status_key_epoch_v2,
    record_security_key_role_v2,
)
from ratify_protocol_v2.signing_v2 import equal_public_keys, generate_keypair_v2
from ratify_protocol_v2.status_batch_v2 import V2StatusEvidenceBatch, V2StatusEvidenceObject
from ratify_protocol_v2.status_provenance_v2 import V2StatusKeyConfig
from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol_v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol_v2.v2reference.journal import new_journal_store
from ratify_protocol_v2.v2reference.store import Store
from ratify_protocol_v2.verification_receipt_v2 import decode_verification_receipt_v2
from ratify_protocol_v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2_STAGE_PREFLIGHT,
    V2_STAGE_REPLAY,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)

#: The scope a refund requires. Chosen by the *service*, never by the caller.
REQUIRED_SCOPE = SCOPE_PAYMENTS_SEND
OPERATION = "refund.issue"
CHALLENGE_TTL_SECONDS = 60
#: v2 session contexts name the workspace by a canonical lowercase UUID.
WORKSPACE_ID = "77e92cdc-26c1-539b-a5c2-170662d3616c"
#: The only currency this reference settles in.
SETTLEMENT_CURRENCY = "USD"
#: The tenant this deployment serves. Real deployments derive this from the
#: authenticated caller, never from the request body.
DEFAULT_TENANT = "acme"
#: One micro-unit is 10^-6 of the major unit: 100.00 USD is 100_000_000.
MICROS_PER_UNIT = 1_000_000

#: Replay domain. A claim is unique per (namespace, epoch, challenge digest).
VERIFIER_NAMESPACE = "nvidia-nooa-refund"
REPLAY_EPOCH = 1
#: The receipt log this receiver publishes to (32 hex characters).
LOG_ID = "6e7669646961726566756e646c6f6731"
#: Evaluator lease on a claim, in seconds.
CLAIM_LEASE_SECONDS = 30
#: The receiver's context policy: every proof must carry exactly the session
#: context this receiver derived at phase 1.
CONTEXT_POLICY_PROFILE = "reference.nvidia-nooa-refund/v1"
#: How fresh signed status must be. A principal that stops publishing makes its
#: delegations fail closed as status_stale.
STATUS_POLICY = RevocationStatusPolicyV2(
    max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5
)


class BadRequest(ValueError):
    """A business input the service refuses to reason about. Maps to 400.

    Every BadRequest is reported with ``error_class: malformed``: the input was
    refused before a challenge was issued or a proof was evaluated."""


#: Order identifiers this service will accept, before canonicalization.
_ORDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_resource_id(tenant: str, order_id: str) -> str:
    """Build the one canonical name for an order, tenant-qualified.

    Two tenants can each have an "8841". A bare order number is therefore
    ambiguous across tenants, and a delegation naming one would authorize the
    other's order of the same number. Qualifying by tenant removes that.

    This function is the whole canonicalization contract. ``resource_id`` is
    an opaque UTF-8 string compared by **exact byte equality** (SPEC-v2
    ``resource_path``): the verifier performs no case folding,
    percent-decoding, or normalization of any kind. An application that
    accepts two spellings of the same resource has two different resources as
    far as verification is concerned. So the receiver pins one spelling here,
    rejects anything that does not fit it, and uses the result for both the
    session binding and the constraint.
    """
    if not isinstance(tenant, str) or not _TENANT_RE.match(tenant):
        raise BadRequest("tenant must be lowercase alphanumeric with hyphens")
    if not isinstance(order_id, str) or not _ORDER_ID_RE.match(order_id):
        raise BadRequest(
            "order_id must be 1-64 chars of [A-Za-z0-9._-] and start alphanumeric"
        )
    return f"tenant/{tenant}/orders/{order_id}"


#: Nothing here should ever be refunded in one call; a ceiling this far above
#: any plausible delegation keeps a fat-fingered request from becoming a
#: denial-of-service on the constraint evaluator. 10^9 USD in micro-units,
#: well inside the v2 integer domain (2^53 - 1).
MAX_PLAUSIBLE_AMOUNT_MICROS = 1_000_000_000 * MICROS_PER_UNIT


def _validate_amount(amount_micros: object, currency: object) -> int:
    """Accept only a positive integer number of micro-units.

    Protocol v1 carried amounts as floats, and a NaN amount cleared every
    ceiling because every ordered comparison against NaN is false. Protocol v2
    removes floats from the wire entirely: ``max_amount_micros`` and
    ``requested_amount_micros`` are integers. This receiver holds its own
    business input to the same rule, so a fractional, non-finite, boolean, or
    string amount is malformed and never reaches a challenge.
    """
    if isinstance(amount_micros, bool) or not isinstance(amount_micros, int):
        raise BadRequest("amount_micros must be an integer number of micro-units")
    if amount_micros <= 0:
        # Zero is rejected deliberately: a zero refund is not a meaningful
        # authorization decision, and permitting it invites callers to probe
        # verification outcomes at no cost. A negative refund is a charge.
        raise BadRequest("amount_micros must be greater than zero")
    if amount_micros > MAX_PLAUSIBLE_AMOUNT_MICROS:
        raise BadRequest("amount_micros exceeds the maximum this service will consider")
    # This reference settles in USD only. A constraint is denominated, and
    # comparing a EUR request against a USD ceiling is not a conversion the
    # verifier should silently perform.
    if currency != SETTLEMENT_CURRENCY:
        raise BadRequest(f"currency must be {SETTLEMENT_CURRENCY}")
    return amount_micros


def encode_public_key(pub) -> dict:
    """A hybrid public key as JSON: both halves, base64."""
    return {
        "ed25519": base64.b64encode(bytes(pub.ed25519)).decode("ascii"),
        "ml_dsa_65": base64.b64encode(bytes(pub.ml_dsa_65)).decode("ascii"),
    }


def parse_agent(agent_id: object, agent_public_key: object):
    """The agent a challenge is issued to: a key ID and the complete key.

    v2 issuance binds the challenge to both, and the receiver checks that the
    ID is the one derived from the key. A key ID alone is never a pin."""
    if not isinstance(agent_id, str) or not _KEY_ID_RE.match(agent_id):
        raise BadRequest("agent_id must be a 64-hex v2 key ID")
    try:
        pub = decode_public_key(agent_public_key, "agent_public_key")
        derived = key_id_v2(pub)
    except Exception as exc:  # noqa: BLE001 - any decode failure is malformed input
        raise BadRequest(f"agent_public_key is not a hybrid public key: {exc}") from exc
    if derived != agent_id:
        raise BadRequest("agent_id is not the key ID of agent_public_key")
    return pub


@dataclass
class _Pending:
    """What the receiver decided this request *is*, recorded at phase 1.

    Phase 2 reads its trusted inputs from here and from the SDK's issuance
    record, never from the request body, which is what makes request
    substitution a cryptographic failure rather than a matter of discipline.
    """

    resource_id: str
    amount_micros: int
    currency: str
    required_scope: str
    agent_id: str
    session_context: bytes
    expires_at: int


class StatusFeed:
    """The transport that carries the principal's signed status to us.

    Untrusted by design: it hands over signed objects, and the verifier checks
    each signature against the status key this receiver configured before
    applying it to the journal. A feed that fails is not "not revoked"; the
    decision fails closed as ``status_unavailable``.
    """

    def __init__(self, source) -> None:
        #: Anything with ``published() -> [(object_type, wire), ...]``.
        self.source = source
        self.error: str | None = None

    def fetch(self) -> list[tuple[int, bytes]]:
        if self.error is not None:
            raise ConnectionError(self.error)
        return self.source.published()


class RefundService:
    """Verifies delegated authority, then moves money, in that order."""

    def __init__(self, trust_root, status_key, status_source) -> None:
        self._ctx = background()
        # Configured trust. First trust is always a deployment decision; it is
        # never inferred from something the caller presents. Pinned to the
        # complete hybrid key, never to a key ID alone.
        self.trust_root = trust_root
        self.trust_root_id = key_id_v2(trust_root)
        self.status_key = status_key
        #: The principal's status feed. Every issuer in an evaluated chain
        #: needs its own configured status key and feed (SPEC-v2 status is
        #: per issuer); see configure_issuer_status for subdelegation.
        self.status = StatusFeed(status_source)
        self._status_keys = {self.trust_root_id: status_key}
        self._feeds = {self.trust_root_id: self.status}

        self.verifier_pub, verifier_priv = generate_keypair_v2()
        self.verifier_id = key_id_v2(self.verifier_pub)

        # DEVELOPMENT ONLY: the SDK's in-memory reference stores.
        self.store = Store(int(time.time()), CLAIM_LEASE_SECONDS, LOG_ID, verifier_priv)
        self.issuance = TestOnlyChallengeIssuanceStore()
        self.journal = new_journal_store()
        record_security_key_role_v2(self._ctx, self.journal, "issuer", trust_root)
        record_security_key_role_v2(self._ctx, self.journal, "verifier", self.verifier_pub)
        configure_status_key_epoch_v2(self._ctx, self.journal, self.trust_root_id, 1, status_key)
        self._issuer = V2ChallengeIssuer(clock=self.store, store=self.issuance)

        self._pending: dict[str, _Pending] = {}
        self._session_id = uuid.uuid4().hex
        self._lock = threading.Lock()
        # Serializes verify -> publish -> release so receipt-log sequence order
        # is decision order. One process, one log: the reference store's
        # outbox publishes in sequence.
        self._decision_lock = threading.Lock()

        # Observable state, for the tests and the scenario driver.
        #: Decoded signed verification receipts, in log order.
        self.receipts: list = []
        #: Their exact wire bytes, as published to the log.
        self.receipt_wires: list[bytes] = []
        self.receipt_ids: list[str] = []
        #: Checkpoint acknowledgements, one per published receipt.
        self.acknowledgements: list = []
        #: Every proof that reached execute(), including ones refused before
        #: the claim, so indices do not correspond to `receipts`.
        self.presented: list[bytes] = []
        #: Operational security log, traffic that never reached a committed
        #: authorization decision. Deliberately not signed.
        self.refusals: list[str] = []
        self.refusal_count: int = 0
        self.internal_errors: int = 0
        #: Observability callbacks that raised. Counted, never surfaced to a
        #: caller, and never able to change a decision or a response.
        self.observation_failures: int = 0
        self.refunded_total_micros: int = 0

    # -- operator controls ------------------------------------------------

    def configure_issuer_status(self, issuer_pub, status_key, status_source) -> None:
        """Admit signed status for a non-root issuer in a chain.

        A subdelegating agent is itself an issuer, and v2 status is evaluated
        per issuer: a chain whose intermediate issuer has no configured status
        key cannot reach current status and fails closed. Configuring it is a
        trust decision the receiver makes, exactly like pinning the root."""
        issuer_id = key_id_v2(issuer_pub)
        record_security_key_role_v2(self._ctx, self.journal, "delegation", issuer_pub)
        configure_status_key_epoch_v2(self._ctx, self.journal, issuer_id, 1, status_key)
        with self._lock:
            self._status_keys[issuer_id] = status_key
            self._feeds[issuer_id] = StatusFeed(status_source)

    def break_status_feed(self, message: str) -> None:
        """Simulate the status feed being unreachable."""
        self.status.error = message

    def _tick(self) -> int:
        """Advance the reference store's authoritative clock to wall time.

        The reference store keeps a manual clock (it exists for deterministic
        tests). The store itself refuses to evaluate on a clock below its
        high-water mark, so this can only move time forward."""
        now = max(int(time.time()), self.store.now())
        self.store.set_time(now)
        return now

    # -- phase 1: the receiver decides what is being asked ----------------

    def challenge(
        self,
        *,
        order_id: str,
        amount_micros: int,
        currency: str,
        agent_id: str,
        agent_public_key,
        tenant: str = DEFAULT_TENANT,
    ) -> dict:
        """Issue a single-use challenge bound to the receiver's own canonical
        description of this operation.

        Raises :class:`BadRequest` if the business inputs are not something
        this service is willing to reason about. That check has to happen
        *here*, before a context is derived or a challenge is issued.
        """
        amount_micros = _validate_amount(amount_micros, currency)
        agent_pub = parse_agent(agent_id, agent_public_key)
        # Canonicalize before anything is bound. The protocol compares
        # resource_id by exact byte equality and never normalizes it, so
        # deciding what the canonical form *is* belongs to the application.
        resource_id = canonical_resource_id(tenant, order_id)
        now = self._tick()
        self._sweep(now)

        payload_digest = hashlib.sha256(
            json.dumps(
                {"amount_micros": amount_micros, "currency": currency, "resource_id": resource_id},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).digest()
        # The same canonical identifier that phase 2 hands the verifier as
        # requested_resource_id. Binding the session to one identifier and
        # evaluating the constraint against another would let an agent obtain
        # a challenge for one order and satisfy a constraint naming another.
        request_hash = operation_context_v2_hash(
            REQUIRED_SCOPE, OPERATION, resource_id, None, payload_digest
        )
        session_context = session_context_v2_hash(
            self.verifier_id,
            WORKSPACE_ID,
            agent_id,
            self._session_id,
            uuid.uuid4().hex,
            request_hash,
        )
        # The issuance helper persists the expected-challenge record before it
        # returns the challenge, so a challenge is never exposed that the
        # verifier could not later load.
        expected = self._issuer.issue_challenge_v2(
            self._ctx,
            V2ChallengeIssueRequest(
                verifier_namespace=VERIFIER_NAMESPACE,
                replay_epoch=REPLAY_EPOCH,
                verifier_id=self.verifier_id,
                lifetime_seconds=CHALLENGE_TTL_SECONDS,
                expected_agent_id=agent_id,
                expected_agent_public_key=agent_pub,
                expected_session_context=session_context,
            ),
        )

        with self._lock:
            self._pending[_key(expected.value)] = _Pending(
                resource_id=resource_id,
                amount_micros=amount_micros,
                currency=currency,
                required_scope=REQUIRED_SCOPE,
                agent_id=agent_id,
                session_context=session_context,
                expires_at=expected.expires_at,
            )

        return {
            "challenge": expected.value,
            "issued_at": expected.issued_at,
            "expires_at": expected.expires_at,
            "session_context": session_context,
            "verifier_id": self.verifier_id,
            # Echoed so the caller can see what the receiver understood. The
            # receiver does not read this back, it reads its own record.
            "parsed": {
                "resource_id": resource_id,
                "amount_micros": amount_micros,
                "currency": currency,
            },
        }

    # -- phase 2: the receiver decides whether to act ---------------------

    def execute(self, *, challenge: bytes, proof: bytes | None) -> dict:
        """Verify, commit, publish, release, and only then act.

        ``proof`` is the exact v2 proof-bundle wire bytes. The SDK decodes it
        strictly; a malformed proof is refused before any claim.
        """
        now = self._tick()
        self._sweep(now)

        if proof is None:
            return self._refuse("no_proof: no proof presented")

        self.presented.append(bytes(proof))

        with self._lock:
            record = self._pending.get(_key(challenge))
        if record is None:
            return self._refuse(
                "expected_challenge_unavailable: no pending request for this challenge"
            )

        # The expected-challenge record is loaded by the *outer* challenge the
        # request names, the receiver's own value. A captured proof submitted
        # under a different challenge therefore fails preflight as
        # challenge_mismatch, before any claim.
        try:
            expected = load_expected_challenge_v2(
                self._ctx, self.issuance, VERIFIER_NAMESPACE, REPLAY_EPOCH, challenge
            )
        except Exception:  # noqa: BLE001 - a missing record is a refusal
            return self._refuse(
                "expected_challenge_unavailable: no issuance record for this challenge"
            )

        with self._decision_lock:
            self._tick()
            outcome = verify_proof_bundle_v2(
                self._ctx,
                V2VerifyRequest(
                    bundle=bytes(proof),
                    expected=expected,
                    context_policy=new_v2_context_policy(
                        CONTEXT_POLICY_PROFILE,
                        True,
                        list(VERIFY_SESSION_CONTEXT_FIELDS_V2),
                        record.session_context,
                    ),
                    # Every trusted input below comes from the receiver's own
                    # phase-1 record. None of it is read from the request body.
                    required_scope=record.required_scope,
                    verifier_namespace=VERIFIER_NAMESPACE,
                    verifier_id=self.verifier_id,
                    replay_epoch=REPLAY_EPOCH,
                    now=self.store.now(),
                    max_challenge_age_seconds=CHALLENGE_TTL_SECONDS,
                    future_skew_seconds=5,
                    context=ConstraintContextV2(
                        has_amount=True,
                        requested_amount_micros=record.amount_micros,
                        requested_currency=record.currency,
                        # Resource-bound authority. A delegation may name the
                        # one order it covers. The identifier comes from the
                        # receiver's own phase-1 parse, so an agent cannot
                        # retarget an authorized refund at a different order.
                        # has_resource asserts the receiver genuinely has
                        # resource context; without it a resource_path
                        # constraint fails closed as constraint_unverifiable.
                        requested_resource_id=record.resource_id,
                        has_resource=True,
                    ),
                    tzdb_version=TZDB_VERSION_V2,
                    status_keys={
                        issuer: V2StatusKeyConfig(epoch=1, key=key)
                        for issuer, key in self._status_keys.items()
                    },
                    status_policy=STATUS_POLICY,
                ),
                V2VerifyCallbacks(
                    claim_store=self.store,
                    trust=self._trust,
                    status_evidence=self._status_evidence,
                    status_journal=self.journal,
                ),
            )

            if outcome.stage == V2_STAGE_PREFLIGHT:
                # Pre-claim: the presentation did not authenticate against this
                # receiver's issuance record (wrong challenge, stale, wrong
                # agent key, wrong session binding, bad signature, malformed).
                # Nothing is claimed, nothing is signed, and the legitimate
                # holder's challenge survives.
                return self._refuse(f"{outcome.error_class}: {_first_line(outcome.error)}")

            # From here the claim exists in the claim store, which is what makes
            # the challenge single-use. The pending record (the receiver's own
            # business inputs) is kept until the challenge expires, so a replay
            # reaches the claim store and is refused there, authoritatively,
            # rather than by the absence of a local record.
            if outcome.stage == V2_STAGE_REPLAY:
                return self._refuse(f"claim_replay: challenge already claimed ({outcome.disposition})")
            if outcome.stage != V2_STAGE_COMMITTED:
                # evaluating: a store or finalization failure after the claim.
                raise RuntimeError("v2 evaluation did not commit")

            committed = outcome.committed
            receipt_wire = self.store.publish_v2_receipt(
                self._ctx, committed.claim_id(), committed.receipt_body()
            )
            receipt = decode_verification_receipt_v2(receipt_wire)
            receipt_id = f"{LOG_ID}:{receipt.sequence}"
            # Recorded as soon as it is in the log: a committed decision stays
            # on the record even if anything after this point fails.
            with self._lock:
                self.receipts.append(receipt)
                self.receipt_wires.append(receipt_wire)
                self.receipt_ids.append(receipt_id)
            acknowledgement = self.store.get_v2_acknowledgement(self._ctx, LOG_ID, receipt.sequence)
            with self._lock:
                self.acknowledgements.append(acknowledgement)
            result = release_v2_decision(
                self._ctx,
                committed,
                receipt_wire,
                V2ReleaseConfig(
                    verifier_public_key=self.verifier_pub,
                    log_id=LOG_ID,
                    claim_store=self.store,
                    checkpoint=self.store,
                ),
            )

            if result.status != V2_RELEASE_RELEASED:
                # A committed decision that cannot be released is not
                # actionable, whatever it says.
                return _denied(
                    "authorization_unverified",
                    f"release_{result.status}: {result.reason}",
                    receipt_id,
                )

            decision = result.decision
            # Gate the side effect on allowed() at the receiver's own clock: a
            # released allow ends at the challenge expiry.
            self._tick()
            allowed = decision.allowed(self._ctx, self.store)
            refunded = record.amount_micros if allowed else 0
            with self._lock:
                self.refunded_total_micros += refunded

        return {
            "decision": "authorized" if allowed else "denied",
            "status": decision.identity_status(),
            "reason": decision.reason(),
            "refunded_micros": refunded,
            "receipt_id": receipt_id,
        }

    # -- callbacks the verifier calls --------------------------------------

    def _trust(self, _ctx, chain) -> V2TrustResolution:
        """Trust anchoring: the chain must terminate at the configured root.

        SPEC-v2 is normative that a key arriving in-band with the proof is
        never a trust root. The verifier cannot know whose roots we accept, so
        it asks; we answer with the complete configured key."""
        root = chain[-1]
        if root.issuer_id == self.trust_root_id and equal_public_keys(
            root.issuer_pub_key, self.trust_root
        ):
            return V2TrustResolution(outcome="trusted", root_key=self.trust_root)
        return V2TrustResolution(outcome="untrusted")

    def _status_evidence(self, _ctx, request) -> V2StatusEvidenceBatch:
        feed = self._feeds.get(request.issuer_id)
        if feed is None:
            raise LookupError("no status feed configured for this issuer")
        return V2StatusEvidenceBatch(
            objects=[V2StatusEvidenceObject(object_type=t, wire=w) for t, w in feed.fetch()]
        )

    # -- decision recording -----------------------------------------------

    def _refuse(self, reason: str) -> dict:
        """Reject traffic that never reached a committed decision.

        These refusals are operational events, not authorization decisions.
        Recording them as signed receipts would mean an unauthenticated caller
        could append to the verifier's audit trail at will, and would blur the
        one thing a receipt is supposed to mean: that a holder of the agent key
        presented a proof against a challenge this receiver issued, and the
        receiver ruled on its authority.
        """
        with self._lock:
            self.refusal_count += 1
            self.refusals.append(reason)
            if len(self.refusals) > MAX_REFUSAL_LOG:
                # Bounded on purpose. An unauthenticated caller drives this
                # list, so an unbounded one would trade an audit-integrity
                # problem for a memory-exhaustion one.
                del self.refusals[:-MAX_REFUSAL_LOG]
        return _denied("invalid", reason, receipt_id="")

    def _sweep(self, now: int) -> None:
        with self._lock:
            for key in [k for k, p in self._pending.items() if p.expires_at <= now]:
                del self._pending[key]


def _first_line(error) -> str:
    return str(error).splitlines()[0][:200] if error is not None else ""


def _denied(status: str, reason: str, receipt_id: str) -> dict:
    return {
        "decision": "denied",
        "status": status,
        "reason": reason,
        "refunded_micros": 0,
        "receipt_id": receipt_id,
    }


#: A protocol reference has no reason to accept a large body.
MAX_BODY_BYTES = 256 * 1024

#: The only thing an unexpected internal failure ever tells the caller.
#: No exception text, no stack trace, no proof contents, no key material, a
#: verifier's error path is an information-disclosure surface like any other.
#: The caller learns one actionable fact: start over with a new challenge.
_INTERNAL_ERROR = {
    "decision": "denied",
    "status": "receiver_error",
    "reason": "the receiver failed closed; obtain a new challenge and retry",
    "refunded_micros": 0,
    "receipt_id": "",
}

#: Cap on the retained operational log; unauthenticated callers drive it.
MAX_REFUSAL_LOG = 1000


def _reject_json_constant(name: str):
    """Refuse the non-RFC-8259 constants Python's json accepts by default.

    ``json.loads('{"amount_micros": NaN}')`` succeeds out of the box. v2 has no
    floats at all, so the parser is the right place to stop it, before any
    code has a chance to forget."""
    raise ValueError(f"{name} is not valid JSON")


def _reject_float(literal: str):
    """Refuse any JSON number with a fraction or exponent. v2 is integer-only."""
    raise ValueError(f"non-integer number {literal[:32]!r} is not accepted")


def _require_str(body: dict, field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise BadRequest(f"{field} must be a non-empty string")
    return value


def _key(challenge: bytes) -> str:
    return base64.b64encode(challenge).decode("ascii")


def malformed(message: str) -> dict:
    return {"error": message, "error_class": "malformed"}


# ---------------------------------------------------------------------------
# HTTP transport, stdlib only
# ---------------------------------------------------------------------------


def _make_handler(service: RefundService):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):  # noqa: N802, BaseHTTPRequestHandler's interface
            # Every branch below returns a deterministic JSON response. A
            # security boundary that answers malformed input with a traceback
            # and a dropped connection is not failing closed, it is just
            # failing.
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._send(malformed("invalid Content-Length"), 400)
            if length < 0 or length > MAX_BODY_BYTES:
                return self._send({"error": "request body too large"}, 413)

            try:
                # parse_constant rejects bare NaN / Infinity; parse_float
                # rejects every fractional or exponent number. Both are
                # malformed in a v2 deployment.
                body = json.loads(
                    self.rfile.read(length) or b"{}",
                    parse_constant=_reject_json_constant,
                    parse_float=_reject_float,
                )
            except ValueError as exc:
                return self._send(malformed(f"malformed JSON: {exc}"), 400)
            if not isinstance(body, dict):
                return self._send(malformed("request body must be a JSON object"), 400)

            if self.path == "/refunds/challenge":
                try:
                    out = service.challenge(
                        order_id=_require_str(body, "order_id"),
                        # tenant is the service's, not the caller's.
                        amount_micros=body.get("amount_micros"),
                        currency=body.get("currency", SETTLEMENT_CURRENCY),
                        agent_id=_require_str(body, "agent_id"),
                        agent_public_key=body.get("agent_public_key"),
                    )
                except BadRequest as exc:
                    return self._send(malformed(str(exc)), 400)
                except Exception:  # noqa: BLE001, see _INTERNAL_ERROR
                    service.internal_errors += 1
                    return self._send(_INTERNAL_ERROR, 500)
                return self._send(out)

            if self.path == "/refunds":
                try:
                    challenge = base64.b64decode(_require_str(body, "challenge"), validate=True)
                except (BadRequest, ValueError, binascii.Error) as exc:
                    return self._send(malformed(f"invalid challenge encoding: {exc}"), 400)

                proof = None
                if body.get("proof") is not None:
                    if not isinstance(body["proof"], str):
                        return self._send(malformed("proof must be a base64 string"), 400)
                    try:
                        proof = base64.b64decode(body["proof"], validate=True)
                    except (ValueError, binascii.Error) as exc:
                        return self._send(malformed(f"invalid proof encoding: {exc}"), 400)
                try:
                    return self._send(service.execute(challenge=challenge, proof=proof))
                except Exception:  # noqa: BLE001, see _INTERNAL_ERROR
                    # The claim, once made, is deliberately NOT undone. It was
                    # atomically recorded before any of this could fail;
                    # handing the challenge back would reopen the replay
                    # window the claim exists to close. The caller obtains a
                    # new one.
                    service.internal_errors += 1
                    return self._send(_INTERNAL_ERROR, 500)

            return self._send({"error": "not found"}, 404)

        def _send(self, payload: dict, status: int = 200) -> None:
            encoded = json.dumps(payload, default=_json_default).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *args) -> None:  # keep test output readable
            pass

    return Handler


def _json_default(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    raise TypeError(f"not JSON-serializable: {type(value).__name__}")


def serve(service: RefundService, host: str = "127.0.0.1", port: int = 0):
    """Run the service on a background thread. Returns ``(server, base_url)``."""
    server = ThreadingHTTPServer((host, port), _make_handler(service))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{host}:{server.server_port}"
