# SPDX-License-Identifier: Apache-2.0
"""The receiving service, where the authorization decision is made.

This process is operated by a different party from the agent. It holds the
principal's root public key as configured trust and nothing else. Everything
arriving over the wire is input to be parsed, never a fact to be believed:
the amount, the order, the operation, and any opinion the agent has about
whether it is allowed.

Transport is the Python standard library. A protocol reference should not
require a web framework to be understood.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import threading
import time
import uuid
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ratify_protocol import (
    SCOPE_PAYMENTS_SEND,
    MemoryChallengeStore,
    OperationContext,
    ProofBundle,
    SessionContextInputs,
    VerifierContext,
    VerifyOptions,
    VerifyResult,
    build_session_context,
    canonical_json,
    derive_id,
    generate_hybrid_keypair,
    issue_verification_receipt,
    operation_context_hash,
    receipt_hash,
    verify_bundle,
    verify_challenge_signature,
)
from ratify_protocol.wire import decode_proof_bundle

#: The scope a refund requires. Chosen by the *service*, never by the caller.
REQUIRED_SCOPE = SCOPE_PAYMENTS_SEND
OPERATION = "refund.issue"
CHALLENGE_TTL_SECONDS = 60
WORKSPACE_ID = "acme-payments"
#: The only currency this reference settles in.
SETTLEMENT_CURRENCY = "USD"
#: The tenant this deployment serves. Real deployments derive this from the
#: authenticated caller, never from the request body.
DEFAULT_TENANT = "acme"

class BadRequest(ValueError):
    """A business input the service refuses to reason about. Maps to 400."""


#: Order identifiers this service will accept, before canonicalization.
_ORDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def canonical_resource_id(tenant: str, order_id: str) -> str:
    """Build the one canonical name for an order, tenant-qualified.

    Two tenants can each have an "8841". A bare order number is therefore
    ambiguous across tenants, and a delegation naming one would authorize the
    other's order of the same number. Qualifying by tenant removes that.

    This function is the whole canonicalization contract. SPEC 5.7.3 makes
    ``resource_id`` an opaque UTF-8 string compared by **exact byte
    equality**: the verifier performs no case folding, percent-decoding, or
    normalization of any kind. That is a deliberate protocol choice, and it
    means an application that accepts two spellings of the same resource has
    two different resources as far as verification is concerned. So the
    receiver pins one spelling here, rejects anything that does not fit it,
    and uses the result for both the session binding and the constraint.
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
#: denial-of-service on the constraint evaluator.
MAX_PLAUSIBLE_AMOUNT = 1_000_000_000.0


def _validate_amount(amount: object, currency: object) -> None:
    """Reject amounts the constraint evaluator cannot safely order.

    This is a security check, not input hygiene. ``max_amount`` is enforced as
    ``requested_amount > max_amount``, and **every ordered comparison against
    NaN is false**, so a NaN amount satisfies any ceiling and authorizes an
    unbounded refund. Python's ``json`` module accepts a bare ``NaN`` literal
    on the wire, so this is reachable by any caller. Negative infinity and
    ordinary negative values slip through the same way; a negative refund is a
    charge.

    The receiver owns its business inputs. Handing an unvalidated float to a
    verifier and expecting the verifier to save you is the mistake.
    """
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise BadRequest("amount must be a number")
    value = float(amount)
    if not math.isfinite(value):
        raise BadRequest("amount must be finite (NaN and infinities are rejected)")
    if value <= 0.0:
        # Zero is rejected deliberately: a zero refund is not a meaningful
        # authorization decision, and permitting it invites callers to probe
        # verification outcomes at no cost.
        raise BadRequest("amount must be greater than zero")
    if value > MAX_PLAUSIBLE_AMOUNT:
        raise BadRequest("amount exceeds the maximum this service will consider")
    # This reference settles in USD only. Checking the shape of an arbitrary
    # code would imply a currency table the demo does not have, and a
    # constraint is denominated, comparing a EUR request against a USD
    # ceiling is not a conversion the verifier should silently perform.
    if currency != SETTLEMENT_CURRENCY:
        raise BadRequest(f"currency must be {SETTLEMENT_CURRENCY}")


@dataclass
class _Pending:
    """What the receiver decided this request *is*, recorded at phase 1.

    Phase 2 reads its trusted inputs from here and never from the request
    body, which is what makes request substitution a cryptographic failure
    rather than a matter of discipline.
    """

    resource_id: str
    amount: float
    currency: str
    required_scope: str
    #: The agent this challenge was issued to. The identifier is already inside
    #: the session-context preimage, but session_context is a 32-byte hash,
    #: the verifier compares hashes and cannot introspect who the challenge
    #: belongs to. Holding the association here is what stops a second agent
    #: from spending the first agent's challenge.
    agent_id: str
    session_context: bytes
    expires_at: int


class _RevocationProvider:
    """Stands in for whatever revocation source a deployment chooses.

    Returns ``(revoked, error)``. An error is *not* "not revoked", the
    verifier fails the presentation closed as ``revocation_error``.
    """

    def __init__(self) -> None:
        self.revoked: set[str] = set()
        self.error: str | None = None

    def is_revoked(self, cert_id: str) -> tuple[bool, str | None]:
        if self.error is not None:
            return False, self.error
        return cert_id in self.revoked, None


class RefundService:
    """Verifies delegated authority, then moves money, in that order."""

    def __init__(self, trust_root, verifier_id: str = "refund-service") -> None:
        # Configured trust. First trust is always a deployment decision; it is
        # never inferred from something the caller presents.
        self.trust_root = trust_root
        self.trust_root_id = derive_id(trust_root)

        self.verifier_id = verifier_id
        self.verifier_pub, self._verifier_priv = generate_hybrid_keypair()

        self.challenges = MemoryChallengeStore()
        self._revocation = _RevocationProvider()
        self._pending: dict[str, _Pending] = {}
        self._session_id = uuid.uuid4().hex
        self._lock = threading.Lock()

        # Observable state, for the tests and the scenario driver.
        self.receipts: list = []
        self.receipt_ids: list[str] = []
        #: Every bundle that reached execute(), including ones refused before
        #: authentication, so indices do not correspond to `receipts` when
        #: refusals are interleaved.
        self.presented: list[ProofBundle] = []
        #: Operational security log, unauthenticated traffic that never
        #: reached an authorization decision. Deliberately not signed.
        self.refusals: list[str] = []
        self.refusal_count: int = 0
        self.internal_errors: int = 0
        #: Observability callbacks that raised. Counted, never surfaced to a
        #: caller, and never able to change a decision or a response.
        self.observation_failures: int = 0
        self.refunded_total: float = 0.0

    # -- operator controls ------------------------------------------------

    def revoke(self, cert_id: str) -> None:
        self._revocation.revoked.add(cert_id)

    def break_revocation(self, message: str) -> None:
        """Simulate the revocation source being unreachable."""
        self._revocation.error = message

    # -- phase 1: the receiver decides what is being asked ----------------

    def challenge(
        self,
        *,
        order_id: str,
        amount: float,
        currency: str,
        agent_id: str,
        tenant: str = DEFAULT_TENANT,
    ) -> dict:
        """Issue a single-use challenge bound to the receiver's own canonical
        description of this operation.

        Raises :class:`BadRequest` if the business inputs are not something
        this service is willing to reason about. That check has to happen
        *here*, before an OperationContext is built or a challenge is issued,
        see :func:`_validate_amount` for why a missing check is exploitable
        rather than merely untidy.
        """
        _validate_amount(amount, currency)
        if not agent_id:
            raise BadRequest("agent_id must be a non-empty string")
        # Canonicalize before anything is bound. The protocol compares
        # resource_id by exact byte equality and never normalizes it, so
        # deciding what the canonical form *is* belongs to the application.
        resource_id = canonical_resource_id(tenant, order_id)
        now = int(time.time())
        self._sweep(now)

        invocation_id = uuid.uuid4().hex
        operation = OperationContext(
            required_scope=REQUIRED_SCOPE,
            operation=OPERATION,
            # The same canonical identifier that phase 2 will hand the verifier
            # as requested_resource_id. Binding the session to one identifier
            # and evaluating the constraint against another would let an agent
            # obtain a challenge for one order and satisfy a constraint naming
            # a different one.
            resource_id=resource_id,
            payload_digest=hashlib.sha256(
                canonical_json(
                    {"amount": amount, "currency": currency, "resource_id": resource_id}
                )
            ).digest(),
        )
        session_context = build_session_context(
            SessionContextInputs(
                verifier_id=self.verifier_id,
                workspace_id=WORKSPACE_ID,
                agent_id=agent_id,
                session_id=self._session_id,
                invocation_id=invocation_id,
                request_hash=operation_context_hash(operation),
            )
        )
        challenge, expires_at = self.challenges.issue(session_context, CHALLENGE_TTL_SECONDS)

        with self._lock:
            self._pending[_key(challenge)] = _Pending(
                resource_id=resource_id,
                amount=amount,
                currency=currency,
                required_scope=REQUIRED_SCOPE,
                agent_id=agent_id,
                session_context=session_context,
                expires_at=expires_at,
            )

        return {
            "challenge": challenge,
            "session_context": session_context,
            "expires_at": expires_at,
            # Echoed so the caller can see what the receiver understood. The
            # receiver does not read this back, it reads its own record.
            "parsed": {"resource_id": resource_id, "amount": amount, "currency": currency},
        }

    # -- phase 2: the receiver decides whether to act ---------------------

    def execute(self, *, challenge: bytes, bundle: ProofBundle | None) -> dict:
        now = int(time.time())
        self._sweep(now)

        if bundle is None:
            return self._refuse("no proof presented")

        self.presented.append(bundle)

        with self._lock:
            record = self._pending.get(_key(challenge))
        if record is None:
            return self._refuse("unknown_challenge: no pending request for this challenge")

        # --- authentication gate ------------------------------------------
        # Nothing above this line may mint a receipt or retire a pending
        # request: it is all reachable by an unauthenticated caller, and an
        # attacker who can append signed entries at will holds a write
        # primitive into the audit trail.
        #
        # Every check below is stated against values the *receiver* holds. A
        # presentation is a claim about one specific challenge; verifying the
        # signature over the bundle's own copy of that challenge would only
        # prove the presenter once answered *something*. A captured bundle
        # replayed under a different outer challenge would then authenticate,
        # burn the fresh challenge, and append a signed denial, a
        # denial-of-service against the legitimate holder.

        # 1. The presentation must be *about* the challenge it was sent with.
        if bundle.challenge != challenge:
            return self._refuse(
                "challenge_binding_mismatch: bundle does not answer the challenge it "
                "was submitted with"
            )

        # 2. It must carry the binding this receiver issued, byte for byte.
        if bundle.session_context != record.session_context:
            return self._refuse(
                "session_binding_mismatch: bundle is not bound to this request's "
                "session context"
            )

        # 3. The pending request must still be live.
        if record.expires_at <= now:
            return self._refuse("challenge_expired: this challenge is no longer valid")

        # 4. The presented key must be the agent the challenge was issued to.
        #    Checked against the derived identifier rather than the bundle's
        #    self-reported agent_id, which the presenter controls.
        if derive_id(bundle.agent_pub_key) != record.agent_id:
            return self._refuse(
                "challenge_agent_mismatch: presented key is not the agent this "
                "challenge was issued to"
            )

        # 5. Proof of possession over exactly those receiver-held values.
        proved_possession = verify_challenge_signature(
            challenge,  # ours, not the bundle's
            bundle.challenge_at,
            bundle.challenge_sig,
            bundle.agent_pub_key,
            record.session_context,  # ours, not the bundle's
            bundle.stream_id,
            bundle.stream_seq,
        )
        if not proved_possession:
            return self._refuse(
                "bad_challenge_sig: presenter did not prove possession of the agent key"
            )

        # Authenticated. Claim the pending record atomically: whoever removes
        # it proceeds, everyone else is refused. Two things depend on this.
        #
        # One, it bounds receipts to challenges issued. Expiry and revocation
        # are evaluated before the SDK consumes the challenge, so a denial on
        # those grounds leaves the challenge unspent, without claiming, the
        # same presentation could be replayed to append a signed receipt every
        # time.
        #
        # Two, it must happen *after* the checks above, not before: a
        # presentation that fails proof of possession must not burn the
        # legitimate holder's challenge.
        with self._lock:
            record = self._pending.pop(_key(challenge), None)
        if record is None:
            return self._refuse("challenge_already_presented: this challenge was already used")

        # A presentation with no delegation chain claims no authority at all.
        # The HTTP decoder already rejects this shape, but RefundService is
        # importable and someone will call it directly, an IndexError on the
        # next line would be a crash where a denial belongs. This is a *signed*
        # denial rather than an unsigned refusal: proof of possession succeeded
        # above, so the presenter is authenticated and their failed claim of
        # authority is a real authorization decision.
        if not bundle.delegations:
            return self._decide(
                bundle,
                VerifyResult(
                    valid=False,
                    identity_status="invalid",
                    error_reason="no_delegations: proof bundle contains no delegation "
                    "certificates",
                ),
                0.0,
            )

        # Trust anchoring: the chain must terminate at the root this
        # deployment configured. SPEC §15.4 is normative, a verifier MUST NOT
        # treat a key that arrives in-band with the proof bundle as a trust
        # root. verify_bundle cannot do this for us; it has no way to know
        # whose roots we accept.
        root = bundle.delegations[-1]
        if root.issuer_id != self.trust_root_id or not _same_key(
            root.issuer_pub_key, self.trust_root
        ):
            return self._decide(
                bundle,
                VerifyResult(
                    valid=False,
                    identity_status="unauthorized",
                    error_reason="untrusted_root: delegation chain does not terminate at a "
                    "trusted principal",
                ),
                0.0,
            )

        result = verify_bundle(
            bundle,
            VerifyOptions(
                # Every trusted input below comes from the receiver's own
                # phase-1 record. None of it is read from the request body.
                required_scope=record.required_scope,
                session_context=record.session_context,
                context=VerifierContext(
                    requested_amount=record.amount,
                    requested_currency=record.currency,
                    # Resource-bound authority (alpha.16). A delegation may name
                    # the one order it covers, so "refund up to $100" becomes
                    # "refund up to $100 for order-8841". The identifier comes
                    # from the receiver's own phase-1 parse, exactly like the
                    # amount, so an agent cannot retarget an authorized refund
                    # at a different order by restating it here.
                    #
                    # has_resource is the caller asserting it genuinely has
                    # resource context. Leaving it False makes a resource_path
                    # constraint fail closed as constraint_unverifiable rather
                    # than silently passing.
                    requested_resource_id=record.resource_id,
                    has_resource=True,
                ),
                challenge_store=self.challenges,
                revocation=self._revocation,
                force_revocation_check=True,
                now=now,
            ),
        )

        return self._decide(bundle, result, record.amount if result.valid else 0.0)

    # -- decision recording -----------------------------------------------

    def _refuse(self, reason: str) -> dict:
        """Reject traffic that never authenticated, without touching the chain.

        These refusals are operational events, not authorization decisions.
        Recording them as signed receipts would mean an unauthenticated caller
        could append to the verifier's audit trail at will, and would blur the
        one thing a receipt is supposed to mean: that a holder of the agent
        key presented a proof and we ruled on its authority.
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

    def _decide(self, bundle: ProofBundle, result: VerifyResult, refunded: float) -> dict:
        # Receipt issuance and the refund ledger share one critical section.
        # The chain links each receipt to its predecessor, so reading
        # ``receipts[-1]`` and appending must be indivisible: two concurrent
        # decisions that both read the same predecessor would sign two
        # receipts carrying the same prev_hash, forking the chain and
        # destroying the tamper-evidence it exists to provide. Requests are
        # served concurrently, so this is reachable, not theoretical.
        with self._lock:
            receipt = issue_verification_receipt(
                bundle,
                _for_receipt(result),
                self.verifier_id,
                self.verifier_pub,
                self._verifier_priv,
                receipt_hash(self.receipts[-1]) if self.receipts else None,
                int(time.time()),
            )
            receipt_id = f"{self.verifier_id}:{len(self.receipts) + 1}"
            self.receipts.append(receipt)
            self.receipt_ids.append(receipt_id)
            self.refunded_total += refunded

        return {
            "decision": "authorized" if result.valid else "denied",
            "status": result.identity_status,
            "reason": result.error_reason,
            "refunded": refunded,
            "receipt_id": receipt_id,
        }

    def _sweep(self, now: int) -> None:
        with self._lock:
            for key in [k for k, p in self._pending.items() if p.expires_at <= now]:
                del self._pending[key]


def _for_receipt(result: VerifyResult) -> VerifyResult:
    """Strip identity from failure results before they are attested.

    Expiry and revocation are checked before the chain signature is verified,
    so ``human_id`` and ``agent_id`` on a failure result are copied from a
    certificate nobody has authenticated yet. Signing them into a receipt
    would turn a denial record into an unearned statement that a named
    principal and agent were present. The presentation stays fully
    recoverable through the receipt's ``bundle_hash``.
    """
    if result.valid:
        return result
    return replace(result, human_id="", agent_id="", granted_scope=[])


def _denied(status: str, reason: str, receipt_id: str) -> dict:
    return {
        "decision": "denied",
        "status": status,
        "reason": reason,
        "refunded": 0.0,
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
    "refunded": 0.0,
    "receipt_id": "",
}

#: Cap on the retained operational log; unauthenticated callers drive it.
MAX_REFUSAL_LOG = 1000


def _reject_json_constant(name: str):
    """Refuse the non-RFC-8259 constants Python's json accepts by default.

    ``json.loads('{"amount": NaN}')`` succeeds out of the box. Since a NaN
    amount defeats every ordered constraint comparison, the parser is the
    right place to stop it, before any code has a chance to forget.
    """
    raise ValueError(f"{name} is not valid JSON")


def _require_str(body: dict, field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise BadRequest(f"{field} must be a non-empty string")
    return value


def _same_key(a, b) -> bool:
    return a.ed25519 == b.ed25519 and a.ml_dsa_65 == b.ml_dsa_65


def _key(challenge: bytes) -> str:
    return base64.b64encode(challenge).decode("ascii")


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
                return self._send({"error": "invalid Content-Length"}, 400)
            if length < 0 or length > MAX_BODY_BYTES:
                return self._send({"error": "request body too large"}, 413)

            try:
                # parse_constant rejects the bare NaN / Infinity literals that
                # Python's json accepts by default but RFC 8259 does not.
                body = json.loads(
                    self.rfile.read(length) or b"{}",
                    parse_constant=_reject_json_constant,
                )
            except ValueError as exc:
                return self._send({"error": f"malformed JSON: {exc}"}, 400)
            if not isinstance(body, dict):
                return self._send({"error": "request body must be a JSON object"}, 400)

            if self.path == "/refunds/challenge":
                try:
                    out = service.challenge(
                        order_id=_require_str(body, "order_id"),
                        # tenant is the service's, not the caller's.
                        amount=body.get("amount"),
                        currency=body.get("currency", "USD"),
                        agent_id=_require_str(body, "agent_id"),
                    )
                except BadRequest as exc:
                    return self._send({"error": str(exc)}, 400)
                except Exception:  # noqa: BLE001, see _INTERNAL_ERROR
                    service.internal_errors += 1
                    return self._send(_INTERNAL_ERROR, 500)
                return self._send(out)

            if self.path == "/refunds":
                try:
                    challenge = base64.b64decode(_require_str(body, "challenge"), validate=True)
                except (BadRequest, ValueError, binascii.Error) as exc:
                    return self._send({"error": f"invalid challenge encoding: {exc}"}, 400)

                bundle = None
                if body.get("bundle") is not None:
                    if not isinstance(body["bundle"], dict):
                        return self._send({"error": "bundle must be a JSON object"}, 400)
                    try:
                        bundle = decode_proof_bundle(json.dumps(body["bundle"]))
                    except (ValueError, TypeError, KeyError) as exc:
                        return self._send(
                            _denied("invalid", f"malformed proof bundle: {exc}", receipt_id="")
                        )
                try:
                    return self._send(service.execute(challenge=challenge, bundle=bundle))
                except Exception:  # noqa: BLE001, see _INTERNAL_ERROR
                    # The claimed challenge is deliberately NOT restored. It
                    # was authenticated and atomically retired before any of
                    # this could fail; handing it back would reopen the replay
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
