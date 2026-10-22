# SPDX-License-Identifier: Apache-2.0
"""Deterministic security tests for the delegated-authority reference, on
Ratify Protocol v2.

No LLM, no NOOA, no network beyond loopback. Every test states *why* the
behaviour matters, because a test that only records what the code does today
cannot fail when the security property regresses.

The scenario throughout: a principal delegates "issue refunds up to 100.00
USD, for 24 hours" to one agent key. A refund service operated by a
*different* party verifies that delegation before moving money.

Amounts are integer micro-units (10^-6 USD), as v2 requires: the ceiling is
``100_000_000`` and the test amounts are 75.00 and 150.00 USD. There are no
floats anywhere on the v2 wire.

The receiver uses the SDK's in-memory reference stores (claim store, receipt
log, checkpoint, journal, challenge issuance). They are development only.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from ratify_protocol_v2.constraints_v2 import ConstraintContextV2
from ratify_protocol_v2.protocol_v2 import decode_proof_bundle_v2
from ratify_protocol_v2.scope import (
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_SEND,
)
from ratify_protocol_v2.verification_receipt_v2 import (
    ReceiptV2Head,
    check_verification_receipt_v2_bundle_binding,
    verification_receipt_v2_digest,
    verify_verification_receipt_v2,
)
from ratify_protocol_v2.witness_v2 import ZERO_HASH

from adversary import forge_presentation as _forge
from agent_client import RefundClient, post_json
from principal import (
    StatusAuthority,
    max_amount_micros,
    new_agent,
    new_principal,
    resource_bound,
    sign_cert,
)
from refund_service import (
    LOG_ID,
    REQUIRED_SCOPE,
    RefundService,
    canonical_resource_id,
    encode_public_key,
    serve,
)

LIMIT = 100_000_000  # 100.00 USD
UNDER = 75_000_000  # 75.00 USD
OVER = 150_000_000  # 150.00 USD
DAY = 24 * 3600


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def world():
    """A principal with signed status, an agent, a running service, a client."""
    principal, principal_priv = new_principal()
    agent, agent_priv = new_agent("refund-agent")

    now = int(time.time())
    status = StatusAuthority(principal, now)
    cert = sign_cert(
        issuer_id=principal.id,
        issuer_pub=principal.public_key,
        issuer_priv=principal_priv,
        subject_id=agent.id,
        subject_pub=agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[max_amount_micros(LIMIT)],
        issued_at=now - 60,
        expires_at=now + DAY,
    )

    service = RefundService(principal.public_key, status.status_pub, status)
    server, base_url = serve(service)
    client = RefundClient(base_url, agent.id, agent.public_key, agent_priv, [cert])
    try:
        yield _World(
            principal, principal_priv, agent, agent_priv, cert, status, service, base_url, client
        )
    finally:
        server.shutdown()


class _World:
    def __init__(
        self, principal, principal_priv, agent, agent_priv, cert, status, service, base_url, client
    ):
        self.principal = principal
        self.principal_priv = principal_priv
        self.agent = agent
        self.agent_priv = agent_priv
        self.cert = cert
        self.status = status
        self.service = service
        self.base_url = base_url
        self.client = client


def forge_presentation(agent_id, agent_pub, signing_priv, delegations, challenge, session_context):
    """An attacker's hand-built presentation; see :mod:`adversary`."""
    return _forge(
        verifier_id=challenge["verifier_id"],
        agent_id=agent_id,
        agent_pub=agent_pub,
        signing_priv=signing_priv,
        delegations=delegations,
        challenge=challenge["challenge"],
        challenge_at=challenge["issued_at"],
        session_context=session_context,
    )


def present(world, challenge: bytes, proof: bytes, **extra) -> dict:
    return post_json(
        world.base_url + "/refunds", {"challenge": challenge, "proof": proof, **extra}
    )


def post_raw(url: str, raw: bytes) -> tuple[int, dict]:
    """POST bytes that may not be well-formed. Returns (status, decoded body).

    The security boundary must answer malformed input with a deterministic
    status, not an exception or a dropped connection, so the tests need to see
    the status rather than have urllib raise it away.
    """
    request = urllib.request.Request(
        url, data=raw, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _challenge_body(world, **overrides) -> bytes:
    body = {
        "order_id": "ord-x",
        "amount_micros": UNDER,
        "currency": "USD",
        "agent_id": world.agent.id,
        "agent_public_key": encode_public_key(world.agent.public_key),
    }
    body.update(overrides)
    return json.dumps(body).encode()


# ---------------------------------------------------------------------------
# 0. Business inputs the verifier cannot safely reason about
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "literal",
    ["NaN", "Infinity", "-Infinity"],
    ids=["nan", "positive_infinity", "negative_infinity"],
)
def test_non_finite_amounts_are_malformed(world, literal):
    """WHY: in Protocol v1 this was an authorization bypass. ``max_amount`` was
    a float compared as ``requested > max``, every ordered comparison against
    NaN is false, and an earlier version of this reference authorized a NaN
    refund. v2 removes floats from the wire, and the receiver holds its own
    input to the same rule: a non-finite amount is ``malformed`` and never
    reaches a challenge."""
    raw = (
        '{"order_id":"ord-nan","amount_micros":%s,"currency":"USD","agent_id":"%s"}'
        % (literal, world.agent.id)
    ).encode()

    status, body = post_raw(world.base_url + "/refunds/challenge", raw)

    assert status == 400
    assert body["error_class"] == "malformed"
    assert world.service.refunded_total_micros == 0
    assert not world.service.receipts


@pytest.mark.parametrize(
    "literal", ["75000000.5", "7.5e7", "75000000.0"], ids=["fraction", "exponent", "integral_float"]
)
def test_fractional_amounts_are_malformed(world, literal):
    """WHY: v2 amounts are integer micro-units. A float is not a coarser
    spelling of an integer; it is a different type, and accepting it would
    reintroduce the rounding and NaN ambiguity v2 removed."""
    raw = _challenge_body(world).replace(
        str(UNDER).encode(), literal.encode(), 1
    )

    status, body = post_raw(world.base_url + "/refunds/challenge", raw)

    assert status == 400
    assert body["error_class"] == "malformed"


@pytest.mark.parametrize(
    "amount", [-50_000_000, -1, 0], ids=["negative", "tiny_negative", "zero"]
)
def test_non_positive_amounts_are_rejected(world, amount):
    """WHY: a negative refund is a charge, and it passes every ceiling check
    trivially because it is smaller than the maximum. Zero is refused
    deliberately, it is not a meaningful authorization decision, and allowing
    it hands callers a free way to probe verification outcomes."""
    status, body = post_raw(
        world.base_url + "/refunds/challenge", _challenge_body(world, amount_micros=amount)
    )

    assert status == 400
    assert body["error_class"] == "malformed"
    assert world.service.refunded_total_micros == 0


@pytest.mark.parametrize(
    "raw,label",
    [
        (b'{"order_id":"o","amount_micros":"75","currency":"USD","agent_id":"a"}', "string_amount"),
        (b'{"order_id":"o","amount_micros":true,"currency":"USD","agent_id":"a"}', "bool_amount"),
        (b'{"order_id":"o","amount_micros":null,"currency":"USD","agent_id":"a"}', "null_amount"),
        (b'{"order_id":"o","amount_micros":75,"currency":"US","agent_id":"a"}', "bad_currency"),
        (b'{"order_id":"","amount_micros":75,"currency":"USD","agent_id":"a"}', "empty_order"),
        (b'{"order_id":"o","amount_micros":75,"currency":"USD","agent_id":""}', "empty_agent"),
        (b'{"order_id":"o","amount_micros":75,"currency":"USD","agent_id":"a"}', "short_agent_id"),
        (b"{not json at all", "malformed_json"),
        (b'["array","not","object"]', "json_array"),
        (b'"a bare string"', "json_scalar"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_malformed_transport_input_fails_closed(world, raw, label):
    """WHY: a security boundary that answers bad input with a traceback and a
    dropped connection has not failed closed, it has just failed. Every one
    of these must produce a deterministic 4xx and leave no state behind."""
    status, _ = post_raw(world.base_url + "/refunds/challenge", raw)

    assert 400 <= status < 500
    assert world.service.refunded_total_micros == 0
    assert not world.service.receipts


def test_agent_id_must_be_derived_from_the_presented_public_key(world):
    """WHY: v2 issues a challenge to an agent's *complete* key, never to a key
    ID alone. A caller that names one ID and supplies another key is asking
    for a challenge bound to an identity it cannot prove."""
    other, _ = new_agent("other")
    status, body = post_raw(
        world.base_url + "/refunds/challenge",
        _challenge_body(world, agent_public_key=encode_public_key(other.public_key)),
    )

    assert status == 400
    assert body["error_class"] == "malformed"


def test_invalid_challenge_encoding_is_rejected(world):
    """WHY: the challenge arrives base64-encoded. Undecodable input must be a
    clean rejection, not an exception escaping the handler."""
    status, _ = post_raw(
        world.base_url + "/refunds", json.dumps({"challenge": "!!!not-base64!!!"}).encode()
    )

    assert 400 <= status < 500
    assert not world.service.receipts


@pytest.mark.parametrize(
    "replacement", [b"NaN", b"1.0e8", b"100000000.0"], ids=["nan", "exponent", "float"]
)
def test_a_float_in_a_signed_delegation_is_malformed(world, replacement):
    """WHY: the NaN bypass in v1 lived in the signed constraint as much as in
    the request. In v2 a delegation whose ``max_amount_micros`` is anything but
    an integer does not decode: the proof is malformed and refused before any
    claim, so it can neither authorize nor write a receipt."""
    ch = world.client.fetch_challenge("ord-float", UNDER)
    proof = world.client.sign(ch)
    needle = b'"max_amount_micros":%d' % LIMIT
    assert needle in proof
    tampered = proof.replace(needle, b'"max_amount_micros":' + replacement)

    out = present(world, ch["challenge"], tampered)

    assert out["decision"] == "denied"
    assert out["reason"].startswith("malformed")
    assert out["receipt_id"] == ""
    assert world.service.receipts == []
    # A malformed presentation does not burn the legitimate holder's challenge.
    assert world.client.present(ch)["decision"] == "authorized"


# ---------------------------------------------------------------------------
# 1. The bounded action the principal actually authorized
# ---------------------------------------------------------------------------


def test_refund_within_bound_is_authorized(world):
    """WHY: if a correctly bounded action does not succeed, the layer is
    useless regardless of how well it denies. This is the baseline the
    denials are measured against."""
    out = world.client.request_refund("ord-1", UNDER)

    assert out["decision"] == "authorized"
    assert out["status"] == "authorized_agent"
    assert out["refunded_micros"] == UNDER
    assert world.service.refunded_total_micros == UNDER


# ---------------------------------------------------------------------------
# 2. The principal's bound survives transit into another organization
# ---------------------------------------------------------------------------


def test_over_limit_refund_is_denied_by_the_principals_constraint(world):
    """WHY: this is the whole proposition. The 100.00 USD ceiling was
    expressed by the principal, in another organization, and is enforced by a
    receiver that never spoke to the principal's infrastructure. If 150.00
    succeeds, the bound existed only where it was written."""
    out = world.client.request_refund("ord-2", OVER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert out["refunded_micros"] == 0
    assert world.service.refunded_total_micros == 0


# ---------------------------------------------------------------------------
# 3. Expiry
# ---------------------------------------------------------------------------


def _expired_client(world):
    now = int(time.time())
    expired = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[max_amount_micros(LIMIT)],
        issued_at=now - 7200,
        expires_at=now - 3600,
    )
    return RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [expired]
    )


def test_expired_delegation_is_denied(world):
    """WHY: authority must lapse without requiring the receiver to reach a
    status source. Expiry is the only bound that holds when the receiver is
    offline, which is why short windows matter."""
    out = _expired_client(world).request_refund("ord-3", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "expired"
    assert out["reason"] == "delegation_expired"
    assert world.service.refunded_total_micros == 0


# ---------------------------------------------------------------------------
# 4. Revocation, by signed status
# ---------------------------------------------------------------------------


def test_revoked_delegation_is_denied(world):
    """WHY: a principal must be able to withdraw authority before it expires
    naturally, the response to a compromised agent. In v2 the withdrawal is a
    signed status object under the principal's status key, which the receiver
    verifies and journals before it derives a status."""
    assert world.client.request_refund("ord-4a", UNDER)["decision"] == "authorized"

    world.status.revoke(world.cert.cert_id, int(time.time()))
    out = world.client.request_refund("ord-4b", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "revoked"
    assert out["reason"] == "delegation_revoked"
    assert world.service.refunded_total_micros == UNDER  # only the pre-revocation refund


def test_status_feed_failure_fails_closed(world):
    """WHY: a status source that is down must not read as 'not revoked'.
    Fail-open here would mean an attacker who can disrupt the status feed has
    silently un-revoked every certificate."""
    world.service.break_status_feed("status feed unreachable")

    out = world.client.request_refund("ord-5", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "authorization_unverified"
    assert out["reason"] == "status_unavailable"
    assert world.service.refunded_total_micros == 0


def test_status_signed_by_any_other_key_cannot_unrevoke(world):
    """WHY: v1 took revocation from an injected callback, so whoever
    controlled the callback controlled revocation. In v2 the receiver accepts
    status only under the status key it configured for this principal. An
    attacker who controls the feed and signs a clean list with a key of its
    own must not be able to resurrect a revoked delegation."""
    world.status.revoke(world.cert.cert_id, int(time.time()))
    assert world.client.request_refund("ord-5a", UNDER)["status"] == "revoked"

    forged = StatusAuthority(world.principal, int(time.time()) + 2)  # another status key
    world.service.status.source = forged

    out = world.client.request_refund("ord-5b", UNDER)

    assert out["decision"] == "denied"
    assert world.service.refunded_total_micros == 0


def test_stale_status_fails_closed(world):
    """WHY: a signed list says what was true when it was signed. A principal
    that stops publishing must not leave its delegations valid forever, so a
    list past the receiver's freshness window is not current status. A list
    that is already expired when it arrives is never journaled at all, so
    there is no status to rely on and the decision is status_unavailable."""
    stale = StatusAuthority(world.principal, int(time.time()) - 7200)
    service = RefundService(world.principal.public_key, stale.status_pub, stale)
    server, base_url = serve(service)
    try:
        client = RefundClient(
            base_url, world.agent.id, world.agent.public_key, world.agent_priv, [world.cert]
        )
        out = client.request_refund("ord-stale", UNDER)
    finally:
        server.shutdown()

    assert out["decision"] == "denied"
    assert out["status"] == "authorization_unverified"
    assert out["reason"] == "status_unavailable"
    assert service.refunded_total_micros == 0


# ---------------------------------------------------------------------------
# 5. The proof is not a bearer token
# ---------------------------------------------------------------------------


def test_stolen_delegation_presented_by_another_key_is_refused(world):
    """WHY: if a leaked certificate were replayable by whoever holds it, the
    delegation would be a bearer token and exfiltration from the agent's
    runtime would be total compromise. Authority is bound to a key the thief
    does not have.

    v2 refuses both shapes before any claim, so neither writes a receipt:
    (a) the thief's own key with the stolen certificate breaks chain linkage;
    (b) the legitimate agent's identity signed with the thief's key fails the
    challenge signature."""
    thief, thief_priv = new_agent("thief")
    thief_client = RefundClient(
        world.base_url, thief.id, thief.public_key, thief_priv, [world.cert]
    )

    ch = thief_client.fetch_challenge("ord-6a", UNDER)
    proof = forge_presentation(
        thief.id, thief.public_key, thief_priv, [world.cert], ch, ch["session_context"]
    )
    out_a = present(world, ch["challenge"], proof)
    assert out_a["decision"] == "denied"
    assert out_a["reason"].startswith("chain_linkage_mismatch")
    assert out_a["receipt_id"] == ""

    ch = world.client.fetch_challenge("ord-6b", UNDER)
    proof = forge_presentation(
        world.agent.id, world.agent.public_key, thief_priv, [world.cert], ch, ch["session_context"]
    )
    out_b = present(world, ch["challenge"], proof)
    assert out_b["decision"] == "denied"
    assert out_b["reason"].startswith("invalid_signature")  # never proved possession
    assert out_b["receipt_id"] == ""

    assert world.service.receipts == []
    assert world.service.refunded_total_micros == 0


# ---------------------------------------------------------------------------
# 6. Replay
# ---------------------------------------------------------------------------


def test_replayed_challenge_is_denied(world):
    """WHY: a valid presentation captured on the wire must not be re-usable.
    Without single-use challenges, one observed 75.00 refund becomes
    unlimited 75.00 refunds. v2 claims the challenge atomically in the claim
    store; a second presentation is a replay and is never evaluated."""
    ch = world.client.fetch_challenge("ord-7", UNDER)
    proof = world.client.sign(ch)

    first = present(world, ch["challenge"], proof)
    second = present(world, ch["challenge"], proof)

    assert first["decision"] == "authorized"
    assert second["decision"] == "denied"
    assert second["reason"].startswith("claim_replay")  # refused by the claim store
    assert second["receipt_id"] == ""
    assert world.service.refunded_total_micros == UNDER  # replay moved no money


# ---------------------------------------------------------------------------
# 7. Request substitution
# ---------------------------------------------------------------------------


def test_amount_claimed_at_execution_time_is_ignored(world):
    """WHY: the receiver must authorize what it parsed, not what the agent
    asserts at execution time. If the phase-2 body could restate the amount,
    an agent would obtain a challenge for a small refund and cash it for a
    large one."""
    ch = world.client.fetch_challenge("ord-8", UNDER)

    out = present(world, ch["challenge"], world.client.sign(ch), amount_micros=OVER)

    assert out["decision"] == "authorized"
    assert out["refunded_micros"] == UNDER  # the receiver's own parse, not the claim
    assert world.service.refunded_total_micros == UNDER


def test_proof_bound_to_one_operation_cannot_authorize_another(world):
    """WHY: binding the session but not the operation would let an
    intermediary attach a cryptographically valid proof to a different action
    inside the same session. The challenge is bound to the receiver's
    canonical description of *this* operation."""
    ch_small = world.client.fetch_challenge("ord-9a", UNDER)
    ch_large = world.client.fetch_challenge("ord-9b", UNDER)

    # Sign the small operation's challenge under the large operation's binding.
    proof = world.client.sign({**ch_small, "session_context": ch_large["session_context"]})
    out = present(world, ch_small["challenge"], proof)

    assert out["decision"] == "denied"
    # Denied by the binding itself, in preflight: no claim, no receipt.
    assert out["reason"].startswith("session_context_mismatch")
    assert out["receipt_id"] == ""
    assert world.service.receipts == []
    assert world.service.refunded_total_micros == 0


def test_a_challenge_issued_to_one_agent_cannot_be_spent_by_another(world):
    """WHY: the challenge is issued to one agent's complete key. If it were
    not, a second agent holding its own valid delegation could race for a
    challenge issued to the first and spend it, and the challenge would be a
    bearer nonce. The second agent here is legitimately delegated, so this
    isolates the binding: the only thing wrong is *whose* challenge it is."""
    other, other_priv = new_agent("other-agent")
    now = int(time.time())
    other_cert = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=other.id,
        subject_pub=other.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[max_amount_micros(LIMIT)],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    ch = world.client.fetch_challenge("ord-20", UNDER)  # issued to the first agent
    other_client = RefundClient(world.base_url, other.id, other.public_key, other_priv, [other_cert])

    out = present(world, ch["challenge"], other_client.sign(ch))

    assert out["decision"] == "denied"
    assert out["reason"].startswith("expected_agent_mismatch")
    assert world.service.refunded_total_micros == 0


def _order_bound_client(world, resource_id, extra_constraints=()):
    """A delegation whose authority is bound to one named resource.

    ``resource_id`` is the *canonical* tenant-qualified name, because the
    protocol compares it by exact byte equality and never normalizes."""
    now = int(time.time())
    cert = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[max_amount_micros(LIMIT), resource_bound(resource_id), *extra_constraints],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    return RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [cert]
    )


def test_resource_bound_delegation_authorizes_only_the_named_order(world):
    """WHY: 'refund up to 100.00' and 'refund up to 100.00 for this order' are
    very different grants. Without resource binding, an agent authorized to
    refund one customer's order can refund every order under the same
    ceiling, one at a time. The identifier is compared byte for byte against
    the receiver's own canonicalized parse."""
    client = _order_bound_client(world, canonical_resource_id("acme", "ord-30"))

    allowed = client.request_refund("ord-30", UNDER)
    denied = client.request_refund("ord-30-different", UNDER)

    assert allowed["decision"] == "authorized"
    assert denied["decision"] == "denied"
    assert denied["status"] == "constraint_denied"
    assert world.service.refunded_total_micros == UNDER  # only the authorized order


def test_same_order_number_in_a_different_tenant_is_denied(world):
    """WHY: two tenants can each have an order numbered 8841. A delegation
    naming a bare '8841' would authorize both, which is a cross-tenant
    authorization bug that looks correct in every log. resource_id is an
    opaque string compared by exact byte equality, so qualifying it is the
    application's job. This asserts the receiver qualifies."""
    other_tenant_grant = _order_bound_client(world, canonical_resource_id("globex", "8841"))

    out = other_tenant_grant.request_refund("8841", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert world.service.refunded_total_micros == 0


@pytest.mark.parametrize(
    "order_id",
    ["../../etc/passwd", "ord 30", "ord/30", "", "-leading-hyphen", "x" * 65],
    ids=["traversal", "space", "slash", "empty", "bad_start", "too_long"],
)
def test_noncanonical_order_ids_are_rejected_before_a_challenge_is_issued(world, order_id):
    """WHY: canonicalization only works if exactly one spelling is accepted.
    Rejecting at the door keeps one resource to one name."""
    status, _ = post_raw(
        world.base_url + "/refunds/challenge", _challenge_body(world, order_id=order_id)
    )

    assert status == 400
    assert not world.service.receipts


def test_session_binding_and_constraint_use_the_same_canonical_identifier(world):
    """WHY: the operation context binds the challenge to a resource, and the
    constraint context evaluates the constraint against a resource. If those
    two could differ, an agent could obtain a challenge bound to one order and
    satisfy a constraint naming another. Both are derived once, at phase 1."""
    canonical = canonical_resource_id("acme", "ord-32")
    client = _order_bound_client(world, canonical)

    echoed = client.fetch_challenge("ord-32", UNDER)["parsed"]["resource_id"]
    assert echoed == canonical

    assert client.present(client.fetch_challenge("ord-32", UNDER))["decision"] == "authorized"


def test_resource_constraint_fails_closed_without_resource_context(world, monkeypatch):
    """WHY: a verifier that silently passes a constraint it cannot evaluate is
    worse than one that has no constraint at all, because the certificate
    reads as if it were enforced. A resource_path constraint evaluated without
    resource context must be unverifiable, not satisfied. The receiver always
    supplies the context; this removes it to assert the protocol's behaviour."""
    import refund_service

    def without_resource(**kwargs):
        kwargs.update(requested_resource_id="", has_resource=False)
        return ConstraintContextV2(**kwargs)

    monkeypatch.setattr(refund_service, "ConstraintContextV2", without_resource)
    client = _order_bound_client(world, canonical_resource_id("acme", "ord-31"))

    out = client.request_refund("ord-31", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_unverifiable"
    assert world.service.refunded_total_micros == 0


def test_chain_must_terminate_at_the_configured_trust_root(world):
    """WHY: verification proves a chain is internally consistent, not that it
    is *yours*. An attacker can mint a perfectly valid root and delegate to
    itself. Without anchoring to a configured principal, that self-issued
    chain verifies flawlessly and authorizes itself."""
    attacker, attacker_priv = new_principal()
    now = int(time.time())
    self_issued = sign_cert(
        issuer_id=attacker.id,
        issuer_pub=attacker.public_key,
        issuer_priv=attacker_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    client = RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [self_issued]
    )

    out = client.request_refund("ord-19", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "unauthorized"
    assert world.service.receipts[-1].trust_assessment == "untrusted"
    assert world.service.refunded_total_micros == 0


# ---------------------------------------------------------------------------
# 8 & 9. Subdelegation non-amplification
# ---------------------------------------------------------------------------


def _subdelegated(world, child_scope, child_constraints, parent_scope=None):
    """Principal -> agent (may delegate) -> sub-agent. Returns a client for the sub-agent."""
    now = int(time.time())
    parent = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=parent_scope or [SCOPE_PAYMENTS_SEND, SCOPE_IDENTITY_DELEGATE],
        constraints=[max_amount_micros(LIMIT)],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    # The agent is now an issuer too. v2 evaluates status per issuer, so the
    # agent publishes signed status under its own status key and the receiver
    # configures it; without that the chain fails closed as status_unavailable.
    agent_status = StatusAuthority(world.agent, now)
    world.service.configure_issuer_status(
        world.agent.public_key, agent_status.status_pub, agent_status
    )
    sub, sub_priv = new_agent("sub-agent")
    child = sign_cert(
        issuer_id=world.agent.id,
        issuer_pub=world.agent.public_key,
        issuer_priv=world.agent_priv,
        subject_id=sub.id,
        subject_pub=sub.public_key,
        scope=child_scope,
        constraints=child_constraints,
        issued_at=now - 30,
        expires_at=now + DAY,
    )
    # Chain order is [leaf, ... root].
    return RefundClient(world.base_url, sub.id, sub.public_key, sub_priv, [child, parent])


def test_child_cannot_grant_a_scope_the_parent_never_held(world):
    """WHY: non-amplification. A delegate must not be able to hand onward
    authority it was never given. The parent may receive payments and may
    delegate, but was never granted the authority to *send*; the child claims
    it anyway. The amplified scope never enters the effective set."""
    client = _subdelegated(
        world,
        child_scope=[SCOPE_PAYMENTS_SEND],  # claimed, but the parent never held it
        child_constraints=[max_amount_micros(LIMIT)],
        parent_scope=[SCOPE_PAYMENTS_RECEIVE, SCOPE_IDENTITY_DELEGATE],
    )

    out = client.request_refund("ord-10", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "scope_denied"
    assert world.service.refunded_total_micros == 0


def test_child_cannot_raise_the_parents_amount_ceiling(world):
    """WHY: bounds must compose downward only. If a delegate could widen a
    monetary ceiling when subdelegating, the principal's 100.00 limit would be
    advisory the moment the agent delegated onward."""
    client = _subdelegated(
        world,
        child_scope=[SCOPE_PAYMENTS_SEND],
        child_constraints=[max_amount_micros(10 * LIMIT)],  # ten times the parent
    )

    out = client.request_refund("ord-11", OVER)  # under the child, over the parent

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert world.service.refunded_total_micros == 0


def test_intermediate_issuer_without_configured_status_fails_closed(world):
    """WHY: status is per issuer. A chain that passes through an issuer the
    receiver has no status key for cannot prove that issuer has not revoked
    its delegation, so it must not authorize, however valid it looks."""
    now = int(time.time())
    parent = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND, SCOPE_IDENTITY_DELEGATE],
        constraints=[max_amount_micros(LIMIT)],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    sub, sub_priv = new_agent("sub-agent")
    child = sign_cert(
        issuer_id=world.agent.id,
        issuer_pub=world.agent.public_key,
        issuer_priv=world.agent_priv,
        subject_id=sub.id,
        subject_pub=sub.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[max_amount_micros(LIMIT)],
        issued_at=now - 30,
        expires_at=now + DAY,
    )
    client = RefundClient(world.base_url, sub.id, sub.public_key, sub_priv, [child, parent])

    out = client.request_refund("ord-12a", UNDER)

    assert out["decision"] == "denied"
    assert out["reason"] == "status_unavailable"
    assert world.service.refunded_total_micros == 0


def test_subdelegation_without_delegate_scope_is_denied(world):
    """WHY: the ability to delegate onward is itself a privilege. If any
    delegate could subdelegate by default, authority would spread without the
    principal ever consenting to it."""
    client = _subdelegated(
        world,
        child_scope=[SCOPE_PAYMENTS_SEND],
        child_constraints=[max_amount_micros(LIMIT)],
        parent_scope=[SCOPE_PAYMENTS_SEND],  # identity:delegate withheld
    )

    out = client.request_refund("ord-12", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "delegation_not_authorized"


# ---------------------------------------------------------------------------
# 10. Receipts, log, checkpoint
# ---------------------------------------------------------------------------


def _verify_log(world):
    """Verify every receipt against the verifier key and the log position."""
    head = ReceiptV2Head(log_id=LOG_ID, verifier_id=world.service.verifier_id)
    for receipt in world.service.receipts:
        verify_verification_receipt_v2(receipt, world.service.verifier_pub, head)
        digest = verification_receipt_v2_digest(receipt)
        head = replace(
            head,
            sequence=receipt.sequence,
            head_hash=digest,
            accepted_digests={**head.accepted_digests, receipt.sequence: digest},
        )
    return head


def test_every_decision_produces_a_verifiable_bound_receipt(world):
    """WHY: a receipt is a verifier-signed assertion of what it decided,
    bound by bundle_hash to the exact presentation it saw. A log line is an
    assertion; this is an artifact a disputing party can check against the
    proof itself."""
    world.client.request_refund("ord-13", UNDER)
    world.client.request_refund("ord-14", OVER)

    assert len(world.service.receipts) == 2
    _verify_log(world)

    approved, denied = world.service.receipts
    assert (approved.decision, approved.decision_reason) == ("allow", "authorized")
    assert (denied.decision, denied.decision_reason) == ("deny", "constraint_denied")

    # Bound to the presentation, not merely adjacent to it.
    check_verification_receipt_v2_bundle_binding(
        approved, decode_proof_bundle_v2(world.service.presented[0])
    )
    check_verification_receipt_v2_bundle_binding(
        denied, decode_proof_bundle_v2(world.service.presented[1])
    )


def test_receipts_chain_and_every_entry_is_acknowledged(world):
    """WHY: individually signed receipts still permit a verifier to quietly
    drop an inconvenient decision. v2 receipts carry a log sequence and the
    previous receipt's digest, so modification, interior removal, reordering
    and forking are detectable, and each entry is released only after a
    checkpoint acknowledges it.

    The checkpoint here is the SDK's reference store, in the same process and
    failure domain as the verifier. That is development only: tail truncation
    is caught only by an *independent* checkpoint or witness, which a
    production deployment must supply."""
    for i in range(3):
        world.client.request_refund(f"ord-15-{i}", UNDER)

    receipts = world.service.receipts
    assert [r.sequence for r in receipts] == [1, 2, 3]
    assert receipts[0].previous_receipt_hash == ZERO_HASH  # genesis
    for earlier, later in zip(receipts, receipts[1:]):
        assert later.previous_receipt_hash == verification_receipt_v2_digest(earlier)
    assert [a.sequence for a in world.service.acknowledgements] == [1, 2, 3]
    _verify_log(world)


def test_concurrent_decisions_produce_one_unbroken_receipt_chain(world):
    """WHY: the chain is only tamper-evident if it is actually a chain.
    Requests are served concurrently; two decisions that both linked to the
    same predecessor would fork the log. The refund ledger shares the
    critical section, since a lost update there would mean money moved with no
    record of it."""
    count = 12
    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(
            pool.map(lambda i: world.client.request_refund(f"ord-c{i}", UNDER), range(count))
        )

    assert all(r["decision"] == "authorized" for r in results)
    assert world.service.refunded_total_micros == UNDER * count  # no lost updates

    receipts = world.service.receipts
    assert [r.sequence for r in receipts] == list(range(1, count + 1))
    prevs = [r.previous_receipt_hash for r in receipts]
    assert len(set(prevs)) == len(prevs)
    _verify_log(world)


def test_unauthenticated_traffic_cannot_grow_the_signed_receipt_log(world):
    """WHY: the receipt log is an authorization audit trail. If an
    unauthenticated caller can make the verifier append signed entries, they
    hold a write primitive into it. Below the claim, nothing is signed."""
    forger, forger_priv = new_agent("forger")
    for i in range(25):
        fake = {
            "challenge": bytes([i]) * 32,
            "issued_at": int(time.time()),
            "verifier_id": world.service.verifier_id,
        }
        present(
            world,
            fake["challenge"],
            forge_presentation(forger.id, forger.public_key, forger_priv, [], fake, None),
        )

    assert world.service.receipts == []  # nothing signed
    assert len(world.service.refusals) == 25  # all in the operational log
    assert world.service.refunded_total_micros == 0

    # And a legitimate call still works afterwards, landing at log genesis.
    assert world.client.request_refund("ord-21", UNDER)["decision"] == "authorized"
    assert [r.sequence for r in world.service.receipts] == [1]


def test_one_challenge_yields_at_most_one_receipt(world):
    """WHY: a denied presentation must not be replayable to append a fresh
    signed receipt every time. The claim is made before evaluation, so a
    challenge reaches a committed result once and only once."""
    client = _expired_client(world)
    ch = client.fetch_challenge("ord-22", UNDER)

    first = client.present(ch)
    replays = [client.present(ch) for _ in range(5)]

    assert first["status"] == "expired"
    assert all(r["decision"] == "denied" and r["receipt_id"] == "" for r in replays)
    assert len(world.service.receipts) == 1  # one challenge, one receipt


def test_one_challenge_presented_concurrently_is_claimed_exactly_once(world):
    """WHY: the claim has to be atomic, not a read-then-delete. Several
    threads can all present the same valid proof; exactly one may win, or one
    authorized action moves money several times."""
    ch = world.client.fetch_challenge("ord-23", UNDER)
    proof = world.client.sign(ch)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: present(world, ch["challenge"], proof), range(8)))

    authorized = [r for r in results if r["decision"] == "authorized"]
    assert len(authorized) == 1
    assert world.service.refunded_total_micros == UNDER  # paid once, not eight times
    assert len(world.service.receipts) == 1


def test_a_captured_presentation_cannot_be_replayed_under_a_new_challenge(world):
    """WHY: a presentation is a claim about one specific challenge. The
    receiver loads its issuance record by the *outer* challenge it is handed,
    so a captured proof resubmitted under a freshly issued challenge fails
    preflight as challenge_mismatch, writes nothing, and leaves the victim's
    new challenge intact."""
    ch_a = world.client.fetch_challenge("ord-25a", UNDER)
    captured = world.client.sign(ch_a)
    assert present(world, ch_a["challenge"], captured)["decision"] == "authorized"
    receipts_before = len(world.service.receipts)

    ch_b = world.client.fetch_challenge("ord-25b", UNDER)
    out = present(world, ch_b["challenge"], captured)

    assert out["decision"] == "denied"
    assert out["reason"].startswith("challenge_mismatch")
    assert out["receipt_id"] == ""
    assert len(world.service.receipts) == receipts_before

    assert world.client.present(ch_b)["decision"] == "authorized"
    assert world.service.refunded_total_micros == UNDER * 2


def test_a_failed_presentation_does_not_burn_the_legitimate_challenge(world):
    """WHY: the claim must happen *after* proof of possession, not before.
    If an unauthenticated presentation retired the challenge, anyone could
    grief a legitimate agent by firing a garbage proof at its challenge."""
    ch = world.client.fetch_challenge("ord-24", UNDER)
    impostor, impostor_priv = new_agent("impostor")
    bad = forge_presentation(
        world.agent.id, world.agent.public_key, impostor_priv, [world.cert], ch, ch["session_context"]
    )
    assert present(world, ch["challenge"], bad)["decision"] == "denied"

    assert world.client.present(ch)["decision"] == "authorized"
    assert world.service.refunded_total_micros == UNDER


def test_empty_delegation_chain_is_a_signed_denial(world):
    """WHY: a presentation carrying no certificates claims no authority, and
    must be denied rather than raise. Proof of possession succeeded, so an
    authenticated presenter made a failed claim of authority, which is a real
    authorization outcome and belongs in the log."""
    client = RefundClient(world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [])

    out = client.request_refund("ord-26", UNDER)

    assert out["decision"] == "denied"
    assert out["reason"] == "not_delegated"
    assert out["receipt_id"]  # authenticated -> signed
    assert len(world.service.receipts) == 1
    assert world.service.refunded_total_micros == 0


def test_internal_failure_fails_closed_without_leaking_or_refunding(world, monkeypatch):
    """WHY: an error path is an information-disclosure surface and a state
    hazard at once. It must not return a traceback, must not move money, and
    must not hand back the challenge it already claimed. The caller learns
    only that the receiver failed closed. The committed decision stays in the
    receipt log.

    The limit, honestly: this is an in-memory demonstration, not a payment
    ledger. A production financial service needs durable transactions and
    idempotency keys, which this deliberately does not implement."""
    import refund_service

    def boom(*args, **kwargs):
        raise RuntimeError("release internals: /secret/path key=0xdeadbeef")

    monkeypatch.setattr(refund_service, "release_v2_decision", boom)

    ch = world.client.fetch_challenge("ord-27", UNDER)
    proof = world.client.sign(ch)
    status, body = post_raw(
        world.base_url + "/refunds",
        json.dumps(
            {
                "challenge": base64.b64encode(ch["challenge"]).decode(),
                "proof": base64.b64encode(proof).decode(),
            }
        ).encode(),
    )

    assert status == 500
    assert body["decision"] == "denied"
    assert body["status"] == "receiver_error"
    serialized = json.dumps(body)
    for leak in ("RuntimeError", "secret", "deadbeef", "Traceback", "release"):
        assert leak not in serialized
    assert world.service.refunded_total_micros == 0
    assert world.service.internal_errors == 1
    assert len(world.service.receipts) == 1  # the committed decision is on record

    # The claimed challenge is gone for good, not restored on the error path.
    monkeypatch.undo()
    retry = present(world, ch["challenge"], proof)
    assert retry["decision"] == "denied"
    assert world.service.refunded_total_micros == 0


def test_denial_receipts_record_assessments_not_an_unearned_identity(world):
    """WHY: a receipt for a failed presentation must not read as though a
    named principal authorized something. v2 records the agent only because
    proof of possession was verified before the claim; it never asserts a
    principal, grants no scope on a denial, and states each assessment it
    actually completed (here: the chain's root was untrusted)."""
    attacker, attacker_priv = new_principal()
    now = int(time.time())
    self_issued = sign_cert(
        issuer_id=attacker.id,
        issuer_pub=attacker.public_key,
        issuer_priv=attacker_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [self_issued]
    ).request_refund("ord-16", UNDER)

    receipt = world.service.receipts[-1]
    assert receipt.decision == "deny"
    assert receipt.trust_assessment == "untrusted"
    assert receipt.human_id == ""
    assert not receipt.granted_scope
    assert receipt.agent_id == world.agent.id  # proven by the challenge signature


def test_successful_receipt_records_what_was_verified(world):
    """WHY: the counterpart to the test above. An allow receipt must carry the
    verified agent, the issuers, the granted scope and every assessment, or it
    has no audit value at all."""
    world.client.request_refund("ord-17", UNDER)

    receipt = world.service.receipts[-1]
    assert receipt.decision == "allow"
    assert receipt.agent_id == world.agent.id
    assert receipt.issuer_ids == [world.principal.id]
    assert REQUIRED_SCOPE in receipt.granted_scope
    assert (receipt.trust_assessment, receipt.status_assessment, receipt.context_assessment) == (
        "trusted",
        "current",
        "bound",
    )


# ---------------------------------------------------------------------------
# The receiver is the gate
# ---------------------------------------------------------------------------


def test_request_without_any_proof_is_denied(world):
    """WHY: the receiver must refuse an unproven request outright. This is
    what makes agent-side presentation non-security-critical, an agent that
    skips presentation gains nothing."""
    ch = world.client.fetch_challenge("ord-18", UNDER)
    out = post_json(world.base_url + "/refunds", {"challenge": ch["challenge"]})

    assert out["decision"] == "denied"
    assert world.service.refunded_total_micros == 0
