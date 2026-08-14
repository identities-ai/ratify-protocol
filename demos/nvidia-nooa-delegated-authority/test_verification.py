# SPDX-License-Identifier: Apache-2.0
"""Deterministic security tests for the delegated-authority reference.

No LLM, no NOOA, no network beyond loopback. Every test states *why* the
behaviour matters, because a test that only records what the code does today
cannot fail when the security property regresses.

The scenario throughout: a principal delegates "issue refunds up to $100 USD,
for 24 hours" to one agent key. A refund service operated by a *different*
party verifies that delegation before moving money.

Amounts are 75 and 150 against a limit of 100, exactly separated so the
float representation used by the protocol's ``max_amount`` constraint cannot
make an assertion ambiguous. Production financial integrations should carry
canonical decimal or integer minor-unit amounts; that is out of scope here and
is not a redesign this reference proposes.
"""

from __future__ import annotations

import time
import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest
from ratify_protocol import (
    Constraint,
    ProofBundle,
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_SEND,
    build_session_context,
    bundle_hash,
    generate_agent,
    receipt_hash,
    sign_challenge,
    verify_verification_receipt,
)

from agent_client import RefundClient, post_json
from principal import new_agent, new_principal, sign_cert
from refund_service import REQUIRED_SCOPE, RefundService, canonical_resource_id, serve

LIMIT = 100.0
UNDER = 75.0
OVER = 150.0
DAY = 24 * 3600


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def world():
    """A principal, an agent, a running refund service, and a client."""
    principal, principal_priv = new_principal()
    agent, agent_priv = new_agent("refund-agent")

    now = int(time.time())
    cert = sign_cert(
        issuer_id=principal.id,
        issuer_pub=principal.public_key,
        issuer_priv=principal_priv,
        subject_id=agent.id,
        subject_pub=agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        issued_at=now - 60,
        expires_at=now + DAY,
    )

    service = RefundService(trust_root=principal.public_key)
    server, base_url = serve(service)
    client = RefundClient(base_url, agent.id, agent.public_key, agent_priv, [cert])
    try:
        yield _World(
            principal, principal_priv, agent, agent_priv, cert, service, base_url, client
        )
    finally:
        server.shutdown()


class _World:
    def __init__(
        self, principal, principal_priv, agent, agent_priv, cert, service, base_url, client
    ):
        self.principal = principal
        self.principal_priv = principal_priv
        self.agent = agent
        self.agent_priv = agent_priv
        self.cert = cert
        self.service = service
        self.base_url = base_url
        self.client = client


def build_bundle(
    agent_id, agent_pub, agent_priv, delegations, challenge, session_context, at=None
):
    """Construct a proof bundle by hand.

    Adversarial tests build bundles directly rather than through the client, so
    that the client stays free of attack knobs it would never have in practice.
    """
    at = at if at is not None else int(time.time())
    return ProofBundle(
        agent_id=agent_id,
        agent_pub_key=agent_pub,
        delegations=list(delegations),
        challenge=challenge,
        challenge_at=at,
        challenge_sig=sign_challenge(challenge, at, agent_priv, session_context),
        session_context=session_context,
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


# ---------------------------------------------------------------------------
# 0. Business inputs the verifier cannot safely reason about
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "literal",
    ["NaN", "Infinity", "-Infinity"],
    ids=["nan", "positive_infinity", "negative_infinity"],
)
def test_non_finite_amounts_are_rejected_at_the_boundary(world, literal):
    """WHY: this is an authorization bypass, not input hygiene.

    ``max_amount`` is enforced as ``requested_amount > max_amount``, and every
    ordered comparison against NaN is false, so a NaN amount satisfies any
    ceiling and authorizes an unbounded refund. Python's json module accepts a
    bare NaN literal, so any caller can reach it. Negative infinity slips
    through identically. Before this check existed, a NaN request came back
    ``authorized`` and poisoned the ledger total to NaN permanently.
    """
    raw = (
        '{"order_id":"ord-nan","amount":%s,"currency":"USD","agent_id":"%s"}'
        % (literal, world.agent.id)
    ).encode()

    status, body = post_raw(world.base_url + "/refunds/challenge", raw)

    assert status == 400
    assert "error" in body
    assert world.service.refunded_total == 0.0
    assert not world.service.receipts


@pytest.mark.parametrize(
    "amount",
    [-50.0, -0.01, 0.0, 0],
    ids=["negative", "tiny_negative", "zero_float", "zero_int"],
)
def test_non_positive_amounts_are_rejected(world, amount):
    """WHY: a negative refund is a charge, and it passes every ceiling check
    trivially because it is smaller than the maximum. Zero is refused
    deliberately, it is not a meaningful authorization decision, and allowing
    it hands callers a free way to probe verification outcomes."""
    status, body = post_raw(
        world.base_url + "/refunds/challenge",
        json.dumps(
            {
                "order_id": "ord-neg",
                "amount": amount,
                "currency": "USD",
                "agent_id": world.agent.id,
            }
        ).encode(),
    )

    assert status == 400
    assert world.service.refunded_total == 0.0


@pytest.mark.parametrize(
    "raw,label",
    [
        (b'{"order_id":"o","amount":"75","currency":"USD","agent_id":"a"}', "string_amount"),
        (b'{"order_id":"o","amount":true,"currency":"USD","agent_id":"a"}', "bool_amount"),
        (b'{"order_id":"o","amount":null,"currency":"USD","agent_id":"a"}', "null_amount"),
        (b'{"order_id":"o","amount":75,"currency":"US","agent_id":"a"}', "bad_currency"),
        (b'{"order_id":"","amount":75,"currency":"USD","agent_id":"a"}', "empty_order"),
        (b'{"order_id":"o","amount":75,"currency":"USD","agent_id":""}', "empty_agent"),
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
    assert world.service.refunded_total == 0.0
    assert not world.service.receipts


def test_invalid_challenge_encoding_is_rejected(world):
    """WHY: the challenge arrives base64-encoded. Undecodable input must be a
    clean rejection, not an exception escaping the handler."""
    status, _ = post_raw(
        world.base_url + "/refunds", json.dumps({"challenge": "!!!not-base64!!!"}).encode()
    )

    assert 400 <= status < 500
    assert not world.service.receipts


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
    assert out["refunded"] == UNDER
    assert world.service.refunded_total == UNDER


# ---------------------------------------------------------------------------
# 2. The principal's bound survives transit into another organization
# ---------------------------------------------------------------------------


def test_over_limit_refund_is_denied_by_the_principals_constraint(world):
    """WHY: this is the whole proposition. The $100 ceiling was expressed by
    the principal, in another organization, and is enforced by a receiver that
    never spoke to the principal's infrastructure. If $150 succeeds, the bound
    existed only where it was written and the delegation carried nothing."""
    out = world.client.request_refund("ord-2", OVER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert out["refunded"] == 0.0
    assert world.service.refunded_total == 0.0


# ---------------------------------------------------------------------------
# 3. Expiry
# ---------------------------------------------------------------------------


def test_expired_delegation_is_denied(world):
    """WHY: authority must lapse without requiring the receiver to reach a
    revocation service. Expiry is the only bound that holds when the receiver
    is offline, which is why short windows matter."""
    now = int(time.time())
    expired = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        issued_at=now - 7200,
        expires_at=now - 3600,
    )
    client = RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [expired]
    )

    out = client.request_refund("ord-3", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "expired"
    assert world.service.refunded_total == 0.0


# ---------------------------------------------------------------------------
# 4. Revocation
# ---------------------------------------------------------------------------


def test_revoked_delegation_is_denied(world):
    """WHY: a principal must be able to withdraw authority before it expires
    naturally, the response to a compromised agent. Expiry alone leaves a
    window an attacker fully controls."""
    assert world.client.request_refund("ord-4a", UNDER)["decision"] == "authorized"

    world.service.revoke(world.cert.cert_id)
    out = world.client.request_refund("ord-4b", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "revoked"
    assert world.service.refunded_total == UNDER  # only the pre-revocation refund


def test_revocation_lookup_failure_fails_closed(world):
    """WHY: a revocation source that is down must not read as 'not revoked'.
    Fail-open here would mean an attacker who can disrupt the revocation
    lookup has silently un-revoked every certificate."""
    world.service.break_revocation("registry unreachable")

    out = world.client.request_refund("ord-5", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] != "authorized_agent"
    assert "revocation" in out["reason"]
    assert world.service.refunded_total == 0.0


# ---------------------------------------------------------------------------
# 5. The proof is not a bearer token
# ---------------------------------------------------------------------------


def test_stolen_delegation_presented_by_another_key_is_denied(world):
    """WHY: if a leaked certificate were replayable by whoever holds it, the
    delegation would be a bearer token and exfiltration from the agent's
    runtime would be total compromise. Authority is bound to a key the thief
    does not have."""
    thief, thief_priv = generate_agent("thief", "agent")
    thief_client = RefundClient(
        world.base_url, thief.id, thief.public_key, thief_priv, [world.cert]
    )

    # (a) The thief plays it properly: requests a challenge under its *own*
    # identity, answers it correctly with its own key, and submits the stolen
    # certificate. Proof of possession therefore succeeds, the presentation
    # is authentically the thief's, and the delegation is what fails, because
    # the certificate names a subject key the thief does not hold.
    ch = thief_client.fetch_challenge("ord-6a", UNDER)
    bundle = build_bundle(
        thief.id,
        thief.public_key,
        thief_priv,
        [world.cert],
        ch["challenge"],
        ch["session_context"],
    )
    out_a = post_json(
        world.base_url + "/refunds", {"challenge": ch["challenge"], "bundle": bundle}
    )
    assert out_a["decision"] == "denied"
    assert out_a["status"] == "invalid"
    assert "key_mismatch" in out_a["reason"]  # the certificate is not the thief's to use
    # Authenticated presenter, so this denial *is* an authorization decision
    # and belongs in the signed chain.
    assert len(world.service.receipts) == 1

    # (b) The thief claims the legitimate agent's identity but cannot sign for it.
    ch = world.client.fetch_challenge("ord-6b", UNDER)
    bundle = build_bundle(
        world.agent.id,
        world.agent.public_key,
        thief_priv,  # wrong private key
        [world.cert],
        ch["challenge"],
        ch["session_context"],
    )
    out_b = post_json(
        world.base_url + "/refunds", {"challenge": ch["challenge"], "bundle": bundle}
    )
    assert out_b["decision"] == "denied"
    assert out_b["status"] == "invalid"
    assert "bad_challenge_sig" in out_b["reason"]  # never proved possession
    # Unauthenticated, so it must not have appended to the signed chain.
    assert len(world.service.receipts) == 1

    assert world.service.refunded_total == 0.0


# ---------------------------------------------------------------------------
# 6. Replay
# ---------------------------------------------------------------------------


def test_replayed_challenge_is_denied(world):
    """WHY: a valid presentation captured on the wire must not be re-usable.
    Without single-use challenges, one observed $75 refund becomes unlimited
    $75 refunds."""
    ch = world.client.fetch_challenge("ord-7", UNDER)
    bundle = build_bundle(
        world.agent.id,
        world.agent.public_key,
        world.agent_priv,
        [world.cert],
        ch["challenge"],
        ch["session_context"],
    )
    payload = {"challenge": ch["challenge"], "bundle": bundle}

    first = post_json(world.base_url + "/refunds", payload)
    second = post_json(world.base_url + "/refunds", payload)

    assert first["decision"] == "authorized"
    assert second["decision"] == "denied"
    assert world.service.refunded_total == UNDER  # replay moved no additional money


# ---------------------------------------------------------------------------
# 7. Request substitution
# ---------------------------------------------------------------------------


def test_amount_claimed_at_execution_time_is_ignored(world):
    """WHY: the receiver must authorize what it parsed, not what the agent
    asserts at execution time. If the phase-2 body could restate the amount,
    an agent would obtain a challenge for a small refund and cash it for a
    large one."""
    ch = world.client.fetch_challenge("ord-8", UNDER)
    bundle = build_bundle(
        world.agent.id,
        world.agent.public_key,
        world.agent_priv,
        [world.cert],
        ch["challenge"],
        ch["session_context"],
    )

    out = post_json(
        world.base_url + "/refunds",
        {"challenge": ch["challenge"], "bundle": bundle, "amount": OVER},
    )

    assert out["decision"] == "authorized"
    assert out["refunded"] == UNDER  # the receiver's own parse, not the claim
    assert world.service.refunded_total == UNDER


def test_proof_bound_to_one_operation_cannot_authorize_another(world):
    """WHY: binding the session but not the operation would let an
    intermediary attach a cryptographically valid proof to a different action
    inside the same session. The challenge is bound to the receiver's
    canonical description of *this* operation."""
    ch_small = world.client.fetch_challenge("ord-9a", UNDER)
    ch_large = world.client.fetch_challenge("ord-9b", UNDER)

    # Sign the small operation's challenge under the large operation's binding.
    bundle = build_bundle(
        world.agent.id,
        world.agent.public_key,
        world.agent_priv,
        [world.cert],
        ch_small["challenge"],
        ch_large["session_context"],
    )

    out = post_json(
        world.base_url + "/refunds", {"challenge": ch_small["challenge"], "bundle": bundle}
    )

    assert out["decision"] == "denied"
    # Denied by the binding itself, not by some incidental check downstream.
    # The receiver catches this at its own gate, comparing against the context
    # it holds, so the presentation never reaches verification and mints no
    # receipt. (verify_bundle would also reject it, as session_context_mismatch;
    # failing earlier means an attacker cannot use substitution to write to the
    # audit chain.)
    assert "session_binding_mismatch" in out["reason"]
    assert out["receipt_id"] == ""
    assert world.service.receipts == []
    assert world.service.refunded_total == 0.0


def test_a_challenge_issued_to_one_agent_cannot_be_spent_by_another(world):
    """WHY: the proposal claims the challenge is bound to the requesting agent
    through SessionContextInputs.agent_id. If it were not, a second agent
    holding its own valid delegation could race for a challenge issued to the
    first and spend it, the challenge would be a bearer nonce.

    The second agent here is legitimately delegated, so this isolates the
    binding: the only thing wrong is *whose* challenge it is."""
    other, other_priv = new_agent("other-agent")
    now = int(time.time())
    other_cert = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=other.id,
        subject_pub=other.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        issued_at=now - 60,
        expires_at=now + DAY,
    )

    # A challenge the service issued for the *first* agent.
    ch = world.client.fetch_challenge("ord-20", UNDER)

    bundle = build_bundle(
        other.id,
        other.public_key,
        other_priv,
        [other_cert],
        ch["challenge"],
        ch["session_context"],
    )
    out = post_json(
        world.base_url + "/refunds", {"challenge": ch["challenge"], "bundle": bundle}
    )

    assert out["decision"] == "denied"
    assert "challenge_agent_mismatch" in out["reason"]
    assert world.service.refunded_total == 0.0


def _order_bound_client(world, resource_id, extra_constraints=()):
    """A delegation whose authority is bound to one named resource (alpha.16).

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
        constraints=[
            Constraint(type="max_amount", max_amount=LIMIT, currency="USD"),
            Constraint(type="resource_path", resource_id=resource_id),
            *extra_constraints,
        ],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    return RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [cert]
    )


def test_resource_bound_delegation_authorizes_only_the_named_order(world):
    """WHY: 'refund up to $100' and 'refund up to $100 for this order' are very
    different grants. Without resource binding, an agent authorized to refund
    one customer's order can refund every order under the same ceiling, one at
    a time. Scope and amount alone do not express which *thing* the authority
    covers.

    Resource-bound authority (alpha.16) closes that. The identifier is
    compared byte-for-byte against the receiver's own canonicalized parse, so
    the agent cannot retarget the grant by restating the order at execution."""
    client = _order_bound_client(world, canonical_resource_id("acme", "ord-30"))

    allowed = client.request_refund("ord-30", UNDER)
    denied = client.request_refund("ord-30-different", UNDER)

    assert allowed["decision"] == "authorized"
    assert denied["decision"] == "denied"
    assert denied["status"] == "constraint_denied"
    assert "resource" in denied["reason"]
    assert world.service.refunded_total == UNDER  # only the authorized order paid


def test_same_order_number_in_a_different_tenant_is_denied(world):
    """WHY: two tenants can each have an order numbered 8841. A delegation
    naming a bare '8841' would authorize both, which is a cross-tenant
    authorization bug that looks correct in every log.

    The protocol will not save you here: SPEC 5.7.3 makes resource_id an
    opaque string compared by exact byte equality, with no normalization and
    no notion of tenancy. Qualifying the identifier is the application's job,
    and getting it wrong is silent. This asserts the receiver qualifies."""
    other_tenant_grant = _order_bound_client(
        world, canonical_resource_id("globex", "8841")
    )

    # The receiver serves tenant "acme", so it canonicalizes to
    # tenant/acme/orders/8841, which is not what the certificate names.
    out = other_tenant_grant.request_refund("8841", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert world.service.refunded_total == 0.0


@pytest.mark.parametrize(
    "order_id",
    ["../../etc/passwd", "ord 30", "ord/30", "", "-leading-hyphen", "x" * 65],
    ids=["traversal", "space", "slash", "empty", "bad_start", "too_long"],
)
def test_noncanonical_order_ids_are_rejected_before_a_challenge_is_issued(world, order_id):
    """WHY: canonicalization only works if exactly one spelling is accepted.
    If the receiver took an order id verbatim, an attacker could pick a
    spelling that collides with a different resource once embedded in the
    canonical form, or simply create a second name for the same order that no
    delegation covers. Rejecting at the door keeps one resource to one name."""
    status, _ = post_raw(
        world.base_url + "/refunds/challenge",
        json.dumps(
            {
                "order_id": order_id,
                "amount": UNDER,
                "currency": "USD",
                "agent_id": world.agent.id,
            }
        ).encode(),
    )

    assert status == 400
    assert not world.service.receipts


def test_session_binding_and_constraint_use_the_same_canonical_identifier(world):
    """WHY: the operation context binds the challenge to a resource, and the
    verifier context evaluates the constraint against a resource. If those two
    could differ, an agent could obtain a challenge bound to one order and
    satisfy a constraint naming another, and each half would look correct on
    its own.

    Both are derived once, at phase 1, from the same canonicalization."""
    canonical = canonical_resource_id("acme", "ord-32")
    client = _order_bound_client(world, canonical)

    echoed = client.fetch_challenge("ord-32", UNDER)["parsed"]["resource_id"]
    assert echoed == canonical

    assert client.present(client.fetch_challenge("ord-32", UNDER))["decision"] == "authorized"


def test_resource_constraint_fails_closed_without_resource_context(world):
    """WHY: a verifier that silently passes a constraint it cannot evaluate is
    worse than one that has no constraint at all, because the certificate
    reads as if it were enforced. A resource_path constraint evaluated without
    resource context must be unverifiable, not satisfied.

    The receiver always supplies the context, so this asserts the protocol's
    fail-closed behaviour rather than the receiver's: it is the property that
    makes the binding above trustworthy."""
    import time as _t

    from ratify_protocol import ProofBundle as _PB
    from ratify_protocol import generate_challenge, verify_bundle
    from ratify_protocol.types import VerifierContext, VerifyOptions

    now = int(_t.time())
    cert = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[Constraint(type="resource_path", resource_id="ord-31")],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    challenge = generate_challenge()
    bundle = _PB(
        agent_id=world.agent.id,
        agent_pub_key=world.agent.public_key,
        delegations=[cert],
        challenge=challenge,
        challenge_at=now,
        challenge_sig=sign_challenge(challenge, now, world.agent_priv),
    )

    result = verify_bundle(
        bundle,
        VerifyOptions(
            required_scope=SCOPE_PAYMENTS_SEND,
            context=VerifierContext(),  # no resource context at all
        ),
    )

    assert not result.valid
    assert result.identity_status == "constraint_unverifiable"


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
    assert "untrusted_root" in out["reason"]
    assert world.service.refunded_total == 0.0


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
        constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
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
        scope=child_scope,
        constraints=child_constraints,
        issued_at=now - 30,
        expires_at=now + DAY,
    )
    # Chain order is [leaf, ... root].
    return RefundClient(world.base_url, sub.id, sub.public_key, sub_priv, [child, parent])


def test_child_cannot_grant_a_scope_the_parent_never_held(world):
    """WHY: non-amplification. A delegate must not be able to hand onward
    authority it was never given, otherwise one honest delegation to a
    misbehaving agent reopens the entire scope vocabulary.

    The parent here may receive payments and may delegate, but was never
    granted the authority to *send*. The child certificate claims it anyway.
    The refund service requires payments:send, chosen by the service itself.

    Note the mechanism, which the proposal states precisely: the amplified
    scope is neutralised by intersection across the chain rather than the
    child certificate being rejected as malformed. What is asserted here is
    the security outcome, the amplified authority cannot be exercised."""
    client = _subdelegated(
        world,
        child_scope=[SCOPE_PAYMENTS_SEND],  # claimed, but the parent never held it
        child_constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        parent_scope=[SCOPE_PAYMENTS_RECEIVE, SCOPE_IDENTITY_DELEGATE],
    )

    out = client.request_refund("ord-10", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "scope_denied"
    assert world.service.refunded_total == 0.0


def test_child_cannot_raise_the_parents_amount_ceiling(world):
    """WHY: bounds must compose downward only. If a delegate could widen a
    monetary ceiling when subdelegating, the principal's $100 limit would be
    advisory the moment the agent delegated onward."""
    client = _subdelegated(
        world,
        child_scope=[SCOPE_PAYMENTS_SEND],
        child_constraints=[
            Constraint(
                type="max_amount", max_amount=1000.0, currency="USD"
            )  # ten times the parent
        ],
    )

    out = client.request_refund("ord-11", OVER)  # 150: under the child, over the parent

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert world.service.refunded_total == 0.0


def test_subdelegation_without_delegate_scope_is_denied(world):
    """WHY: the ability to delegate onward is itself a privilege. If any
    delegate could subdelegate by default, authority would spread without the
    principal ever consenting to it."""
    client = _subdelegated(
        world,
        child_scope=[SCOPE_PAYMENTS_SEND],
        child_constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        parent_scope=[SCOPE_PAYMENTS_SEND],  # identity:delegate withheld
    )

    out = client.request_refund("ord-12", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "delegation_not_authorized"


# ---------------------------------------------------------------------------
# 10. Receipts
# ---------------------------------------------------------------------------


def test_every_decision_produces_a_verifiable_bound_receipt(world):
    """WHY: a receipt is a verifier-signed assertion of
    what it decided, bound by bundle_hash to the exact presentation it saw. A
    log line is an assertion; this is an artifact a disputing party can check
    against the proof itself."""
    world.client.request_refund("ord-13", UNDER)
    world.client.request_refund("ord-14", OVER)

    assert len(world.service.receipts) == 2
    for receipt in world.service.receipts:
        assert verify_verification_receipt(receipt) is None

    approved, denied = world.service.receipts
    assert approved.decision == "authorized_agent"
    assert denied.decision == "constraint_denied"

    # Bound to the presentation, not merely adjacent to it.
    assert approved.bundle_hash == bundle_hash(world.service.presented[0])
    assert denied.bundle_hash == bundle_hash(world.service.presented[1])


def test_receipts_chain_so_interior_gaps_and_reordering_are_detectable(world):
    """WHY: individually signed receipts still permit a verifier to quietly
    drop an inconvenient decision. Chaining by prev_hash makes four things
    detectable within the verifier's own sequence: modification of a retained
    earlier receipt, removal from the middle when a later receipt is retained,
    reordering, and forking.

    It does NOT detect deletion of the final receipt, or truncation of the
    whole suffix, a chain cut short is internally consistent and verifies
    perfectly. Catching that needs something outside the verifier: a published
    checkpoint, a witness, a trusted counter, or another party holding a later
    chain head. The test name says "interior" for that reason.

    And none of this is independent attestation, the verifier signs its own
    history."""
    for i in range(3):
        world.client.request_refund(f"ord-15-{i}", UNDER)

    receipts = world.service.receipts
    assert len(receipts) == 3
    assert receipts[0].prev_hash == b"\x00" * 32  # genesis
    for earlier, later in zip(receipts, receipts[1:]):
        assert later.prev_hash == receipt_hash(earlier)


def test_concurrent_decisions_produce_one_unbroken_receipt_chain(world):
    """WHY: the chain is only tamper-evident if it is actually a chain.
    Requests are served concurrently, so issuing a receipt means reading the
    previous one and appending, indivisibly. Two decisions that both read
    the same predecessor would sign two receipts carrying the same prev_hash,
    forking the sequence: a later deletion could then be hidden in the fork
    and the property the receipt exists to provide would be gone.

    The refund ledger shares that critical section for the same reason,
    a lost update there would mean money moved with no record of it."""
    count = 12
    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(
            pool.map(lambda i: world.client.request_refund(f"ord-c{i}", UNDER), range(count))
        )

    assert all(r["decision"] == "authorized" for r in results)
    assert world.service.refunded_total == UNDER * count  # no lost updates

    receipts = world.service.receipts
    assert len(receipts) == count
    assert receipts[0].prev_hash == b"\x00" * 32
    for earlier, later in zip(receipts, receipts[1:]):
        assert later.prev_hash == receipt_hash(earlier)
    # A fork would show up as two receipts claiming the same predecessor.
    prevs = [r.prev_hash for r in receipts]
    assert len(set(prevs)) == len(prevs)


def test_unauthenticated_traffic_cannot_grow_the_signed_receipt_chain(world):
    """WHY: the receipt chain is an authorization audit trail. If an
    unauthenticated caller can make the verifier append signed entries, they
    hold a write primitive into it, they can bury real decisions in noise and
    grow the chain without bound, and every entry still verifies.

    The gate is proof of possession. Below it, nothing is signed; above it,
    the presenter demonstrably holds the agent key named in the receiver's own
    pending record."""
    forged = generate_agent("forger", "assistant")[0]

    # 25 fabricated presentations against a challenge that was never issued.
    for i in range(25):
        post_json(
            world.base_url + "/refunds",
            {
                "challenge": bytes([i]) * 32,
                "bundle": build_bundle(
                    forged.id,
                    forged.public_key,
                    world.agent_priv,
                    [world.cert],
                    bytes([i]) * 32,
                    b"",
                ),
            },
        )

    assert world.service.receipts == []  # nothing signed
    assert len(world.service.refusals) == 25  # all in the operational log
    assert world.service.refunded_total == 0.0

    # And a legitimate call still works afterwards, landing at chain genesis.
    assert world.client.request_refund("ord-21", UNDER)["decision"] == "authorized"
    assert len(world.service.receipts) == 1
    assert world.service.receipts[0].prev_hash == b"\x00" * 32


def test_one_challenge_yields_at_most_one_receipt(world):
    """WHY: expiry and revocation are evaluated *before* the SDK consumes the
    challenge, so a presentation denied on those grounds leaves the challenge
    unspent. Without the receiver retiring its own pending record, the same
    authenticated presentation could be replayed to append a fresh signed
    receipt every time, bounded only by the attacker's patience."""
    now = int(time.time())
    expired = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[],
        issued_at=now - 7200,
        expires_at=now - 3600,
    )
    client = RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [expired]
    )
    ch = client.fetch_challenge("ord-22", UNDER)

    first = client.present(ch)
    replays = [client.present(ch) for _ in range(5)]

    assert first["status"] == "expired"
    assert all(r["decision"] == "denied" for r in replays)
    assert len(world.service.receipts) == 1  # one challenge, one receipt


def test_one_challenge_presented_concurrently_is_claimed_exactly_once(world):
    """WHY: retiring the pending record has to be an atomic claim, not a
    read-then-delete. Requests are served concurrently, so several threads can
    all read the same record, all pass proof of possession, and all proceed,
    each appending a receipt and, worse, each moving money for a single
    authorized action. Exactly one presenter may win."""
    ch = world.client.fetch_challenge("ord-23", UNDER)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: world.client.present(ch), range(8)))

    authorized = [r for r in results if r["decision"] == "authorized"]
    assert len(authorized) == 1
    assert world.service.refunded_total == UNDER  # paid once, not eight times
    assert len(world.service.receipts) == 1  # one challenge, one receipt


def test_a_captured_presentation_cannot_be_replayed_under_a_new_challenge(world):
    """WHY: a presentation is a claim about one specific challenge. Verifying
    possession over the *bundle's own* copy of the challenge only proves the
    presenter once answered something, so a bundle captured from an earlier
    legitimate exchange could be resubmitted under a freshly issued challenge,
    authenticate, retire that challenge, and append a signed denial receipt.

    The victim is the legitimate agent: its brand-new challenge is burned
    before it can use it, and the audit trail gains an entry it did not cause.
    Everything the gate checks is therefore stated against receiver-held
    values, never the bundle's."""
    # 1. Capture a valid presentation for challenge A.
    ch_a = world.client.fetch_challenge("ord-25a", UNDER)
    captured = build_bundle(
        world.agent.id,
        world.agent.public_key,
        world.agent_priv,
        [world.cert],
        ch_a["challenge"],
        ch_a["session_context"],
    )
    assert world.client.present(ch_a)["decision"] == "authorized"
    receipts_before = len(world.service.receipts)

    # 2. A fresh challenge B is issued to the same agent.
    ch_b = world.client.fetch_challenge("ord-25b", UNDER)

    # 3. Submit outer challenge B carrying the captured bundle A.
    out = post_json(
        world.base_url + "/refunds", {"challenge": ch_b["challenge"], "bundle": captured}
    )

    # 4/5. An unsigned refusal, and nothing appended to the chain.
    assert out["decision"] == "denied"
    assert out["receipt_id"] == ""
    assert len(world.service.receipts) == receipts_before

    # 6/7. Challenge B was not retired, and its rightful holder can still use it.
    assert world.client.present(ch_b)["decision"] == "authorized"
    assert world.service.refunded_total == UNDER * 2


def test_a_failed_presentation_does_not_burn_the_legitimate_challenge(world):
    """WHY: the claim must happen *after* proof of possession, not before.
    If an unauthenticated presentation retired the pending record, anyone
    could grief a legitimate agent by firing a garbage bundle at its
    challenge and consuming it first."""
    ch = world.client.fetch_challenge("ord-24", UNDER)

    # An impostor answers the wrong way, using the right challenge.
    impostor, impostor_priv = generate_agent("impostor", "assistant")
    bad = build_bundle(
        world.agent.id,
        world.agent.public_key,
        impostor_priv,
        [world.cert],
        ch["challenge"],
        ch["session_context"],
    )
    refused = post_json(
        world.base_url + "/refunds", {"challenge": ch["challenge"], "bundle": bad}
    )
    assert refused["decision"] == "denied"

    # The rightful holder's challenge is untouched.
    assert world.client.present(ch)["decision"] == "authorized"
    assert world.service.refunded_total == UNDER


def test_empty_delegation_chain_is_denied_not_crashed(world):
    """WHY: a presentation carrying no certificates claims no authority, and
    must be denied rather than raise. The HTTP decoder rejects this shape, but
    RefundService is importable and a reviewer evaluating it as a library will
    call execute() directly, an IndexError there is a crash where a decision
    belongs.

    The denial is *signed*: proof of possession succeeded, so an authenticated
    presenter made a failed claim of authority, which is a real authorization
    outcome and belongs in the chain."""
    ch = world.client.fetch_challenge("ord-26", UNDER)
    at = int(time.time())
    empty = ProofBundle(
        agent_id=world.agent.id,
        agent_pub_key=world.agent.public_key,
        delegations=[],
        challenge=ch["challenge"],
        challenge_at=at,
        challenge_sig=sign_challenge(
            ch["challenge"], at, world.agent_priv, ch["session_context"]
        ),
        session_context=ch["session_context"],
    )

    out = world.service.execute(challenge=ch["challenge"], bundle=empty)

    assert out["decision"] == "denied"
    assert "no_delegations" in out["reason"]
    assert out["receipt_id"]  # authenticated -> signed
    assert len(world.service.receipts) == 1
    assert world.service.refunded_total == 0.0


def test_internal_failure_fails_closed_without_leaking_or_refunding(world, monkeypatch):
    """WHY: an error path is an information-disclosure surface and a state
    hazard at once. It must not return a traceback, must not move money, and
    must not hand back the challenge it already claimed, restoring it would
    reopen the replay window the atomic claim exists to close. The caller
    learns only that the receiver failed closed.

    Note the limit honestly: this is an in-memory demonstration, not a payment
    ledger. Money and the receipt are recorded in one critical section so the
    demo cannot pay out and then lose the record, but a production financial
    service needs durable transactions and idempotency keys, which this
    deliberately does not implement."""
    import refund_service

    def boom(*args, **kwargs):
        raise RuntimeError("verifier internals: /secret/path key=0xdeadbeef")

    monkeypatch.setattr(refund_service, "verify_bundle", boom)

    ch = world.client.fetch_challenge("ord-27", UNDER)
    at = int(time.time())
    bundle = build_bundle(
        world.agent.id,
        world.agent.public_key,
        world.agent_priv,
        [world.cert],
        ch["challenge"],
        ch["session_context"],
        at=at,
    )
    status, body = post_raw(
        world.base_url + "/refunds",
        json.dumps(
            {
                "challenge": __import__("base64").b64encode(ch["challenge"]).decode(),
                "bundle": json.loads(
                    __import__("ratify_protocol").wire.encode_proof_bundle(bundle)
                ),
            }
        ).encode(),
    )

    assert status == 500
    assert body["decision"] == "denied"
    assert body["status"] == "receiver_error"
    # Nothing internal escapes.
    serialized = json.dumps(body)
    for leak in ("RuntimeError", "secret", "deadbeef", "Traceback", "verify_bundle"):
        assert leak not in serialized
    assert world.service.refunded_total == 0.0
    assert world.service.receipts == []
    assert world.service.internal_errors == 1

    # The claimed challenge is gone for good, not restored on the error path.
    monkeypatch.undo()
    retry = world.client.present(ch)
    assert retry["decision"] == "denied"
    assert world.service.refunded_total == 0.0


def test_failure_receipts_do_not_assert_an_authenticated_identity(world):
    """WHY: a receipt for a *failed* presentation must not record the
    presenter's claimed identity as though it were established. Expiry and
    revocation are checked before the chain signature is verified, so the
    identifiers available at that point come from an unverified certificate.
    Emitting them would turn a denial record into an unearned attestation
    that a named principal and agent were present."""
    now = int(time.time())
    expired = sign_cert(
        issuer_id=world.principal.id,
        issuer_pub=world.principal.public_key,
        issuer_priv=world.principal_priv,
        subject_id=world.agent.id,
        subject_pub=world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[],
        issued_at=now - 7200,
        expires_at=now - 3600,
    )
    client = RefundClient(
        world.base_url, world.agent.id, world.agent.public_key, world.agent_priv, [expired]
    )
    client.request_refund("ord-16", UNDER)

    receipt = world.service.receipts[-1]
    assert receipt.decision == "expired"
    assert receipt.human_id == ""
    assert receipt.agent_id == ""
    # The presentation itself remains recoverable through the bundle hash.
    assert receipt.bundle_hash == bundle_hash(world.service.presented[-1])


def test_successful_receipt_does_record_the_verified_identity(world):
    """WHY: the counterpart to the test above. Blanking identity on failure is
    only correct if success still records who was verified, otherwise the
    receipt would carry no audit value at all."""
    world.client.request_refund("ord-17", UNDER)

    receipt = world.service.receipts[-1]
    assert receipt.decision == "authorized_agent"
    assert receipt.human_id == world.principal.id
    assert receipt.agent_id == world.agent.id


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
    assert world.service.refunded_total == 0.0
