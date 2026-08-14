# SPDX-License-Identifier: Apache-2.0
"""Runnable narrative: one principal, one agent, one receiving service.

    python demos/nvidia-nooa-delegated-authority/scenarios.py

Every line of output below is produced by the receiving service. The agent
never decides anything.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

from ratify_protocol import (
    Constraint,
    ProofBundle,
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_SEND,
    generate_agent,
    sign_challenge,
    verify_verification_receipt,
)

from agent_client import RefundClient, post_json
from principal import new_agent, new_principal, sign_cert
from refund_service import RefundService, canonical_resource_id, serve

LIMIT, UNDER, OVER, DAY = 100.0, 75.0, 150.0, 24 * 3600


def banner(text: str) -> None:
    print(f"\n{'━' * 74}\n{text}\n{'━' * 74}")


def show(label: str, out: dict) -> None:
    mark = "ALLOW" if out["decision"] == "authorized" else "DENY "
    print(f"  [{mark}] {label}")
    print(f"          status   {out['status']}")
    if out["reason"]:
        print(f"          reason   {out['reason'][:88]}")
    print(f"          refunded ${out['refunded']:.2f}    receipt {out['receipt_id']}")


def main() -> None:
    principal, principal_priv = new_principal()
    agent, agent_priv = new_agent("refund-agent")
    now = int(time.time())

    banner("SETUP")
    print(f"  principal      {principal.id}")
    print(f"  agent          {agent.id}")
    print(f"  delegation     payments:send, max $100.00 USD, expires in 24h")

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
    print(f"  service        {base_url} (separate process boundary)")
    client = RefundClient(base_url, agent.id, agent.public_key, agent_priv, [cert])

    try:
        banner("1. WITHIN THE DELEGATED BOUND")
        show("$75 refund", client.request_refund("ord-1", UNDER))

        banner("2. OVER THE PRINCIPAL'S BOUND")
        show("$150 refund against a $100 ceiling", client.request_refund("ord-2", OVER))

        banner("3. EXPIRED DELEGATION")
        expired = sign_cert(
            issuer_id=principal.id,
            issuer_pub=principal.public_key,
            issuer_priv=principal_priv,
            subject_id=agent.id,
            subject_pub=agent.public_key,
            scope=[SCOPE_PAYMENTS_SEND],
            constraints=[],
            issued_at=now - 7200,
            expires_at=now - 3600,
        )
        show(
            "$75 refund on a delegation that lapsed an hour ago",
            RefundClient(
                base_url, agent.id, agent.public_key, agent_priv, [expired]
            ).request_refund("ord-3", UNDER),
        )

        banner("4. WRONG AGENT KEY (a stolen certificate)")
        thief, thief_priv = generate_agent("thief", "assistant")
        # The thief plays it properly: its own challenge, its own key, someone
        # else's certificate. Proof of possession succeeds; the delegation is
        # what fails, because the certificate names a subject key it lacks.
        thief_client = RefundClient(base_url, thief.id, thief.public_key, thief_priv, [cert])
        ch = thief_client.fetch_challenge("ord-4", UNDER)
        at = int(time.time())
        stolen = ProofBundle(
            agent_id=thief.id,
            agent_pub_key=thief.public_key,
            delegations=[cert],
            challenge=ch["challenge"],
            challenge_at=at,
            challenge_sig=sign_challenge(
                ch["challenge"], at, thief_priv, ch["session_context"]
            ),
            session_context=ch["session_context"],
        )
        show(
            "thief presents a certificate issued to someone else",
            post_json(base_url + "/refunds", {"challenge": ch["challenge"], "bundle": stolen}),
        )

        banner("5. REPLAY OF A VALID PRESENTATION")
        ch = client.fetch_challenge("ord-5", UNDER)
        at = int(time.time())
        bundle = ProofBundle(
            agent_id=agent.id,
            agent_pub_key=agent.public_key,
            delegations=[cert],
            challenge=ch["challenge"],
            challenge_at=at,
            challenge_sig=sign_challenge(
                ch["challenge"], at, agent_priv, ch["session_context"]
            ),
            session_context=ch["session_context"],
        )
        payload = {"challenge": ch["challenge"], "bundle": bundle}
        show("first presentation", post_json(base_url + "/refunds", payload))
        show("the very same bytes, replayed", post_json(base_url + "/refunds", payload))

        banner("6. SUBSTITUTION ATTEMPT (the claim is ignored, not the request)")
        ch = client.fetch_challenge("ord-6", UNDER)
        at = int(time.time())
        bundle = ProofBundle(
            agent_id=agent.id,
            agent_pub_key=agent.public_key,
            delegations=[cert],
            challenge=ch["challenge"],
            challenge_at=at,
            challenge_sig=sign_challenge(
                ch["challenge"], at, agent_priv, ch["session_context"]
            ),
            session_context=ch["session_context"],
        )
        show(
            "challenge taken for $75, execution body claims $150, $75 is what moves",
            post_json(
                base_url + "/refunds",
                {"challenge": ch["challenge"], "bundle": bundle, "amount": OVER},
            ),
        )
        print("          note     the receiver used its own parse ($75), not the claim")

        banner("7. SUBDELEGATION THAT AMPLIFIES SCOPE")
        parent = sign_cert(
            issuer_id=principal.id,
            issuer_pub=principal.public_key,
            issuer_priv=principal_priv,
            subject_id=agent.id,
            subject_pub=agent.public_key,
            scope=[SCOPE_PAYMENTS_RECEIVE, SCOPE_IDENTITY_DELEGATE],
            constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
            issued_at=now - 60,
            expires_at=now + DAY,
        )
        sub, sub_priv = new_agent("sub-agent")
        child = sign_cert(
            issuer_id=agent.id,
            issuer_pub=agent.public_key,
            issuer_priv=agent_priv,
            subject_id=sub.id,
            subject_pub=sub.public_key,
            scope=[SCOPE_PAYMENTS_SEND],  # the parent never held this
            constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
            issued_at=now - 30,
            expires_at=now + DAY,
        )
        show(
            "child claims payments:send its parent never had",
            RefundClient(
                base_url, sub.id, sub.public_key, sub_priv, [child, parent]
            ).request_refund("ord-7", UNDER),
        )
        print("          note     neutralised by scope intersection, not by rejecting the cert")

        banner("8. SUBDELEGATION THAT AMPLIFIES THE AMOUNT")
        parent = sign_cert(
            issuer_id=principal.id,
            issuer_pub=principal.public_key,
            issuer_priv=principal_priv,
            subject_id=agent.id,
            subject_pub=agent.public_key,
            scope=[SCOPE_PAYMENTS_SEND, SCOPE_IDENTITY_DELEGATE],
            constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
            issued_at=now - 60,
            expires_at=now + DAY,
        )
        sub, sub_priv = new_agent("greedy-sub-agent")
        child = sign_cert(
            issuer_id=agent.id,
            issuer_pub=agent.public_key,
            issuer_priv=agent_priv,
            subject_id=sub.id,
            subject_pub=sub.public_key,
            scope=[SCOPE_PAYMENTS_SEND],
            constraints=[Constraint(type="max_amount", max_amount=1000.0, currency="USD")],
            issued_at=now - 30,
            expires_at=now + DAY,
        )
        show(
            "child raises its own ceiling to $1000, asks for $150",
            RefundClient(
                base_url, sub.id, sub.public_key, sub_priv, [child, parent]
            ).request_refund("ord-8", OVER),
        )
        print(
            "          note     the parent's $100 constraint is still evaluated, and still binds"
        )

        banner("9. RESOURCE-BOUND AUTHORITY (alpha.16)")
        # "Refund up to $100" and "refund up to $100 for THIS order" are very
        # different grants. A resource_path constraint names the one resource
        # the authority covers.
        order_bound = sign_cert(
            issuer_id=principal.id,
            issuer_pub=principal.public_key,
            issuer_priv=principal_priv,
            subject_id=agent.id,
            subject_pub=agent.public_key,
            scope=[SCOPE_PAYMENTS_SEND],
            constraints=[
                Constraint(type="max_amount", max_amount=LIMIT, currency="USD"),
                Constraint(
                    type="resource_path",
                    resource_id=canonical_resource_id("acme", "ord-9"),
                ),
            ],
            issued_at=now - 60,
            expires_at=now + DAY,
        )
        bound_client = RefundClient(
            base_url, agent.id, agent.public_key, agent_priv, [order_bound]
        )
        show(
            "the one order the principal named",
            bound_client.request_refund("ord-9", UNDER),
        )
        show(
            "a different order, same agent, same amount",
            bound_client.request_refund("ord-9-other", UNDER),
        )
        print("          note     the delegation names tenant/acme/orders/ord-9; the receiver")
        print("                   canonicalizes its own parse and compares byte-for-byte")

        # A third tenant's order with the same local number is a different
        # resource. Bare order numbers would collide here.
        cross_tenant = RefundClient(
            base_url,
            agent.id,
            agent.public_key,
            agent_priv,
            [
                sign_cert(
                    issuer_id=principal.id,
                    issuer_pub=principal.public_key,
                    issuer_priv=principal_priv,
                    subject_id=agent.id,
                    subject_pub=agent.public_key,
                    scope=[SCOPE_PAYMENTS_SEND],
                    constraints=[
                        Constraint(type="max_amount", max_amount=LIMIT, currency="USD"),
                        Constraint(
                            type="resource_path",
                            resource_id=canonical_resource_id("globex", "ord-9"),
                        ),
                    ],
                    issued_at=now - 60,
                    expires_at=now + DAY,
                )
            ],
        )
        show(
            "another tenant's order with the same local number",
            cross_tenant.request_refund("ord-9", UNDER),
        )

        banner("10. REVOCATION")
        show("before revoking", client.request_refund("ord-9a", UNDER))
        service.revoke(cert.cert_id)
        show("after the principal revokes", client.request_refund("ord-9b", UNDER))

        banner("11. AN AMOUNT THE CONSTRAINT CANNOT ORDER")
        raw = '{"order_id":"ord-10","amount":NaN,"currency":"USD","agent_id":"%s"}' % agent.id
        request = urllib.request.Request(
            base_url + "/refunds/challenge",
            data=raw.encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request)
            print("  [ALLOW] NaN refund, THIS IS A BUG")
        except urllib.error.HTTPError as exc:
            print(f"  [DENY ] NaN refund rejected at the door: HTTP {exc.code}")
            print("          note     every ordered comparison with NaN is false, so a NaN")
            print("                   amount would clear any ceiling. Rejected before a")
            print("                   challenge is even issued.")

        banner("RECEIPTS")
        print(f"  {len(service.receipts)} signed receipts (authenticated presentations only)")
        print(f"  {service.refusal_count} refusals logged unsigned, never authenticated")
        bad = [r for r in service.receipts if verify_verification_receipt(r) is not None]
        print(
            f"  signature check: {len(service.receipts) - len(bad)} valid, {len(bad)} invalid"
        )
        print(f"  total refunded: ${service.refunded_total:.2f}")
        print(
            "\n  A receipt is a verifier-signed assertion of the receiver's decision, bound\n"
            "  to the exact proof by bundle_hash. Chaining catches modification, reordering,\n"
            "  forks and interior gaps, not truncation of the tail. It is not third-party\n"
            "  attestation."
        )
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
