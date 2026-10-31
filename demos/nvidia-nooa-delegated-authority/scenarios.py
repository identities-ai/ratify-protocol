# SPDX-License-Identifier: Apache-2.0
"""Runnable narrative: one principal, one agent, one receiving service.

    python demos/nvidia-nooa-delegated-authority/scenarios.py

Protocol v2. Every line of output below is produced by the receiving service.
The agent never decides anything. The receiver's claim store, receipt log,
checkpoint and journal are the SDK's in-memory reference stores: development
only.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

from ratify_protocol.v2.scope import (
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_SEND,
)

from adversary import forge_presentation
from agent_client import RefundClient, post_json
from openshell_probe import receipts_verify
from principal import (
    StatusAuthority,
    max_amount_micros,
    new_agent,
    new_principal,
    resource_bound,
    sign_cert,
)
from refund_service import RefundService, canonical_resource_id, encode_public_key, serve

#: Integer micro-units: 100.00, 75.00 and 150.00 USD.
LIMIT, UNDER, OVER, DAY = 100_000_000, 75_000_000, 150_000_000, 24 * 3600


def usd(micros: int) -> str:
    return f"{micros // 1_000_000}.{(micros % 1_000_000) // 10_000:02d} USD"


def banner(text: str) -> None:
    print(f"\n{'=' * 74}\n{text}\n{'=' * 74}")


def show(label: str, out: dict) -> None:
    mark = "ALLOW" if out["decision"] == "authorized" else "DENY "
    print(f"  [{mark}] {label}")
    print(f"          status   {out['status']}")
    if out["reason"]:
        print(f"          reason   {out['reason'][:88]}")
    receipt = out["receipt_id"] or "none (no new committed decision, nothing signed)"
    print(f"          refunded {usd(out['refunded_micros'])}    receipt {receipt}")


def main() -> None:
    principal, principal_priv = new_principal()
    agent, agent_priv = new_agent("refund-agent")
    now = int(time.time())
    status = StatusAuthority(principal, now)

    banner("SETUP (Ratify Protocol v2, development-only reference stores)")
    print(f"  principal      {principal.id}")
    print(f"  status key     {status.status_key_id} (separate from the root key)")
    print(f"  agent          {agent.id}")
    print("  delegation     payments:send, max_amount_micros 100000000 USD, expires in 24h")

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
    print(f"  service        {base_url} (separate process boundary)")
    client = RefundClient(base_url, agent.id, agent.public_key, agent_priv, [cert])

    try:
        banner("1. WITHIN THE DELEGATED BOUND")
        show("75.00 USD refund", client.request_refund("ord-1", UNDER))

        banner("2. OVER THE PRINCIPAL'S BOUND")
        show("150.00 USD refund against a 100.00 USD ceiling", client.request_refund("ord-2", OVER))

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
            "75.00 USD refund on a delegation that lapsed an hour ago",
            RefundClient(
                base_url, agent.id, agent.public_key, agent_priv, [expired]
            ).request_refund("ord-3", UNDER),
        )

        banner("4. WRONG AGENT KEY (a stolen certificate)")
        thief, thief_priv = new_agent("thief")
        # The thief requests its own challenge and signs with its own key, but
        # presents someone else's certificate. The SDK would refuse to sign
        # this, so it is built by hand, the way an attacker would.
        ch = RefundClient(base_url, thief.id, thief.public_key, thief_priv, [cert]).fetch_challenge(
            "ord-4", UNDER
        )
        stolen = forge_presentation(
            verifier_id=ch["verifier_id"],
            agent_id=thief.id,
            agent_pub=thief.public_key,
            signing_priv=thief_priv,
            delegations=[cert],
            challenge=ch["challenge"],
            challenge_at=ch["issued_at"],
            session_context=ch["session_context"],
        )
        show(
            "thief presents a certificate issued to someone else",
            post_json(base_url + "/refunds", {"challenge": ch["challenge"], "proof": stolen}),
        )

        banner("5. REPLAY OF A VALID PRESENTATION")
        ch = client.fetch_challenge("ord-5", UNDER)
        payload = {"challenge": ch["challenge"], "proof": client.sign(ch)}
        show("first presentation", post_json(base_url + "/refunds", payload))
        show("the very same bytes, replayed", post_json(base_url + "/refunds", payload))

        banner("6. SUBSTITUTION ATTEMPT (the claim is ignored, not the request)")
        ch = client.fetch_challenge("ord-6", UNDER)
        show(
            "challenge taken for 75.00, execution body claims 150.00, 75.00 is what moves",
            post_json(
                base_url + "/refunds",
                {"challenge": ch["challenge"], "proof": client.sign(ch), "amount_micros": OVER},
            ),
        )
        print("          note     the receiver used its own parse (75.00), not the claim")

        # The agent subdelegates below, so it is an issuer too. v2 evaluates
        # signed status per issuer, so it publishes its own and the receiver
        # admits that status key.
        agent_status = StatusAuthority(agent, now)
        service.configure_issuer_status(agent.public_key, agent_status.status_pub, agent_status)

        banner("7. SUBDELEGATION THAT AMPLIFIES SCOPE")
        parent = sign_cert(
            issuer_id=principal.id,
            issuer_pub=principal.public_key,
            issuer_priv=principal_priv,
            subject_id=agent.id,
            subject_pub=agent.public_key,
            scope=[SCOPE_PAYMENTS_RECEIVE, SCOPE_IDENTITY_DELEGATE],
            constraints=[max_amount_micros(LIMIT)],
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
            constraints=[max_amount_micros(LIMIT)],
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
            constraints=[max_amount_micros(LIMIT)],
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
            constraints=[max_amount_micros(10 * LIMIT)],
            issued_at=now - 30,
            expires_at=now + DAY,
        )
        show(
            "child raises its own ceiling to 1000.00, asks for 150.00",
            RefundClient(
                base_url, sub.id, sub.public_key, sub_priv, [child, parent]
            ).request_refund("ord-8", OVER),
        )
        print("          note     the parent's 100.00 constraint is still evaluated, and still binds")

        banner("9. RESOURCE-BOUND AUTHORITY")
        # "Refund up to 100.00" and "refund up to 100.00 for THIS order" are
        # very different grants. A resource_path constraint names the one
        # resource the authority covers.
        def order_bound(tenant: str, order: str) -> RefundClient:
            grant = sign_cert(
                issuer_id=principal.id,
                issuer_pub=principal.public_key,
                issuer_priv=principal_priv,
                subject_id=agent.id,
                subject_pub=agent.public_key,
                scope=[SCOPE_PAYMENTS_SEND],
                constraints=[
                    max_amount_micros(LIMIT),
                    resource_bound(canonical_resource_id(tenant, order)),
                ],
                issued_at=now - 60,
                expires_at=now + DAY,
            )
            return RefundClient(base_url, agent.id, agent.public_key, agent_priv, [grant])

        bound_client = order_bound("acme", "ord-9")
        show("the one order the principal named", bound_client.request_refund("ord-9", UNDER))
        show(
            "a different order, same agent, same amount",
            bound_client.request_refund("ord-9-other", UNDER),
        )
        print("          note     the delegation names tenant/acme/orders/ord-9; the receiver")
        print("                   canonicalizes its own parse and compares byte-for-byte")
        show(
            "another tenant's order with the same local number",
            order_bound("globex", "ord-9").request_refund("ord-9", UNDER),
        )

        banner("10. REVOCATION BY SIGNED STATUS")
        show("before revoking", client.request_refund("ord-9a", UNDER))
        status.revoke(cert.cert_id, int(time.time()))
        print("          note     the principal's status key signs a revocation push and list")
        show("after the principal revokes", client.request_refund("ord-9b", UNDER))

        banner("11. AN AMOUNT THAT IS NOT AN INTEGER")
        for literal in ("NaN", "75000000.5"):
            raw = (
                '{"order_id":"ord-10","amount_micros":%s,"currency":"USD","agent_id":"%s",'
                '"agent_public_key":%s}'
                % (literal, agent.id, str(encode_public_key(agent.public_key)).replace("'", '"'))
            )
            request = urllib.request.Request(
                base_url + "/refunds/challenge",
                data=raw.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(request)
                print(f"  [ALLOW] amount {literal}, THIS IS A BUG")
            except urllib.error.HTTPError as exc:
                print(f"  [DENY ] amount {literal} rejected at the door: HTTP {exc.code} malformed")
        print("          note     v2 amounts are integer micro-units. A NaN cleared every")
        print("                   ceiling in v1; in v2 it is malformed and no challenge is issued.")

        banner("RECEIPTS")
        print(f"  {len(service.receipts)} signed receipts in the log (committed decisions only)")
        print(f"  {service.refusal_count} refusals logged unsigned, never claimed")
        print(f"  checkpoint acknowledgements: {len(service.acknowledgements)}")
        print(f"  log verifies end to end: {receipts_verify(service)}")
        print(f"  total refunded: {usd(service.refunded_total_micros)}")
        print(
            "\n  A receipt is a verifier-signed assertion of the receiver's decision, bound\n"
            "  to the exact proof by bundle_hash and linked into a sequenced log. The\n"
            "  checkpoint here is the SDK's in-memory reference store, in the verifier's own\n"
            "  failure domain: development only. Tail truncation is caught only by an\n"
            "  independent checkpoint or witness. It is not third-party attestation."
        )
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
