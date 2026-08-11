# SPDX-License-Identifier: Apache-2.0
"""Receiver, evidence recorder, and host-only control plane for the profile.

Started on the host by run-openshell-profile.sh. The client half runs inside an
OpenShell sandbox and reaches the MCP endpoint only through the gateway's
policy boundary, so every request counted here has already been admitted.

Three surfaces, deliberately separated:

    MCP endpoint    bound to an interface the sandbox can reach, carries the
                    proof, and is the only thing named in the OpenShell policy
    control plane   bound to 127.0.0.1 on a *different* dynamic port, never
                    named in the policy, and therefore unreachable from the
                    sandbox. Serves snapshots and signs proofs.
    event log       append-only, monotonic sequence, written under the same
                    lock that mutates the counters

Why a control plane rather than a polled state file
---------------------------------------------------
An earlier version rewrote ``state.json`` every 400 ms and the runner read
whatever happened to be on disk. That is not evidence: the read is not atomic
with respect to the writes, a case's effects can land after its own poll, and a
stale file is indistinguishable from a case that did nothing. Snapshots are now
pulled on demand, generated inside the lock, and carry a sequence number, so
"nothing happened between these two points" is a claim the runner can actually
make.

Why the private keys live here and nowhere else
-----------------------------------------------
The runner needs signed presentations, so something has to hold the agent key.
Writing the key material to the work directory, pickled or otherwise, puts
authorization material on disk for the lifetime of a run. Instead this process
keeps every private key in memory and exposes a loopback-only signing endpoint.
Nothing secret is ever serialized, so there is nothing to shred at teardown.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from ratify_protocol import (
    Constraint,
    HybridPublicKey,
    ProofBundle,
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_SEND,
    sign_challenge,
    verify_verification_receipt,
)
from ratify_protocol.wire import encode_delegation_cert, encode_proof_bundle

from mcp_server import build_server
from ratify_protocol import derive_id

from principal import new_agent, new_principal, sign_cert
from refund_service import RefundService, canonical_resource_id

DAY = 24 * 3600
LIMIT = 100.0

#: alpha.16 caps a delegation chain at 8 certificates (SPEC 5.1).
MAX_CHAIN_DEPTH = 8

#: Event types the runner adjudicates against. Named here so a typo in a
#: recorder call is a KeyError at startup rather than a silently absent event.
EVENT_TYPES = frozenset(
    {
        "http_ingress",
        "tool_dispatch",
        "prepare",
        "execute",
        "proof_observed",
        "decision",
    }
)


def canaries(run_id: str) -> dict[str, str]:
    """Per-run values that cannot appear in a log by coincidence.

    Derived from the run id so two concurrent runs never search for each
    other's strings and mistake a neighbour's log line for a leak.
    """
    tag = hashlib.sha256(run_id.encode()).hexdigest()[:10].upper()
    return {
        # The tenant is constrained by the receiver's canonicalization rule
        # (lowercase alphanumeric and hyphens), so this canary is lowercased
        # rather than being allowed to fail validation at run time.
        "tenant": f"acme{tag[:6].lower()}",
        "order": f"ord-canary-{tag}",
        "principal": f"PRINCIPAL-{tag}",
        "agent": f"AGENT-{tag}",
        "resource": f"RESOURCE-{tag}",
        # Well-formed W3C: 32-hex trace-id, 16-hex parent-id. Propagated
        # opaquely by the adapter, but a malformed value would be a poor
        # example to publish.
        "traceparent": "00-" + (tag.lower() * 4)[:32] + "-" + (tag.lower() * 2)[:16] + "-01",
        "baggage": f"canary=BAGGAGE-{tag}",
        "proof_key": "com.ratifyprotocol",
        "receipt_prefix": "refund-service:",
        "malformed_marker": f"MALFORMED-{tag}",
    }


class Recorder:
    """Counters plus an append-only event log, under one lock.

    Every mutation and every snapshot happen inside ``self.lock``, so a
    snapshot is a consistent cut and its ``seq`` is a real high-water mark
    rather than whatever a background thread last flushed.
    """

    def __init__(self, service: RefundService) -> None:
        self.lock = threading.Lock()
        self.service = service
        self.seq = 0
        self.events: list[dict] = []
        self.http_ingress = 0
        self.tool_dispatch: list[str] = []
        self.prepare = 0
        self.execute = 0
        self.inbound_proof_sha: list[str] = []
        self.inbound_proof_len: list[int] = []

    # -- recording --------------------------------------------------------

    def _append(self, event_type: str, **fields) -> None:
        """Caller must hold the lock."""
        if event_type not in EVENT_TYPES:
            raise KeyError(f"unknown event type {event_type!r}")
        self.seq += 1
        self.events.append({"seq": self.seq, "event_type": event_type, **fields})

    def ingress(self) -> None:
        with self.lock:
            self.http_ingress += 1
            self._append("http_ingress")

    def dispatch(self, tool: str) -> None:
        with self.lock:
            self.tool_dispatch.append(tool)
            self._append("tool_dispatch", tool_name=tool)

    def prepared(self, resource_id: str | None = None) -> None:
        """Record a challenge issue, tagged with the receiver's own canonical
        resource id.

        The tag is what lets the runner segment a single-process suite into
        subcases from the server's own append-only log, rather than believing
        the sandbox's account of which request was which.
        """
        with self.lock:
            self.prepare += 1
            self._append("prepare", resource_id=resource_id)

    def executed(self) -> None:
        with self.lock:
            self.execute += 1
            self._append("execute")

    def proof_seen(self, sha: str, length: int) -> None:
        """Carriage fidelity, recorded as hash and length only.

        The proof itself is authorization material and is never written to the
        event log, a snapshot, or the artifact.
        """
        with self.lock:
            self.inbound_proof_sha.append(sha)
            self.inbound_proof_len.append(length)
            self._append("proof_observed", proof_sha256=sha, proof_len=length)

    def decided(self, decision: dict) -> None:
        with self.lock:
            self._append(
                "decision",
                decision=decision.get("decision"),
                status=decision.get("status"),
                receipt_id=decision.get("receipt_id") or None,
            )

    # -- reading ----------------------------------------------------------

    def snapshot(self) -> dict:
        with self.lock:
            service = self.service
            return {
                "seq": self.seq,
                "counters": {
                    "http_ingress": self.http_ingress,
                    "tool_dispatch": list(self.tool_dispatch),
                    "prepare": self.prepare,
                    "execute": self.execute,
                    "inbound_proof_sha": list(self.inbound_proof_sha),
                    "inbound_proof_len": list(self.inbound_proof_len),
                    "refunded_total": service.refunded_total,
                    "receipts": len(service.receipts),
                    "receipts_all_verify": all(
                        verify_verification_receipt(r) is None for r in service.receipts
                    ),
                    "receipt_ids": list(service.receipt_ids),
                    "refusals": service.refusal_count,
                    "internal_errors": service.internal_errors,
                    "observation_failures": service.observation_failures,
                },
                "events": list(self.events),
            }


class IngressCounter:
    """Counts HTTP requests without reading, buffering, or replaying the body.

    Observes ``scope`` only. An earlier version buffered and replayed the body
    to inspect it and silently corrupted the transport; nothing here touches
    ``receive`` or ``send``.
    """

    def __init__(self, app, recorder: Recorder) -> None:
        self.app = app
        self.recorder = recorder

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            self.recorder.ingress()
        return await self.app(scope, receive, send)


class World:
    """Every identity, delegation, and key the profile needs.

    Private keys stay in this object for the process lifetime and are never
    serialized. :meth:`sign` is the only way to obtain a presentation, and it
    is reachable only over the loopback control plane.
    """

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.canaries = canaries(run_id)
        tenant = self.canaries["tenant"]
        order = self.canaries["order"]
        now = int(time.time())
        self.now = now

        self.principal, self.principal_priv = new_principal()
        self.agent, self.agent_priv = new_agent(self.canaries["agent"])
        # A second agent, for the "presented key is not the agent this
        # challenge was issued to" case.
        self.other_agent, self.other_agent_priv = new_agent("other-agent")
        # A principal this receiver does not trust.
        self.rogue, self.rogue_priv = new_principal()

        self.service = RefundService(trust_root=self.principal.public_key)
        self.resource_id = canonical_resource_id(tenant, order)

        def root_cert(subject_id, subject_pub, scope, constraints, issued=-60, expires=DAY,
                      issuer=None, issuer_priv=None, issuer_pub=None):
            return sign_cert(
                issuer_id=issuer if issuer is not None else self.principal.id,
                issuer_pub=issuer_pub if issuer_pub is not None else self.principal.public_key,
                issuer_priv=issuer_priv if issuer_priv is not None else self.principal_priv,
                subject_id=subject_id,
                subject_pub=subject_pub,
                scope=list(scope),
                constraints=list(constraints),
                issued_at=now + issued,
                expires_at=now + expires,
            )

        def amount(value=LIMIT):
            return Constraint(type="max_amount", max_amount=value, currency="USD")

        def resource(res_id):
            return Constraint(type="resource_path", resource_id=res_id)

        agent_id, agent_pub = self.agent.id, self.agent.public_key
        self.certs: dict[str, list] = {}

        self.certs["valid"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND],
                      [amount(), resource(self.resource_id)])
        ]
        # A second grant with identical terms, so revoking it cannot disturb
        # the positive path's certificate.
        self.certs["revoked"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND],
                      [amount(), resource(self.resource_id)])
        ]
        self.certs["wrong_order"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND],
                      [amount(), resource(canonical_resource_id(tenant, order + "-OTHER"))])
        ]
        # The same local order id under a different tenant. Resource identity
        # is the tenant-qualified path, so this must not satisfy the constraint.
        self.certs["other_tenant"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND],
                      [amount(), resource(canonical_resource_id(tenant + "-other", order))])
        ]
        self.certs["expired"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND],
                      [amount(), resource(self.resource_id)], issued=-7200, expires=-3600)
        ]
        self.certs["no_resource"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND], [amount()])
        ]
        self.certs["untrusted_root"] = [
            root_cert(agent_id, agent_pub, [SCOPE_PAYMENTS_SEND],
                      [amount(), resource(self.resource_id)],
                      issuer=self.rogue.id, issuer_priv=self.rogue_priv,
                      issuer_pub=self.rogue.public_key)
        ]

        # Scope amplification: an intermediate that never held payments:send
        # subdelegates it anyway. Chains are ordered leaf-first.
        mid, mid_priv = new_agent("intermediate")
        parent_no_send = root_cert(
            mid.id, mid.public_key,
            [SCOPE_PAYMENTS_RECEIVE, SCOPE_IDENTITY_DELEGATE],
            [amount(), resource(self.resource_id)],
        )
        child_claims_send = sign_cert(
            issuer_id=mid.id, issuer_pub=mid.public_key, issuer_priv=mid_priv,
            subject_id=agent_id, subject_pub=agent_pub,
            scope=[SCOPE_PAYMENTS_SEND],
            constraints=[amount(), resource(self.resource_id)],
            issued_at=now - 30, expires_at=now + DAY,
        )
        self.certs["scope_amplification"] = [child_claims_send, parent_no_send]

        # Constraint amplification: the parent caps the amount, the child tries
        # to raise it.
        mid2, mid2_priv = new_agent("intermediate-2")
        parent_capped = root_cert(
            mid2.id, mid2.public_key,
            [SCOPE_PAYMENTS_SEND, SCOPE_IDENTITY_DELEGATE],
            [amount(LIMIT), resource(self.resource_id)],
        )
        child_raises_cap = sign_cert(
            issuer_id=mid2.id, issuer_pub=mid2.public_key, issuer_priv=mid2_priv,
            subject_id=agent_id, subject_pub=agent_pub,
            scope=[SCOPE_PAYMENTS_SEND],
            constraints=[amount(LIMIT * 10), resource(self.resource_id)],
            issued_at=now - 30, expires_at=now + DAY,
        )
        self.certs["constraint_amplification"] = [child_raises_cap, parent_capped]

        self.certs["max_depth"] = self._chain(MAX_CHAIN_DEPTH, amount, resource)
        self.certs["over_depth"] = self._chain(MAX_CHAIN_DEPTH + 1, amount, resource)

    def _chain(self, depth: int, amount, resource) -> list:
        """A ``depth``-certificate chain ending at the trusted principal.

        Leaf-first, matching the wire order the verifier expects. Every hop
        carries identical terms so the only thing under test is length.
        """
        chain = []
        issuer_id, issuer_pub, issuer_priv = (
            self.principal.id,
            self.principal.public_key,
            self.principal_priv,
        )
        for hop in range(depth):
            last = hop == depth - 1
            if last:
                subject_id, subject_pub = self.agent.id, self.agent.public_key
                scope = [SCOPE_PAYMENTS_SEND]
            else:
                mid, mid_priv = new_agent(f"hop-{hop}")
                subject_id, subject_pub = mid.id, mid.public_key
                scope = [SCOPE_PAYMENTS_SEND, SCOPE_IDENTITY_DELEGATE]
            cert = sign_cert(
                issuer_id=issuer_id, issuer_pub=issuer_pub, issuer_priv=issuer_priv,
                subject_id=subject_id, subject_pub=subject_pub,
                scope=scope,
                constraints=[amount(), resource(self.resource_id)],
                issued_at=self.now - 60, expires_at=self.now + DAY,
            )
            chain.append(cert)
            if not last:
                issuer_id, issuer_pub, issuer_priv = subject_id, subject_pub, mid_priv
        chain.reverse()  # leaf first
        return chain

    def delegate_to(self, agent_pub: HybridPublicKey, *, amount: float = LIMIT,
                    bind_resource: bool = True, order: str | None = None) -> tuple[str, str]:
        """Issue a delegation to a key the agent generated for itself.

        This is the direction authority is supposed to flow. The agent creates
        its own keypair inside its own process and sends the public half here;
        the principal decides what that key may do. No private key crosses a
        boundary, and the subject identifier is derived from the key rather than
        trusted from whatever the requester claimed it was.
        """
        subject_id = derive_id(agent_pub)
        constraints = [Constraint(type="max_amount", max_amount=amount, currency="USD")]
        if bind_resource:
            resource_id = (
                canonical_resource_id(self.canaries["tenant"], order)
                if order else self.resource_id
            )
            constraints.append(Constraint(type="resource_path", resource_id=resource_id))
        cert = sign_cert(
            issuer_id=self.principal.id,
            issuer_pub=self.principal.public_key,
            issuer_priv=self.principal_priv,
            subject_id=subject_id,
            subject_pub=agent_pub,
            scope=[SCOPE_PAYMENTS_SEND],
            constraints=constraints,
            issued_at=self.now - 60,
            expires_at=self.now + DAY,
        )
        return subject_id, encode_delegation_cert(cert)

    # -- signing ----------------------------------------------------------

    def sign(self, variant: str, challenge: bytes, session_context: bytes) -> str:
        """Return a base64 presentation for ``variant``. Keys never leave here."""
        if variant == "wrong_agent":
            agent_id = self.other_agent.id
            agent_pub = self.other_agent.public_key
            agent_priv = self.other_agent_priv
            certs = self.certs["valid"]
        else:
            agent_id = self.agent.id
            agent_pub = self.agent.public_key
            agent_priv = self.agent_priv
            certs = self.certs[variant]
        at = int(time.time())
        bundle = ProofBundle(
            agent_id=agent_id,
            agent_pub_key=agent_pub,
            delegations=list(certs),
            challenge=challenge,
            challenge_at=at,
            challenge_sig=sign_challenge(challenge, at, agent_priv, session_context),
            session_context=session_context,
        )
        return base64.b64encode(encode_proof_bundle(bundle).encode()).decode()


def control_handler(world: World, recorder: Recorder, snapshots: dict):
    """The loopback control plane. Not reachable from the sandbox."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            return json.loads(self.rfile.read(length))

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
            if self.path.startswith("/snapshot"):
                return self._send(recorder.snapshot())
            if self.path.startswith("/public"):
                # Everything the runner may know. No key material, no proofs.
                return self._send(
                    {
                        "run_id": world.run_id,
                        "agent_id": world.agent.id,
                        "other_agent_id": world.other_agent.id,
                        "principal_id": world.principal.id,
                        "resource_id": world.resource_id,
                        "canaries": world.canaries,
                        "variants": sorted(world.certs),
                        "max_chain_depth": MAX_CHAIN_DEPTH,
                    }
                )
            return self._send({"error": "not found"}, 404)

        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
            try:
                body = self._body()
                if self.path.startswith("/sign"):
                    proof = world.sign(
                        body["variant"],
                        base64.b64decode(body["challenge"]),
                        base64.b64decode(body["session_context"]),
                    )
                    return self._send(
                        {
                            "proof": proof,
                            "sha256": hashlib.sha256(proof.encode()).hexdigest(),
                            "len": len(proof),
                        }
                    )
                if self.path.startswith("/delegate"):
                    pub = HybridPublicKey(
                        ed25519=base64.b64decode(body["agent_pub"]["ed25519"]),
                        ml_dsa_65=base64.b64decode(body["agent_pub"]["ml_dsa_65"]),
                    )
                    subject_id, encoded = world.delegate_to(
                        pub,
                        amount=float(body.get("amount", LIMIT)),
                        bind_resource=bool(body.get("bind_resource", True)),
                        order=body.get("order"),
                    )
                    return self._send({"subject_id": subject_id, "delegation": encoded})
                if self.path.startswith("/revoke"):
                    # Revoke every certificate in a named chain.
                    for cert in world.certs[body["variant"]]:
                        world.service.revoke(cert.cert_id)
                    return self._send({"revoked": body["variant"]})
                if self.path.startswith("/break-revocation"):
                    world.service.break_revocation(body.get("message", "provider unreachable"))
                    return self._send({"broken": True})
                if self.path.startswith("/fix-revocation"):
                    world.service._revocation.error = None
                    return self._send({"broken": False})
                if self.path.startswith("/break-observer"):
                    snapshots["observer_raises"] = True
                    return self._send({"observer_raises": True})
                if self.path.startswith("/fix-observer"):
                    snapshots["observer_raises"] = False
                    return self._send({"observer_raises": False})
            except Exception as exc:  # noqa: BLE001 - a control error is a result
                return self._send({"error": f"{type(exc).__name__}: {exc}"}, 500)
            return self._send({"error": "not found"}, 404)

        def log_message(self, *args) -> None:
            """Silent. The control plane handles signing requests, and its
            default access log would echo request lines into the run output."""

    return Handler


def build_app(world: World, recorder: Recorder, snapshots: dict, mcp_host: str, mcp_port: int):
    service = world.service

    _challenge, _execute = service.challenge, service.execute

    def challenge(**kw):
        # Canonicalized here with the receiver's own function, from the
        # receiver's own inputs. Not read back from anything the caller sent.
        try:
            resource_id = canonical_resource_id(kw.get("tenant", ""), kw.get("order_id", ""))
        except Exception:  # noqa: BLE001 - a rejected request still gets an event
            resource_id = None
        recorder.prepared(resource_id)
        return _challenge(**kw)

    def execute(*, challenge, bundle):  # noqa: A002 - matches the receiver's signature
        recorder.executed()
        decision = _execute(challenge=challenge, bundle=bundle)
        recorder.decided(decision)
        return decision

    service.challenge, service.execute = challenge, execute

    def observe(tool: str, trace: dict) -> None:
        if snapshots.get("observer_raises"):
            raise RuntimeError("observer failed after the decision was made")

    server = build_server(
        service,
        observe=observe,
        dispatched=recorder.dispatch,
        measure_proof=recorder.proof_seen,
    )

    # Host allow-list is exact. A request whose Host header is anything else,
    # including a bare IP the policy does not name, is refused by the SDK's
    # transport security before it reaches a tool.
    allowed_hosts = [
        f"{mcp_host}:{mcp_port}",
        mcp_host,
        f"127.0.0.1:{mcp_port}",
        "127.0.0.1",
    ]
    return IngressCounter(
        server.streamable_http_app(
            json_response=True,
            transport_security=TransportSecuritySettings(
                allowed_hosts=allowed_hosts,
                # The only client is an MCP client inside the sandbox, which
                # sends no Origin. An empty allow-list refuses every
                # cross-origin request rather than waving them all through.
                allowed_origins=[],
            ),
        ),
        recorder,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mcp-port", type=int, required=True)
    parser.add_argument("--ctrl-port", type=int, required=True)
    parser.add_argument("--mcp-bind", default="0.0.0.0")
    parser.add_argument("--mcp-host", default="host.openshell.internal")
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()

    world = World(args.run_id)
    recorder = Recorder(world.service)
    snapshots: dict = {"observer_raises": False}
    app = build_app(world, recorder, snapshots, args.mcp_host, args.mcp_port)

    control = ThreadingHTTPServer(
        ("127.0.0.1", args.ctrl_port), control_handler(world, recorder, snapshots)
    )
    control.daemon_threads = True
    threading.Thread(target=control.serve_forever, daemon=True).start()

    ready = pathlib.Path(args.ready_file)
    ready.parent.mkdir(parents=True, exist_ok=True)
    tmp = ready.with_suffix(".tmp")
    tmp.write_text(json.dumps({"mcp_port": args.mcp_port, "ctrl_port": args.ctrl_port}))
    tmp.replace(ready)

    uvicorn.run(app, host=args.mcp_bind, port=args.mcp_port, log_level="error")


if __name__ == "__main__":
    main()
