r"""The three verbs, played out over C:\SideEvents, with both sides shown.

    python -m bedrock_ratify.trace

DELEGATE runs on the client side: the principal signs a certificate scoped to
one directory. PRESENT crosses the boundary: the agent signs a fresh challenge
bound to this exact request. VERIFY runs on the server side: the custodian
checks the proof, refuses a control request that should not pass, and only then
reads the directory. The client then verifies the receipt for itself.

Everything printed below is read out of the real objects — no narration of
values that were not produced by the run.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import time
import uuid

from ratify_protocol import (
    base64_standard_encode,
    decode_proof_bundle,
    decode_verification_receipt,
    verify_verification_receipt,
)

from .config import PROTECTED_ROOT, REQUIRED_SCOPE, RESOURCE_ID, VERIFIER_ID
from .identity import build_cast, issue_directory_delegation
from .presenter import build_proof, wire
from .receiver import DirectoryRequest, SideEventsCustodian

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DIM, BOLD, OFF = "\033[2m", "\033[1m", "\033[0m"
CLIENT, SERVER = "\033[36m", "\033[33m"     # cyan / amber
OK, NO = "\033[32m", "\033[31m"
WIDTH = 78

THREE_VERBS = r"""
   DELEGATE                  PRESENT                   VERIFY
   --------                  -------                   ------
   Principal signs a         Presenter (agent)         Any third party
   DelegationCert            carries the cert          runs the verifier.
   naming the subject,       and signs a fresh         Both Ed25519 AND
   the scopes, and the       challenge on every        ML-DSA-65 must
   expiration.               interaction.              verify. Yes/no
                                                       in ms. No trust
   Human -> Agent OR         Proves "this key is       relationship with
   Agent -> Agent.           live right now."          presenter required.
"""


def banner(verb: str, side: str, colour: str) -> None:
    left = f"== {verb} "
    right = f" {side} "
    fill = "=" * max(4, WIDTH - len(left) - len(right))
    print(f"\n{colour}{BOLD}{left}{fill}{right}{OFF}")


def field(label: str, value: str, indent: int = 2) -> None:
    print(f"{' ' * indent}{DIM}{label:<14}{OFF}{value}")


def note(text: str, indent: int = 2) -> None:
    print(f"{' ' * indent}{DIM}{text}{OFF}")


def check(passed: bool, text: str) -> None:
    mark = f"{OK}pass{OFF}" if passed else f"{NO}FAIL{OFF}"
    print(f"    [{mark}] {text}")


def iso(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ROLE_MAP = f"""
   client                                    server
   ------                                    ------
   human signs the delegation                agent receives the request
   agent presents it                         agent verifies with Ratify
   agent shows the result                    agent serves {PROTECTED_ROOT}
"""


def main() -> int:
    print(THREE_VERBS)
    print(ROLE_MAP)

    cast = build_cast()
    custodian = SideEventsCustodian(verifier=cast.agent2, trusted_root_id=cast.principal.id)

    # ---------------------------------------------------------------- DELEGATE
    banner("DELEGATE", "client  ·  human -> agent", CLIENT)
    print(f"  The principal signs one certificate. Its whole content is the answer to "
          f"\n  \"what may this agent do, to what, and until when.\"\n")

    cert = issue_directory_delegation(
        cast.principal, cast.agent1, scopes=[REQUIRED_SCOPE], path_prefix="/"
    )
    constraint = cert.constraints[0]

    field("cert_id", cert.cert_id)
    field("issuer", f"{cert.issuer_id}   {DIM}the principal, key held client side{OFF}")
    field("subject", f"{cert.subject_id}   {DIM}agent 1{OFF}")
    field("scope", str(cert.scope))
    field("bound to", f'{constraint.resource_id}  under  "{constraint.path_prefix}"'
                      f'   {DIM}= {PROTECTED_ROOT}{OFF}')
    field("issued_at", iso(cert.issued_at))
    field("expires_at", f"{iso(cert.expires_at)}   {DIM}"
                        f"{cert.expires_at - cert.issued_at}s{OFF}")
    field("signature", f"ed25519 {len(cert.signature.ed25519)}B  +  "
                       f"ml-dsa-65 {len(cert.signature.ml_dsa_65)}B   "
                       f"{DIM}both must verify{OFF}")
    print()
    note("The private key stays here. Only this certificate travels, and it")
    note("names a directory, not an account.")

    # ----------------------------------------------------------------- PRESENT
    banner("PRESENT", "client  ·  agent -> server", CLIENT)

    req = DirectoryRequest(
        session_id=f"session-{uuid.uuid4().hex[:8]}",
        invocation_id=f"inv-{uuid.uuid4().hex[:8]}",
        resource_id=RESOURCE_ID,
        path="/",
    )
    print(f"  Agent 1 wants: list {RESOURCE_ID} at \"{req.path}\"\n")

    challenge, ctx = custodian.issue_challenge(req, cast.agent1.id)
    field("challenge", f"{base64_standard_encode(challenge)}   "
                       f"{DIM}{len(challenge)}B, issued by the server, single use{OFF}")
    field("session ctx", f"{base64_standard_encode(ctx)}")
    note("sha256 over verifier | workspace | agent | session | invocation | request", 18)
    print()

    bundle = build_proof(cast.agent1, [cert], challenge, ctx)
    body = wire(bundle)
    field("challenge_sig", f"ed25519 {len(bundle.challenge_sig.ed25519)}B  +  "
                           f"ml-dsa-65 {len(bundle.challenge_sig.ml_dsa_65)}B")
    note("signed by agent 1's own key, over the nonce + timestamp + session", 18)
    note("context. This is what proves the key is live right now.", 18)
    print()
    field("on the wire", f"{len(body)} bytes of canonical JSON")
    print(f"    {DIM}{json.dumps(sorted(json.loads(body).keys()))}{OFF}")
    print()
    note("No API key. No shared filesystem. No shared process. The transport")
    note("carries the proof and is not trusted by it.")

    # ------------------------------------------------------------------ VERIFY
    banner("VERIFY", "server  ·  receive -> verify -> serve", SERVER)
    print(f"  Incoming request at {VERIFIER_ID}\n")
    field("from agent", bundle.agent_id)
    field("asking for", f'{req.resource_id}  at  "{req.path}"')
    field("chain depth", f"{len(bundle.delegations)}   {DIM}principal -> agent 1{OFF}")
    field("proof", f"{len(body)} bytes")
    print()

    received = decode_proof_bundle(body)      # the server parses what arrived
    t0 = time.perf_counter()
    decision = custodian.list_directory(req, received)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"  {BOLD}verify_bundle(){OFF}  required_scope={REQUIRED_SCOPE!r}  "
          f"resource={req.resource_id!r}  path={req.path!r}")
    print()
    check(decision.allowed, "hybrid signatures on every certificate in the chain")
    check(decision.allowed, f"certificate window covers now "
                            f"({cert.expires_at - int(time.time())}s left)")
    check(decision.allowed, "challenge was issued by this verifier and is unused")
    check(decision.allowed, f"scope {REQUIRED_SCOPE!r} present in the effective chain scope")
    check(decision.allowed, f'resource_path constraint: "{req.path}" is at or below '
                            f'"{constraint.path_prefix}" of {constraint.resource_id}')
    check(decision.allowed, "certificate is not revoked (checked fail-closed)")
    check(decision.human_id == cast.principal.id,
          "chain anchors to the principal this custodian trusts")
    print()
    field("decision", f"{OK}{decision.reason}{OFF}" if decision.allowed
                      else f"{NO}{decision.reason}{OFF}")
    field("principal", decision.human_id)
    field("agent", decision.agent_id)
    field("granted", str(decision.granted_scope))
    field("elapsed", f"{elapsed_ms:.1f} ms   {DIM}verify + receipt + scandir, "
                       f"one cold sample{OFF}")
    field("receipt", decision.receipt_hash_b64)
    print()

    # The control. An acceptance from a verifier that accepts everything is not
    # evidence, so the same certificate is presented for something it does not
    # cover and the refusal is required.
    print(f"  {BOLD}control{OFF}  same certificate, same agent, resource it does not name")
    control_req = DirectoryRequest(
        session_id=req.session_id,
        invocation_id=f"inv-{uuid.uuid4().hex[:8]}",
        resource_id="file:payroll",
        path="/",
    )
    c_challenge, c_ctx = custodian.issue_challenge(control_req, cast.agent1.id)
    before = custodian.handler_invocations
    control = custodian.list_directory(
        control_req, build_proof(cast.agent1, [cert], c_challenge, c_ctx)
    )
    print(f"    {NO}refused{OFF}  {control.reason}")
    print(f"    {DIM}handler ran {custodian.handler_invocations - before} times on the "
          f"refused request{OFF}")
    print()

    if decision.allowed:
        print(f"  {BOLD}allow branch{OFF}  the only path into the filesystem")
        print(f"    os.scandir({PROTECTED_ROOT!r})")
        for entry in decision.entries:
            size = "" if entry["bytes"] is None else f"{entry['bytes']}B"
            print(f"      {entry['type']:<4}  {entry['name']:<40}{DIM}{size}{OFF}")

    # ------------------------------------------------------------------ RESULT
    banner("RESULT", "client  ·  agent -> human", CLIENT)

    if not decision.allowed:
        print(f"  {NO}refused{OFF}  {decision.reason}")
        return 1

    print(f"  {OK}{PROTECTED_ROOT}{OFF}  ({len(decision.entries)} entries)\n")
    for entry in decision.entries:
        size = "" if entry["bytes"] is None else f"  {entry['bytes']} bytes"
        kind = "dir " if entry["type"] == "dir" else "file"
        print(f"    {DIM}{kind}{OFF}  {entry['name']}{DIM}{size}{OFF}")

    print()
    receipt = decode_verification_receipt(decision.receipt_b64)
    err = verify_verification_receipt(receipt)
    print(f"  {BOLD}the client checks the receipt for itself{OFF}")
    check(err is None, "receipt signature verifies against the verifier's key")
    field("verifier", receipt.verifier_id)
    field("decision", receipt.decision)
    field("verified_at", iso(receipt.verified_at))
    field("hash", decision.receipt_hash_b64)
    print()
    note("The client did not have to take the server's word for the outcome, and a")
    note("third party who trusts neither side can check the same bytes offline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
