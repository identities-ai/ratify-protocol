r"""End-to-end run: two Bedrock agents, one directory, one proof.

    python -m bedrock_ratify.run              # live: two Claude-on-Bedrock clients
    python -m bedrock_ratify.run --offline    # no AWS: scripted agents, same Ratify path
    python -m bedrock_ratify.run --deny-only  # just the refusal matrix

The allow path is one line of output. The refusal matrix is the point: the same
custodian, the same code path, refusing eight differently-broken requests for
eight different stated reasons, with the filesystem handler untouched each time.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid

from ratify_protocol import (
    DelegationCert,
    decode_proof_bundle,
    encode_proof_bundle,
)

from .agents import CustodianAgent, RequesterAgent
from .config import AWS_REGION, PROTECTED_ROOT, RESOURCE_ID
from .identity import build_cast, issue_directory_delegation
from .presenter import build_proof
from .receiver import DirectoryRequest, SideEventsCustodian

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def hr(title: str) -> None:
    print(f"\n{BOLD}{title}{OFF}\n{'-' * len(title)}")


def allow(msg: str) -> None:
    print(f"  {GREEN}ALLOW{OFF}  {msg}")


def deny(label: str, reason: str) -> None:
    print(f"  {RED}DENY {OFF}  {label}\n         {DIM}{reason}{OFF}")


# ---------------------------------------------------------------------------
# The refusal matrix. Each case breaks exactly one thing.
# ---------------------------------------------------------------------------


def run_deny_matrix(cast, custodian: SideEventsCustodian, cert: DelegationCert) -> int:
    """Returns the number of cases that refused as expected."""
    refused = 0

    def attempt(label: str, *, path="/", resource=RESOURCE_ID, chain=None, mutate=None,
                replay_bundle=None, replay_req=None):
        nonlocal refused
        req = replay_req or DirectoryRequest(
            session_id="deny-session",
            invocation_id=f"inv-{uuid.uuid4()}",
            resource_id=resource,
            path=path,
        )
        if replay_bundle is not None:
            bundle = replay_bundle
        else:
            challenge, ctx = custodian.issue_challenge(req, cast.agent1.id)
            bundle = build_proof(cast.agent1, chain or [cert], challenge, ctx)
            if mutate:
                bundle = mutate(bundle)
        before = custodian.handler_invocations
        decision = custodian.list_directory(req, bundle)
        if decision.allowed:
            print(f"  {RED}UNEXPECTED ALLOW{OFF}  {label}")
            return
        assert custodian.handler_invocations == before, "handler ran on a refused request"
        refused += 1
        deny(label, decision.reason)

    # 1. Outside the granted prefix.
    narrow = issue_directory_delegation(
        cast.principal, cast.agent1, scopes=["files:read"], path_prefix="/tools"
    )
    attempt("path outside the granted prefix (/tools granted, / asked)",
            path="/", chain=[narrow])

    # 2. A resource this custodian does not serve.
    attempt("resource the custodian does not serve", resource="file:payroll")

    # 3. Scope the principal never granted.
    write_only = issue_directory_delegation(
        cast.principal, cast.agent1, scopes=["files:write"]
    )
    attempt("scope not delegated (files:write held, files:read required)",
            chain=[write_only])

    # 4. An untrusted principal, cryptographically perfect.
    stranger_cert = issue_directory_delegation(
        cast.stranger, cast.agent1, scopes=["files:read"]
    )
    attempt("valid signatures, principal the custodian does not trust",
            chain=[stranger_cert])

    # 5. Expired.
    past = int(time.time()) - 7200
    expired = issue_directory_delegation(
        cast.principal, cast.agent1, scopes=["files:read"], now=past, ttl_seconds=3600
    )
    attempt("delegation expired", chain=[expired])

    # 6. Tampered after signing: widen the scope on the wire.
    def widen(bundle):
        cloned = decode_proof_bundle(encode_proof_bundle(bundle))
        cloned.delegations[0].scope = sorted(set(cloned.delegations[0].scope) | {"data:export"})
        return cloned

    attempt("scope widened after signing", mutate=widen)

    # 7. Replay: a bundle that already succeeded, presented again.
    req = DirectoryRequest("replay-session", f"inv-{uuid.uuid4()}", RESOURCE_ID, "/")
    challenge, ctx = custodian.issue_challenge(req, cast.agent1.id)
    good = build_proof(cast.agent1, [cert], challenge, ctx)
    first = custodian.list_directory(req, good)
    assert first.allowed, first.reason
    attempt("challenge replayed after a successful use",
            replay_bundle=good, replay_req=req)

    # 8. Revoked mid-flight: the principal withdraws while the agent still holds
    #    a certificate with plenty of validity left.
    live = issue_directory_delegation(cast.principal, cast.agent1, scopes=["files:read"])
    req = DirectoryRequest("kill-switch", f"inv-{uuid.uuid4()}", RESOURCE_ID, "/")
    challenge, ctx = custodian.issue_challenge(req, cast.agent1.id)
    before_revoke = custodian.list_directory(req, build_proof(cast.agent1, [live], challenge, ctx))
    assert before_revoke.allowed, before_revoke.reason
    remaining = live.expires_at - int(time.time())
    custodian.revoke(live.cert_id)
    attempt(f"revoked mid-flight ({remaining}s of validity remained)", chain=[live])

    return refused


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true",
                        help="skip Bedrock; run the scripted agents")
    parser.add_argument("--deny-only", action="store_true",
                        help="run only the refusal matrix")
    parser.add_argument("--path", default="/",
                        help="logical path to request (default: /)")
    args = parser.parse_args(argv)

    cast = build_cast()
    custodian_service = SideEventsCustodian(
        verifier=cast.agent2, trusted_root_id=cast.principal.id
    )

    print(f"{BOLD}Resource{OFF}   {PROTECTED_ROOT}  (as {RESOURCE_ID})")
    print(f"{BOLD}Principal{OFF}  {cast.principal.id}")
    print(f"{BOLD}Agent 1{OFF}    {cast.agent1.id}  requester, Bedrock client #1")
    print(f"{BOLD}Agent 2{OFF}    {cast.agent2.id}  custodian, Bedrock client #2")
    print(f"{BOLD}Mode{OFF}       {'offline (scripted agents)' if args.offline else 'live Bedrock'}")

    # The principal signs one bounded delegation to agent 1.
    cert = issue_directory_delegation(
        cast.principal, cast.agent1, scopes=["files:read", "identity:delegate"]
    )
    print(f"\n{DIM}delegation {cert.cert_id}"
          f"\n  scope      {cert.scope}"
          f"\n  bound to   {cert.constraints[0].resource_id} under "
          f"{cert.constraints[0].path_prefix}"
          f"\n  expires in {cert.expires_at - cert.issued_at}s{OFF}")

    if not args.deny_only:
        hr("Allow path — agent 1 asks agent 2 for the directory")
        custodian_agent = CustodianAgent(custodian_service, offline=args.offline)
        requester = RequesterAgent(
            cast.agent1, [cert], custodian_agent, offline=args.offline
        )
        try:
            report = requester.ask(
                f"Please get me a listing of {PROTECTED_ROOT} at path {args.path}, "
                "then tell me what is in it."
            )
        except RuntimeError as exc:
            print(f"  {RED}bedrock unavailable{OFF}  {exc}")
            print(f"  {DIM}configure AWS credentials for {AWS_REGION}, or rerun with "
                  f"--offline to exercise the same authority path without a model.{OFF}")
            return 2
        response = requester.last_response
        if response and response.allowed:
            allow(f"{len(response.entries)} entries, receipt {response.receipt_hash[:16]}...")
            for entry in response.entries:
                size = "" if entry["bytes"] is None else f"  {entry['bytes']}B"
                print(f"         {entry['type']:4}  {entry['name']}{size}")
        elif response:
            deny("allow path did not verify", response.reason)
        print(f"\n{DIM}agent 1 reports:{OFF} {report.strip()}")

    hr("Refusal matrix — same custodian, same code path, eight broken requests")
    refused = run_deny_matrix(cast, custodian_service, cert)

    hr("Result")
    print(f"  refused {refused}/8 as expected")
    print(f"  protected handler ran {custodian_service.handler_invocations} times "
          f"{DIM}(only on verified requests){OFF}")
    return 0 if refused == 8 else 1


if __name__ == "__main__":
    sys.exit(main())
