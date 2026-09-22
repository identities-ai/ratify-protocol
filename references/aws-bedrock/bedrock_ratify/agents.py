r"""The two Bedrock clients.

Agent 1 (requester) runs Claude on Bedrock and decides, in language, that it
needs the C:\SideEvents listing. Its tool handler does the Ratify half: ask the
custodian for a challenge, sign it, ship the bundle.

Agent 2 (custodian) is a second, independent Bedrock client. It reads the
incoming request, reviews the scope it is being asked for, and calls its own
tool. That tool is the enforcement point: the model's opinion never reaches the
filesystem, only `SideEventsCustodian.list_directory` does, and that verifies
the proof first.

Both agents are optional. `--offline` swaps the model for a scripted decision
so the authority boundary can be exercised without AWS credentials; the Ratify
path is byte-identical either way.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Callable

from ratify_protocol import DelegationCert, decode_proof_bundle

from .a2a import RequestEnvelope, ResponseEnvelope
from .config import MODEL_ID, PROTECTED_ROOT, REQUIRED_SCOPE, RESOURCE_ID, AWS_REGION
from .identity import Party
from .presenter import build_proof, wire
from .receiver import DirectoryRequest, SideEventsCustodian

MAX_TOKENS = 4096


# --------------------------------------------------------------------------
# Bedrock plumbing
# --------------------------------------------------------------------------


def bedrock_client():
    """Claude on Amazon Bedrock, via the Messages-API Mantle endpoint."""
    from anthropic import AnthropicBedrockMantle

    return AnthropicBedrockMantle(aws_region=AWS_REGION)


def bedrock_status() -> dict:
    """Can this process actually reach Bedrock?

    Checked at startup so a console can say so in its header rather than
    failing silently on the first request. Credentials are resolved, not
    exercised — a resolvable credential can still be denied by IAM.
    """
    status = {"model": MODEL_ID, "region": AWS_REGION, "available": False, "reason": ""}
    try:
        import boto3

        creds = boto3.Session().get_credentials()
    except Exception as exc:
        status["reason"] = f"{type(exc).__name__}: {exc}"
        return status
    if creds is None:
        status["reason"] = "no AWS credentials resolved from the environment"
        return status
    status["available"] = True
    return status


def run_tool_loop(
    client,
    *,
    system: str,
    user_message: str,
    tools: list[dict],
    handlers: dict[str, Callable[[dict], Any]],
    max_turns: int = 6,
) -> tuple[str, list[dict]]:
    """A plain agent loop: call the model, run the tools it asks for, repeat.

    Returns the model's final text and a trace of the tool calls it made.
    """
    messages: list[dict] = [{"role": "user", "content": user_message}]
    trace: list[dict] = []

    for _ in range(max_turns):
        response = client.messages.create(
            model=MODEL_ID,
            max_tokens=MAX_TOKENS,
            thinking={"type": "adaptive"},
            system=system,
            tools=tools,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            text = "".join(b.text for b in response.content if b.type == "text")
            return text, trace

        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            payload = handlers[block.name](block.input)
            trace.append({"tool": block.name, "input": block.input, "output": payload})
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(payload, default=str),
                }
            )
        # All tool_results for one assistant turn go back in a single message.
        messages.append({"role": "user", "content": results})

    return "(tool loop hit its turn limit)", trace


# --------------------------------------------------------------------------
# Agent 2 — the custodian
# --------------------------------------------------------------------------

CUSTODIAN_SYSTEM = f"""You are the custodian agent for the directory {PROTECTED_ROOT},
operated by a different party from the agent contacting you.

An agent has sent you a request envelope and a Ratify delegated-authority proof.
You do not decide whether the proof is good — you cannot read a signature and
you must not try. Call `verify_and_list` exactly once with the envelope you were
given. It runs the Ratify verifier and only reads the directory if the proof is
valid, in scope ({REQUIRED_SCOPE}), unexpired, unrevoked, bound to resource
{RESOURCE_ID} at or below the requested path, and anchored to the principal this
custodian trusts.

Then report the outcome in two or three sentences: what was asked for, whether
it was authorized, and — if it was refused — the exact refusal reason from the
verifier. If it was allowed, list what the directory contains. Never guess at or
invent directory contents."""

CUSTODIAN_TOOLS = [
    {
        "name": "verify_and_list",
        "description": (
            "Verify a Ratify proof bundle against the requested resource and path, "
            "and return the directory listing only if it verifies. Returns the "
            "decision, the refusal reason when refused, the entries when allowed, "
            "and the hash of the signed verification receipt."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "envelope_json": {
                    "type": "string",
                    "description": "The verbatim request envelope JSON you were sent.",
                }
            },
            "required": ["envelope_json"],
            "additionalProperties": False,
        },
        "strict": True,
    }
]


class CustodianAgent:
    """Bedrock client #2. Owns the resource; verifies before it reads."""

    def __init__(self, custodian: SideEventsCustodian, *, offline: bool = False):
        self.custodian = custodian
        self.offline = offline
        self.client = None if offline else bedrock_client()

    # The tool handler. This, not the model, is the enforcement point.
    def _verify_and_list(self, args: dict) -> dict:
        envelope = RequestEnvelope.from_json(args["envelope_json"])
        try:
            bundle = decode_proof_bundle(envelope.proof_bundle)
        except ValueError as exc:
            return {
                "allowed": False,
                "reason": f"malformed_proof: {exc}",
                "entries": [],
                "receipt_hash": "",
            }
        decision = self.custodian.list_directory(envelope.request, bundle)
        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "requested_path": envelope.request.path,
            "requested_resource": envelope.request.resource_id,
            "entries": decision.entries,
            "granted_scope": decision.granted_scope,
            "principal": decision.human_id,
            "agent": decision.agent_id,
            "receipt_hash": decision.receipt_hash_b64,
            "handler_invocations": decision.handler_invocations,
        }

    def handle(self, envelope: RequestEnvelope) -> ResponseEnvelope:
        raw = envelope.to_json()

        if self.offline:
            out = self._verify_and_list({"envelope_json": raw})
            return _response(out, summary=_scripted_summary(out))

        text, trace = run_tool_loop(
            self.client,
            system=CUSTODIAN_SYSTEM,
            user_message=(
                "An agent is requesting a directory listing. Review what it is "
                "asking for, then verify its authority.\n\nEnvelope:\n" + raw
            ),
            tools=CUSTODIAN_TOOLS,
            handlers={"verify_and_list": self._verify_and_list},
        )
        out = trace[-1]["output"] if trace else {
            "allowed": False,
            "reason": "no_verification_attempted: the custodian model never called the verifier",
            "entries": [],
            "receipt_hash": "",
        }
        return _response(out, summary=text)


def _response(out: dict, summary: str) -> ResponseEnvelope:
    return ResponseEnvelope(
        allowed=bool(out.get("allowed")),
        reason=str(out.get("reason", "")),
        entries=list(out.get("entries") or []),
        receipt_hash=str(out.get("receipt_hash", "")),
        summary=summary,
    )


def _scripted_summary(out: dict) -> str:
    if out.get("allowed"):
        names = ", ".join(e["name"] for e in out["entries"]) or "(empty)"
        return (
            f"Authorized for {out['requested_path']} under scope "
            f"{out.get('granted_scope')}; returning {len(out['entries'])} entries: {names}."
        )
    return f"Refused {out.get('requested_path')}: {out.get('reason')}"


# --------------------------------------------------------------------------
# Agent 1 — the requester
# --------------------------------------------------------------------------

REQUESTER_SYSTEM = f"""You are an assistant that can ask another organisation's
custodian agent for a listing of the directory {PROTECTED_ROOT}.

You do not have access to that directory. You hold a delegation certificate a
principal signed, bounded to one resource and one path prefix. To get a listing,
call `request_directory` with the path you want, written as a logical path
inside the resource: "/" for the top level, "/tools" for a subdirectory.

The custodian may refuse. If it does, report the refusal reason it gave and do
not retry the same path or attempt to work around it. Report what you were told,
nothing more."""

REQUESTER_TOOLS = [
    {
        "name": "request_directory",
        "description": (
            "Ask the SideEvents custodian agent for a directory listing. Presents "
            "your delegation and a freshly signed challenge. Returns the "
            "custodian's decision and, if allowed, the entries."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": 'Logical path inside the resource, e.g. "/" or "/tools".',
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "strict": True,
    }
]


class RequesterAgent:
    """Bedrock client #1. Holds a delegation; holds no access."""

    def __init__(
        self,
        agent: Party,
        chain: list[DelegationCert],
        custodian_agent: CustodianAgent,
        *,
        offline: bool = False,
        resource_id: str = RESOURCE_ID,
    ):
        self.agent = agent
        self.chain = chain
        self.peer = custodian_agent
        self.resource_id = resource_id
        self.offline = offline
        self.client = None if offline else bedrock_client()
        self.session_id = f"session-{uuid.uuid4()}"
        self.last_response: ResponseEnvelope | None = None

    def present(self, path: str, *, resource_id: str | None = None) -> ResponseEnvelope:
        """One full round trip: challenge, sign, send, receive."""
        req = DirectoryRequest(
            session_id=self.session_id,
            invocation_id=f"inv-{uuid.uuid4()}",
            resource_id=resource_id or self.resource_id,
            path=path,
        )
        challenge, ctx = self.peer.custodian.issue_challenge(req, self.agent.id)
        bundle = build_proof(self.agent, self.chain, challenge, ctx)
        response = self.peer.handle(RequestEnvelope(req, wire(bundle)))
        self.last_response = response
        return response

    def _request_directory(self, args: dict) -> dict:
        response = self.present(args["path"])
        return {
            "allowed": response.allowed,
            "reason": response.reason,
            "entries": response.entries,
            "custodian_said": response.summary,
            "receipt_hash": response.receipt_hash,
        }

    def ask(self, instruction: str) -> str:
        if self.offline:
            out = self._request_directory({"path": "/"})
            return _scripted_requester_report(out)

        text, _trace = run_tool_loop(
            self.client,
            system=REQUESTER_SYSTEM,
            user_message=instruction,
            tools=REQUESTER_TOOLS,
            handlers={"request_directory": self._request_directory},
        )
        return text


def _scripted_requester_report(out: dict) -> str:
    if out["allowed"]:
        return (
            "The custodian authorized the request. "
            + out["custodian_said"]
            + f" Receipt {out['receipt_hash']}."
        )
    return f"The custodian refused: {out['reason']}"
