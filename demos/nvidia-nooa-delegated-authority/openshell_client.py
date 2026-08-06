# SPDX-License-Identifier: Apache-2.0
"""Client half of the OpenShell profile. Runs INSIDE the sandbox.

Standard library only, because the sandbox is egress-restricted to the MCP
endpoint by the very policy under test and cannot reach a package index.
Requests are assembled as raw JSON where a case needs to express something a
Python dict cannot, such as a duplicate object member.

    python3 client.py <job.json> <result.json> <selector>

``selector`` is either ``handshake`` or a case index. One invocation performs
exactly one step, which is what lets the runner take a snapshot immediately
before and immediately after each case and attribute the delta to that case
alone. Batching the whole group into one invocation would make the deltas
inseparable.

The job file is uploaded once per group with ``openshell sandbox upload`` and
the selector is a small fixed argument, so nothing here depends on how much
data a command line can carry. An earlier version inlined the client and its
vectors into a single ``/bin/sh -c`` payload that reached 592,073 bytes and
crossed the CLI, gRPC, the gateway, the supervisor, and the container exec API
before reaching a shell. Any one of those can impose a limit below the host's
ARG_MAX, and the observed failure mode was a silently empty result.

The MCP session id is persisted to a file in the sandbox between invocations,
so a group's cases share one session without the runner having to pass it
through an argument. The session id is a transport correlation handle, not a
credential: every authorization decision is made by the receiver against a
challenge the receiver issued.

This half reports what happened and interprets nothing. All judgement lives in
the runner, which is outside the sandbox and therefore outside the blast
radius of anything the sandbox does.
"""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.error
import urllib.request

#: Every network call is bounded. The sandbox has no supervision of its own,
#: and an unbounded read against a policy-blocked endpoint would hang the
#: exec, which is a failure mode this profile has already been bitten by.
HTTP_TIMEOUT_SECONDS = 30

ENV = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


def post(url, body, headers, timeout=HTTP_TIMEOUT_SECONDS):
    """POST raw bytes. Returns (status, text, headers). Never raises for HTTP status.

    A blocked connection is a result, not an error: OpenShell refusing to open
    the socket is exactly what several cases are testing for, so the transport
    failure is captured and reported rather than raised.
    """
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace"), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace"), dict(exc.headers)
    except Exception as exc:  # noqa: BLE001 - a blocked connection is a result
        return None, f"TRANSPORT_ERROR:{type(exc).__name__}:{exc}", {}


def decode(text):
    """MCP may answer as JSON or as an SSE frame."""
    if not text:
        return {}
    try:
        return json.loads(text.split("data: ", 1)[1] if "data: " in text else text)
    except Exception:  # noqa: BLE001
        return {"_unparsed": text[:400]}


def tool_text(payload):
    """The tool's own JSON result, when it produced one.

    A refused call answers with ``isError`` and a plain-text message rather
    than JSON, so this returns None and the caller reports the error text
    separately. Both are real outcomes and neither may be mistaken for the
    other.
    """
    try:
        return json.loads(payload["result"]["content"][0]["text"])
    except Exception:  # noqa: BLE001
        return None


def error_text(payload):
    try:
        if payload["result"].get("isError"):
            return payload["result"]["content"][0]["text"][:300]
    except Exception:  # noqa: BLE001
        pass
    return None


def base_headers(session=None, method=None, name=None, extra=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["mcp-session-id"] = session
    if method:
        headers["mcp-method"] = method
    if name:
        headers["mcp-name"] = name
    headers.update(extra or {})
    return headers


def handshake(url, session_path):
    """initialize, notifications/initialized, tools/list. Persists the session."""
    out = {}
    status, text, headers = post(
        url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "openshell-profile", "version": "1"},
            },
        },
        base_headers(method="initialize"),
    )
    out["initialize"] = {"http_status": status, "body_head": text[:200]}
    if status != 200:
        return out
    session = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
    out["session"] = session
    pathlib.Path(session_path).write_text(session or "")

    status, text, _ = post(
        url,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        base_headers(session, "notifications/initialized"),
    )
    out["notifications_initialized"] = {"http_status": status}

    status, text, _ = post(
        url,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": ENV}},
        base_headers(session, "tools/list"),
    )
    payload = decode(text)
    out["tools_list"] = {
        "http_status": status,
        "tools": sorted(
            t.get("name") for t in payload.get("result", {}).get("tools", []) or []
        ),
    }
    return out


def run_case(case, url, session):
    """Send one case and report the observable outcome."""
    target = case.get("url") or url
    body = case["raw"].encode() if case.get("raw") else case["body"]
    status, text, _ = post(
        target,
        body,
        base_headers(
            session if not case.get("no_session") else None,
            case.get("hdr_method"),
            case.get("hdr_name"),
            case.get("extra_headers"),
        ),
    )
    payload = decode(text)
    parsed = tool_text(payload)
    result = {
        "http_status": status,
        "url": target,
        # OpenShell's refusal is visible in the body it substitutes. Recorded
        # as an observation; the runner decides what it means.
        "policy_denied": isinstance(text, str) and "policy_denied" in text,
        "transport_error": isinstance(text, str) and text.startswith("TRANSPORT_ERROR:"),
        "jsonrpc_error": (
            payload.get("error", {}).get("message")
            if isinstance(payload.get("error"), dict)
            else None
        ),
        "is_error": (
            payload.get("result", {}).get("isError")
            if isinstance(payload.get("result"), dict)
            else None
        ),
        "error_text": error_text(payload),
        "decision": (parsed or {}).get("decision"),
        "status_code": (parsed or {}).get("status"),
        "reason": ((parsed or {}).get("reason") or "")[:160],
        "receipt_id": (parsed or {}).get("receipt_id"),
        "refunded": (parsed or {}).get("refunded"),
        "body_head": text[:200] if isinstance(text, str) else None,
    }
    # refund.prepare returns the challenge and session binding the receiver
    # derived. The runner needs them verbatim to have a proof signed.
    if isinstance(parsed, dict) and "challenge" in parsed:
        result["prepared"] = parsed
    return result


def main() -> None:
    job_path, out_path, selector = sys.argv[1], sys.argv[2], sys.argv[3]
    job = json.loads(pathlib.Path(job_path).read_text())
    url = job["url"]
    session_path = job["session_file"]

    if selector == "handshake":
        payload = {"group": job.get("group"), "step": "handshake",
                   "result": handshake(url, session_path)}
    else:
        index = int(selector)
        case = job["cases"][index]
        session = None
        try:
            session = pathlib.Path(session_path).read_text().strip() or None
        except OSError:
            session = None
        payload = {
            "group": job.get("group"),
            "step": index,
            "case": case["name"],
            "session_present": session is not None,
            "result": run_case(case, url, session),
        }

    pathlib.Path(out_path).write_text(json.dumps(payload))
    # Also to stdout, so a download failure does not lose the evidence.
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
