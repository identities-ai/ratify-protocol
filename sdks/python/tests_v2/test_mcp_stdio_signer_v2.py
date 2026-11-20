"""The stdio signer (ratify-mcp-signer) against a local fake of the hosted
Verify MCP service over real TLS: the tools/call flow, both MCP client eras,
key handling, and the CLI. No network beyond localhost."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import shutil
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ratify_protocol.v2 import _native, generate_keypair_v2, key_id_v2
from ratify_protocol.v2.protocol_v2 import (
    DelegationCertV2,
    decode_proof_bundle_v2,
    encode_delegation_cert_v2,
    sign_delegation_cert_v2,
    verify_proof_bundle_v2_signatures,
)

pytest.importorskip("keyring")
pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="signing needs ratify-protocol-native-v2")

from ratify_protocol.v2.mcp import binding, cli, keys  # noqa: E402
from ratify_protocol.v2.mcp.errors import ConfigError, McpError  # noqa: E402
from ratify_protocol.v2.mcp.server import StdioServer  # noqa: E402
from ratify_protocol.v2.mcp.signer import Signer, SignerConfig  # noqa: E402

VERIFIER_ID = "1111111111111111111111111111111111111111111111111111111111111111"
WORKSPACE_ID = "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
CONNECTION_ID = "3f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
INVOCATION_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
CHALLENGE = base64.b64encode(bytes(range(32))).decode()
SERVER_INFO = {"io.modelcontextprotocol/serverInfo": {"name": "ratify-verify-mcp", "version": "1"}}


@pytest.fixture(scope="session")
def tls_cert(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required to create the test certificate")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return str(cert), str(key)


class FakeService:
    """Records every request and answers per ``self.challenge_reply`` /
    ``self.mcp_reply`` (callables returning (status, headers, body bytes))."""

    def __init__(self):
        self.requests: list[dict] = []
        self.clock = time.time
        self.challenge_reply = self.default_challenge
        self.mcp_reply = self.default_mcp

    def challenge_body(self, **override) -> dict:
        now = int(self.clock())
        body = {"challenge": CHALLENGE, "invocation_id": INVOCATION_ID, "verifier_id": VERIFIER_ID,
                "workspace_id": WORKSPACE_ID, "required_scope": None, "issued_at": now, "expires_at": now + 120}
        body.update(override)
        return body

    def default_challenge(self, req):
        body = self.challenge_body(required_scope=binding.tool_scope(req["json"]["tool"]))
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()

    def default_mcp(self, req):
        msg = req["json"]
        method = msg["method"]
        if method == "tools/call":
            result = {"content": [{"type": "text", "text": "ok"}], "structuredContent": {"n": 1},
                      "isError": False, "resultType": "complete", "_meta": SERVER_INFO}
        elif method == "tools/list":
            result = {"tools": [{"name": "get_metrics"}], "resultType": "complete", "_meta": SERVER_INFO}
        else:
            result = {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}},
                      "serverInfo": {"name": "ratify-verify-mcp", "version": "1"},
                      "resultType": "complete", "_meta": SERVER_INFO}
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()


@pytest.fixture
def fake_service(tls_cert):
    service = FakeService()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            req = {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                   "raw": raw, "json": json.loads(raw)}
            service.requests.append(req)
            reply = service.challenge_reply if self.path == "/challenge" else service.mcp_reply
            status, headers, body = reply(req)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*tls_cert)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    service.port = httpd.server_address[1]
    service.endpoint = f"https://localhost:{service.port}"
    service.ca_file = tls_cert[0]
    yield service
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="session")
def agent_keys():
    root_pub, root_priv = generate_keypair_v2()
    agent_pub, agent_priv = generate_keypair_v2()
    now = int(time.time())
    cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2, cert_id="mcp-test", issuer_id=key_id_v2(root_pub), issuer_pub_key=root_pub,
        subject_id=key_id_v2(agent_pub), subject_pub_key=agent_pub,
        scope=sorted({s for _, s in binding.TOOLS}), constraints=[],
        issued_at=now - 60, expires_at=now + 86400), root_priv)
    return {"agent_pub": agent_pub, "agent_priv": agent_priv, "root_pub": root_pub,
            "cert_wire": encode_delegation_cert_v2(cert), "root_priv": root_priv}


@pytest.fixture
def private_dir(tmp_path):
    d = tmp_path / "signer"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)
    return d


@pytest.fixture
def key_file(private_dir, agent_keys):
    path = private_dir / "agent.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, keys._encode_private(agent_keys["agent_pub"], agent_keys["agent_priv"]))
    os.close(fd)
    return path


@pytest.fixture
def config_dict(fake_service, agent_keys, key_file):
    return {"endpoint": fake_service.endpoint, "audience": fake_service.endpoint + "/mcp",
            "verifier_id": VERIFIER_ID, "workspace_id": WORKSPACE_ID, "connection_id": CONNECTION_ID,
            "delegations": [base64.b64encode(agent_keys["cert_wire"]).decode()],
            "key": {"kind": "file", "path": str(key_file)}}


@pytest.fixture
def config_file(private_dir, config_dict):
    path = private_dir / "config.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps(config_dict).encode())
    os.close(fd)
    return path


@pytest.fixture
def signer(config_file, fake_service):
    return Signer.from_config(str(config_file), ca_file=fake_service.ca_file)


def decode_proof(req: dict):
    """Decode and signature-check the proof bundle the shim sent."""
    proof = req["json"]["params"]["_meta"]["com.ratifyprotocol/proof"]
    bundle = decode_proof_bundle_v2(base64.b64decode(proof["bundle"]))
    verify_proof_bundle_v2_signatures(bundle)
    return proof, bundle




# --- tools/call flow ---
def test_call_sends_required_headers_and_meta(signer, fake_service):
    result = signer.call_tool("list_decisions", {"limit": 5, "decision": "deny"})
    assert result["isError"] is False
    ch, call = fake_service.requests
    assert ch["path"] == "/challenge" and call["path"] == "/mcp"
    for req in (ch, call):
        h = req["headers"]
        assert h["content-type"] == "application/json"
        assert h["accept"] == "application/json, text/event-stream"
        assert "origin" not in h  # any Origin is refused by the hosted service
    assert call["headers"]["mcp-protocol-version"] == "2026-07-28"
    assert call["headers"]["mcp-method"] == "tools/call"
    assert call["headers"]["mcp-name"] == "list_decisions"
    canonical = b'{"decision":"deny","limit":5}'
    assert ch["json"] == {"connection_id": CONNECTION_ID, "tool": "list_decisions",
                          "payload_digest": "sha256:" + hashlib.sha256(canonical).hexdigest()}
    meta = call["json"]["params"]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
    assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "ratify-mcp-signer"
    assert call["json"]["params"]["name"] == "list_decisions"
    assert call["json"]["params"]["arguments"] == {"limit": 5, "decision": "deny"}


def test_proof_binds_the_call_and_pins(signer, fake_service, agent_keys):
    """The bundle is a valid signed v2 bundle whose session context is the one
    recomputed from the call as received, not anything the server suggested."""
    def challenge(req):
        body = fake_service.challenge_body(required_scope="custom:verify.metrics:read",
                                           request_hash="00" * 32, session_context="ff" * 32)
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()
    fake_service.challenge_reply = challenge
    signer.call_tool("get_metrics", {"from": "2026-11-01T00:00:00Z"})
    ch, call = fake_service.requests
    proof, bundle = decode_proof(call)
    assert proof["connection_id"] == CONNECTION_ID
    assert proof["invocation_id"] == INVOCATION_ID
    assert proof["challenge"] == CHALLENGE
    assert bundle.version == 2 and bundle.verifier_id == VERIFIER_ID
    assert bundle.agent_id == signer.agent_id
    assert bundle.challenge == base64.b64decode(CHALLENGE)
    assert len(bundle.delegations) == 1
    # Recompute exactly as the hosted service does from what it received.
    received_args = call["json"]["params"]["arguments"]
    digest = binding.payload_digest(binding.canonical_arguments(received_args))
    rh = binding.request_hash("get_metrics", CONNECTION_ID, signer.config.audience, digest)
    sc = binding.session_context(VERIFIER_ID, WORKSPACE_ID, signer.agent_id, CONNECTION_ID, INVOCATION_ID, rh)
    assert bundle.session_context == sc
    assert bundle.session_context != bytes.fromhex("ff" * 32)


def test_challenge_at_equals_issued_at(signer, fake_service):
    """challenge_at is the authenticated issuance time exactly, never the
    local clock (the verifier rejects anything else)."""
    sent = {}

    def challenge(req):
        body = fake_service.challenge_body(required_scope="custom:verify.metrics:read")
        body["issued_at"] = body["expires_at"] - 115  # deliberately not "now"
        sent.update(body)
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()
    fake_service.challenge_reply = challenge
    signer.call_tool("get_metrics", {})
    _, bundle = decode_proof(fake_service.requests[1])
    assert bundle.challenge_at == sent["issued_at"]


@pytest.mark.parametrize("override", [
    {"verifier_id": "2" * 64},
    {"workspace_id": "00000000-0000-4000-8000-000000000000"},
    {"required_scope": "custom:verify.evidence:read"},
    {"invocation_id": "not-a-uuid"},
    {"challenge": base64.b64encode(b"short").decode()},
    {"challenge": "!!!"},
    {"expires_at": None},
])
def test_refuses_challenge_that_differs_from_pins(signer, fake_service, override):
    def challenge(req):
        body = fake_service.challenge_body(required_scope="custom:verify.metrics:read")
        body.update(override)
        if override.get("expires_at", 0) is None:
            body["expires_at"] = int(fake_service.clock()) + 5  # under 10 s left
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()
    fake_service.challenge_reply = challenge
    with pytest.raises(McpError) as exc:
        signer.call_tool("get_metrics", {})
    assert "signer refused the challenge" in exc.value.error["message"]
    assert [r["path"] for r in fake_service.requests] == ["/challenge"]  # nothing signed or sent


def test_value_model_violation_requests_no_challenge(signer, fake_service):
    for bad in ({"limit": 1.5}, {"x": None}, {"s": "\x07"}):
        with pytest.raises(McpError) as exc:
            signer.call_tool("list_decisions", bad)
        assert exc.value.code == -32602
    with pytest.raises(McpError) as exc:
        signer.call_tool("delete_everything", {})
    assert exc.value.code == -32602
    assert fake_service.requests == []


def test_hosted_challenge_error_passes_through_unchanged(signer, fake_service):
    err = {"code": -31007, "message": "rate_limited", "data": {"retry_after_seconds": 7}}
    fake_service.challenge_reply = lambda req: (429, {"Content-Type": "application/json", "Retry-After": "7"},
                                                json.dumps({"error": err}).encode())
    with pytest.raises(McpError) as exc:
        signer.call_tool("get_metrics", {})
    assert exc.value.error == err


@pytest.mark.parametrize("status,err", [
    (403, {"code": -31004, "message": "denied", "data": {"decision_reason": "scope_denied", "claim_id": "c1"}}),
    (429, {"code": -31007, "message": "rate_limited", "data": {"retry_after_seconds": 3}}),
    (503, {"code": -31008, "message": "verify_unavailable"}),
])
def test_hosted_mcp_error_passes_through_unchanged(signer, fake_service, status, err):
    fake_service.mcp_reply = lambda req: (status, {"Content-Type": "application/json"}, json.dumps(
        {"jsonrpc": "2.0", "id": req["json"]["id"], "error": err}).encode())
    with pytest.raises(McpError) as exc:
        signer.call_tool("get_metrics", {})
    assert exc.value.error == err and exc.value.hosted


def test_accepts_event_stream_response(signer, fake_service):
    def sse(req):
        msg = {"jsonrpc": "2.0", "id": req["json"]["id"], "result": {"content": [], "isError": False,
                                                                     "resultType": "complete"}}
        body = (": keepalive\n\nevent: message\ndata: " + json.dumps(msg) + "\n\n").encode()
        return 200, {"Content-Type": "text/event-stream"}, body
    fake_service.mcp_reply = sse
    assert signer.call_tool("get_metrics", {})["resultType"] == "complete"


def test_refuses_response_for_another_request(signer, fake_service):
    fake_service.mcp_reply = lambda req: (200, {"Content-Type": "application/json"}, json.dumps(
        {"jsonrpc": "2.0", "id": 999, "result": {}}).encode())
    with pytest.raises(McpError):
        signer.list_tools()


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_refuses_redirects(signer, fake_service, status):
    fake_service.challenge_reply = lambda req: (status, {"Location": "https://evil.example/challenge"}, b"")
    with pytest.raises(McpError) as exc:
        signer.call_tool("get_metrics", {})
    assert "redirect" in exc.value.error["message"]
    assert len(fake_service.requests) == 1


def test_tls_verification_is_on(config_file, fake_service):
    s = Signer.from_config(str(config_file))  # platform trust store; self-signed cert must fail
    with pytest.raises(McpError) as exc:
        s.list_tools()
    assert "TLS" in exc.value.error["message"]
    assert fake_service.requests == []


@pytest.mark.parametrize("endpoint", ["http://localhost:1", "https://localhost:1/", "https://LOCALHOST:1",
                                      "https://u:p@localhost:1", "https://localhost:1/x", "ftp://localhost"])
def test_refuses_non_https_or_non_canonical_endpoint(config_dict, endpoint):
    config_dict["endpoint"] = endpoint
    config_dict["audience"] = endpoint.rstrip("/") + "/mcp"
    with pytest.raises(ConfigError):
        SignerConfig.from_dict(config_dict)


def test_refuses_mismatched_audience(config_dict):
    config_dict["audience"] = "https://other.example/mcp"
    with pytest.raises(ConfigError):
        SignerConfig.from_dict(config_dict)


def test_refuses_chain_for_another_key(config_dict, agent_keys):
    _, other = generate_keypair_v2()
    with pytest.raises(ConfigError):
        Signer(SignerConfig.from_dict(config_dict).client, private_key=other)


def test_signer_repr_has_no_key(signer):
    assert "ml_dsa" not in repr(signer) and "private" not in repr(signer).lower()


# --- stdio server ---
def run(signer, messages):
    stdin = io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in messages))
    stdout = io.BytesIO()
    StdioServer(signer, stdin, stdout).serve()
    lines = stdout.getvalue().splitlines()
    return [json.loads(line) for line in lines]


def test_2025_11_25_client_with_initialize(signer, fake_service):
    out = run(signer, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_metrics", "arguments": {}}},
    ])
    assert [m["id"] for m in out] == [1, 2, 3, 4]  # no reply to the notification
    assert out[0]["result"]["protocolVersion"] == "2025-11-25"
    assert out[0]["result"]["capabilities"] == {"tools": {}}
    assert out[1]["result"] == {}
    for m in out[2:]:
        assert "resultType" not in m["result"]  # not defined in 2025-11-25
    assert out[3]["result"]["structuredContent"] == {"n": 1}
    # initialize and ping are answered locally; only list + challenge + call went out.
    assert [r["path"] for r in fake_service.requests] == ["/mcp", "/challenge", "/mcp"]


def test_2026_07_28_client_with_server_discover(signer, fake_service):
    out = run(signer, [
        {"jsonrpc": "2.0", "id": "a", "method": "server/discover", "params": {}},
        {"jsonrpc": "2.0", "id": "b", "method": "tools/call", "params": {"name": "get_metrics", "arguments": {},
         "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}},
    ])
    assert out[0]["result"]["resultType"] == "complete"
    assert out[0]["result"]["supportedVersions"] == ["2026-07-28"]
    assert out[1]["result"]["resultType"] == "complete"
    discover = fake_service.requests[0]
    assert discover["headers"]["mcp-method"] == "server/discover"
    assert discover["json"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"


def test_hosted_error_reaches_client_unchanged(signer, fake_service):
    err = {"code": -31007, "message": "rate_limited", "data": {"retry_after_seconds": 9}}
    fake_service.mcp_reply = lambda req: (429, {"Content-Type": "application/json"}, json.dumps(
        {"jsonrpc": "2.0", "id": req["json"]["id"], "error": err}).encode())
    out = run(signer, [{"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                        "params": {"name": "get_metrics", "arguments": {}}}])
    assert out == [{"jsonrpc": "2.0", "id": 7, "error": err}]


def test_invalid_arguments_from_client(signer, fake_service):
    stdin = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_agents",'
                       b'"arguments":{"limit":1,"limit":2}}}\n'
                       b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_agents",'
                       b'"arguments":{"limit":2.0}}}\n'
                       b'not json\n'
                       b'{"jsonrpc":"2.0","id":3,"method":"resources/list"}\n')
    stdout = io.BytesIO()
    StdioServer(signer, stdin, stdout).serve()
    out = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [m.get("error", {}).get("code") for m in out] == [-32602, -32602, -32700, -32601]
    assert fake_service.requests == []


# --- keys and CLI ---
def _secret_fragments(key_path):
    obj = json.loads(open(key_path).read())
    ed = base64.b64decode(obj["ed25519_private_key"])[:32]
    ml = base64.b64decode(obj["mldsa65_private_key"])
    # The ML-DSA secret key starts with rho, which is also public (the first
    # 32 bytes of the public key), so check from byte 33 (base64 char 44) on.
    return [obj["ed25519_private_key"][:24], obj["mldsa65_private_key"][44:84],
            obj["mldsa65_private_key"][-24:], ed.hex()[:24], ml[32:64].hex(), base64.b64encode(ed).decode()[:24]]


def _assert_no_secret(text, key_path):
    for frag in _secret_fragments(key_path):
        assert frag not in text


@pytest.mark.parametrize("target,mode", [("key", 0o644), ("key", 0o640), ("config", 0o644), ("dir", 0o755)])
def test_wide_permissions_refuse_to_start(config_file, key_file, private_dir, fake_service, capsys, caplog,
                                          target, mode):
    path = {"key": key_file, "config": config_file, "dir": private_dir}[target]
    os.chmod(path, mode)
    caplog.set_level(logging.DEBUG)
    rc = cli.main(["serve", "--config", str(config_file)])
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "chmod" in captured.err
    os.chmod(path, 0o700 if target == "dir" else 0o600)
    _assert_no_secret(captured.err + caplog.text, key_file)


def test_corrupt_key_error_does_not_echo_key(key_file, config_file, capsys):
    data = open(key_file).read()
    os.chmod(key_file, 0o600)
    with open(key_file, "w") as f:
        f.write(data.replace('"mldsa65_private_key": "', '"mldsa65_private_key": "!'))
    with pytest.raises(ConfigError) as exc:
        keys.load_key({"kind": "file", "path": str(key_file)})
    assert exc.value.__cause__ is None and exc.value.__context__ is None or exc.value.__suppress_context__
    assert data[40:80] not in str(exc.value)


def test_symlinked_key_is_refused(private_dir, key_file):
    link = private_dir / "link.key"
    os.symlink(key_file, link)
    with pytest.raises(ConfigError):
        keys.load_key({"kind": "file", "path": str(link)})


def test_calls_never_log_or_print_secrets(signer, fake_service, key_file, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    stdin = io.BytesIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "get_decision", "arguments": {"claim_id": "secret-arg-123"}}}
                                  ).encode() + b"\n")
    stdout = io.BytesIO()
    StdioServer(signer, stdin, stdout).serve()
    proof = fake_service.requests[1]["json"]["params"]["_meta"]["com.ratifyprotocol/proof"]
    captured = capsys.readouterr()
    logs = caplog.text + captured.err + captured.out
    _assert_no_secret(logs + stdout.getvalue().decode(), key_file)
    assert "secret-arg-123" not in logs
    assert proof["bundle"][:40] not in logs and proof["bundle"][:40] not in stdout.getvalue().decode()


def test_init_file_store_configure_and_test(tmp_path, fake_service, agent_keys, capsys, monkeypatch):
    d = tmp_path / "conn"
    assert cli.main(["init", "--dir", str(d), "--key-store", "file", "--label", "laptop"]) == 0
    out = capsys.readouterr()
    pub = json.loads(out.out)
    assert set(pub) == {"ed25519", "ml_dsa_65"}
    assert (d / "agent-public.json").read_text().strip() == out.out.strip()
    assert "Key ID: " in out.err
    assert os.stat(d).st_mode & 0o777 == 0o700
    cfg = json.loads((d / "config.json").read_text())
    key_path = cfg["key"]["path"]
    assert os.stat(key_path).st_mode & 0o777 == 0o600
    assert os.stat(d / "config.json").st_mode & 0o777 == 0o600
    _assert_no_secret(out.out + out.err, key_path)

    # The public key printed is exactly the canonical form ratify-keys prints.
    from ratify_protocol.v2 import HybridPublicKey
    hp = HybridPublicKey(base64.b64decode(pub["ed25519"]), base64.b64decode(pub["ml_dsa_65"]))
    assert keys.public_key_json(hp).decode() == out.out.strip()
    assert f"Key ID: {key_id_v2(hp)}" in out.err

    # Console issues a delegation to that key; configure merges client_config.
    now = int(time.time())
    cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2, cert_id="mcp-x", issuer_id=key_id_v2(agent_keys["root_pub"]),
        issuer_pub_key=agent_keys["root_pub"], subject_id=key_id_v2(hp), subject_pub_key=hp,
        scope=["custom:verify.metrics:read"], constraints=[], issued_at=now - 5, expires_at=now + 3600),
        agent_keys["root_priv"])
    console = tmp_path / "console.json"
    console.write_text(json.dumps({"client_config": {
        "endpoint": fake_service.endpoint, "audience": fake_service.endpoint + "/mcp",
        "verifier_id": "1" * 64, "workspace_id": "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
        "connection_id": "3f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
        "delegations": [base64.b64encode(encode_delegation_cert_v2(cert)).decode()]}}))
    assert cli.main(["configure", "--config", str(d / "config.json"), "--from", str(console)]) == 0
    capsys.readouterr()
    assert os.stat(d / "config.json").st_mode & 0o777 == 0o600

    # The test subcommand makes one get_metrics call (TLS trusted via test CA).
    real = Signer.from_config
    monkeypatch.setattr(Signer, "from_config", classmethod(
        lambda cls, p, **kw: real.__func__(cls, p, ca_file=fake_service.ca_file)))
    assert cli.main(["test", "--config", str(d / "config.json")]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["outcome"] == "allowed"
    assert fake_service.requests[0]["json"]["tool"] == "get_metrics"
    _assert_no_secret(out.out + out.err, key_path)


def test_configure_refuses_console_key_and_missing_fields(config_file, tmp_path):
    bad = tmp_path / "c.json"
    bad.write_text(json.dumps({"key": {"kind": "file", "path": "/var/empty/x"}}))
    with pytest.raises(ConfigError):
        cli.merge_console_config(str(config_file), bad.read_bytes())


def test_init_refuses_wide_existing_dir(tmp_path):
    d = tmp_path / "wide"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    assert cli.main(["init", "--dir", str(d), "--key-store", "file"]) == 2


def test_keyring_store_roundtrip(monkeypatch, tmp_path, agent_keys):
    import keyring
    from keyring.backend import KeyringBackend

    class Mem(KeyringBackend):
        priority = 1
        store: dict = {}

        def get_password(self, s, u):
            return self.store.get((s, u))

        def set_password(self, s, u, p):
            self.store[(s, u)] = p

        def delete_password(self, s, u):
            self.store.pop((s, u), None)

    keyring.set_keyring(Mem())
    try:
        ref = keys.store_key(agent_keys["agent_pub"], agent_keys["agent_priv"], kind="keyring",
                             directory=str(tmp_path), name="conn-1")
        assert ref == {"kind": "keyring", "service": "ratify-mcp-signer", "name": "conn-1"}
        pub, _ = keys.load_key(ref)
        assert pub == agent_keys["agent_pub"]
        with pytest.raises(ConfigError):
            keys.store_key(agent_keys["agent_pub"], agent_keys["agent_priv"], kind="keyring",
                           directory=str(tmp_path), name="conn-1")
    finally:
        from keyring.backends import fail
        keyring.set_keyring(fail.Keyring())


def test_stdio_refuses_ambiguous_or_non_object_calls(signer, fake_service):
    # Each of these would otherwise sign a call other than the one on the
    # wire: a JSON-text string taken as arguments, a repeated tool name
    # (last one wins), or -0 normalized to 0.
    stdin = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_metrics","arguments":"{}"}}\n'
                       b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_agents","name":"get_metrics"}}\n'
                       b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_agents","arguments":{"limit":-0}}}\n'
                       b'{"jsonrpc":"2.0","id":4,"id":5,"method":"ping"}\n')
    stdout = io.BytesIO()
    StdioServer(signer, stdin, stdout).serve()
    out = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [m.get("error", {}).get("code") for m in out] == [-32602, -32600, -32602, -32600]
    assert fake_service.requests == []


def test_prove_possession_honours_nested_client_config_pins(private_dir, key_file, capsys):
    # serve reads pins from a client_config object, so prove-possession must
    # refuse a token for another deployment the same way.
    import base64 as b64
    path = private_dir / "nested.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps({"key": {"kind": "file", "path": str(key_file)},
                             "client_config": {"audience": "https://verify.example/mcp"}}).encode())
    os.close(fd)
    payload = {"challenge_id": "8b1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f", "challenge": b64.b64encode(bytes(32)).decode(),
               "issued_at": 1790000000, "workspace_id": WORKSPACE_ID, "receiver_id": "7a1c2d3e-4a5b-5c6d-8e9f-0a1b2c3d4e5f",
               "audience": "https://other.example/mcp", "verifier_id": VERIFIER_ID}
    token = "ratify-mcp-connect-1." + b64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    assert cli.main(["prove-possession", "--config", str(path), "--challenge", token]) == 2
    assert "does not match" in capsys.readouterr().err
