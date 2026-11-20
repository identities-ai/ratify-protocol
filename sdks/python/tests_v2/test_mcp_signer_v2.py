"""Verify MCP signer vectors (testvectors/v2/mcp).

The hosted service recomputes every value below from the call it receives.
A signer that differs in one byte produces proofs the service rejects or,
worse, a proof that binds something other than the call the client asked
for. Every SDK runs these same files."""
from __future__ import annotations

import base64
import json

import pytest
from corpus import V2_DIR

from ratify_protocol.v2 import _native, mcp
from ratify_protocol.v2.protocol_v2 import decode_proof_bundle_v2, verify_proof_bundle_v2_signatures

MCP_DIR = V2_DIR / "mcp"
MCP_FILES = ("README.md", "binding.json", "client-config.json", "connect.json", "tool-call.json")

needs_native = pytest.mark.skipif(not _native.AVAILABLE, reason="signing needs ratify-protocol-native-v2")


def load(name: str) -> dict:
    return json.loads((MCP_DIR / name).read_text(encoding="utf-8"))


def agent_key(entry: dict):
    from ratify_protocol.v2 import key_id_v2, keypair_from_seeds_v2
    pub, priv = keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]), bytes.fromhex(entry["ml_dsa_65_seed_hex"]))
    assert key_id_v2(pub) == entry["key_id_v2"]
    return priv


def same_bundle(got_b64: str, want_b64: str) -> None:
    """Identical except the hedged ML-DSA-65 component of challenge_sig; both verify."""
    got_wire, want_wire = base64.b64decode(got_b64), base64.b64decode(want_b64)
    got, want = decode_proof_bundle_v2(got_wire), decode_proof_bundle_v2(want_wire)
    verify_proof_bundle_v2_signatures(got)
    verify_proof_bundle_v2_signatures(want)
    masked = got_wire.replace(base64.b64encode(bytes(got.challenge_sig.ml_dsa_65)),
                              base64.b64encode(bytes(want.challenge_sig.ml_dsa_65)), 1)
    assert masked == want_wire


def test_mcp_directory_holds_exactly_the_runner_files():
    assert sorted(p.name for p in MCP_DIR.iterdir()) == sorted(MCP_FILES)


def test_binding_vectors():
    f = load("binding.json")
    assert f["action"] == mcp.ACTION and f["proof_meta_key"] == mcp.PROOF_META_KEY
    assert [(t["name"], t["scope"]) for t in f["tools"]] == list(mcp.TOOLS)
    for c in f["cases"]:
        canonical = mcp.canonical_arguments(c["arguments_json"])
        assert canonical == c["canonical_arguments"].encode("utf-8"), c["name"]
        digest = mcp.payload_digest(canonical)
        assert mcp.payload_digest_text(digest) == c["payload_digest"], c["name"]
        req = mcp.request_hash(c["tool"], c["connection_id"], c["audience"], digest)
        assert req.hex() == c["request_hash"], c["name"]
        sess = mcp.session_context(c["verifier_id"], c["workspace_id"], c["agent_id"], c["connection_id"],
                                   c["invocation_id"], req)
        assert sess.hex() == c["session_context"], c["name"]
    for c in f["invalid_arguments"]:
        raw = base64.b64decode(c["arguments_base64"]) if "arguments_base64" in c else c["arguments_json"].encode()
        with pytest.raises(mcp.InvalidArgumentsError):
            mcp.canonical_arguments(raw)


def test_client_config_vectors():
    f = load("client-config.json")
    for c in f["valid"]:
        cfg = mcp.parse_client_config(c["config_json"])
        e = c["expected"]
        assert (cfg.endpoint, cfg.audience, cfg.verifier_id, cfg.workspace_id, cfg.connection_id) == (
            e["endpoint"], e["audience"], e["verifier_id"], e["workspace_id"], e["connection_id"]), c["name"]
        assert [d.cert_id for d in cfg.delegations] == e["delegation_cert_ids"], c["name"]
    for c in f["invalid"]:
        with pytest.raises(mcp.InvalidConfigError):
            mcp.parse_client_config(c["config_json"])


@needs_native
def test_tool_call_vectors():
    f = load("tool-call.json")
    cfg = mcp.parse_client_config(f["client_config_json"])
    agent, wrong = agent_key(f["agent_key"]), agent_key(f["wrong_agent_key"])
    for c in f["cases"]:
        call = mcp.new_tool_call(c["tool"], c["arguments_json"])
        assert call.canonical_arguments == c["canonical_arguments"].encode("utf-8"), c["name"]
        assert cfg.challenge_request(call) == c["challenge_request"].encode("utf-8"), c["name"]
        ch = cfg.check_challenge(c["tool"], c["challenge_response"], c["now"])
        req = mcp.request_hash(c["tool"], cfg.connection_id, cfg.audience, call.payload_digest)
        assert req.hex() == c["request_hash"], c["name"]
        assert mcp.session_context(cfg.verifier_id, cfg.workspace_id, f["agent_key"]["key_id_v2"], cfg.connection_id,
                                   ch.invocation_id, req).hex() == c["session_context"], c["name"]
        env = mcp.sign_tool_call(cfg, agent, call, ch)
        want = c["envelope"]
        assert (env.connection_id, env.invocation_id, env.challenge) == (
            want["connection_id"], want["invocation_id"], want["challenge"]), c["name"]
        same_bundle(env.bundle, want["bundle"])
        with pytest.raises(mcp.ChallengeRefusedError):
            mcp.sign_tool_call(cfg, wrong, call, ch)
    for c in f["refused_challenges"]:
        with pytest.raises(mcp.ChallengeRefusedError):
            cfg.check_challenge(c["tool"], c["challenge_response"], c["now"])
    assert f["refused_signings"]
    for c in f["refused_signings"]:
        ch = cfg.check_challenge(c["checked_tool"], c["challenge_response"], c["now"])
        sign_cfg = mcp.parse_client_config(c["signing_config_json"]) if c["signing_config_json"] else cfg
        call = mcp.new_tool_call(c["signing_tool"], c["signing_arguments_json"])
        with pytest.raises(mcp.ChallengeRefusedError):
            mcp.sign_tool_call(sign_cfg, agent, call, ch)


def test_connect_contexts_and_tokens():
    f = load("connect.json")
    assert f["domain"] == mcp.CONNECT_POSSESSION_DOMAIN and f["token_prefix"] == mcp.CONNECT_TOKEN_PREFIX
    for c in f["contexts"]:
        got = mcp.connect_possession_context(c["workspace_id"], c["receiver_id"], c["audience"],
                                             c["challenge_id"], c["agent_id"])
        assert got.hex() == c["session_context"], c["name"]
    for c in f["proofs"]:
        t = mcp.parse_connect_token(c["token"])
        p = c["parsed"]
        assert (t.challenge_id, base64.b64encode(t.challenge).decode(), t.issued_at, t.workspace_id,
                t.receiver_id, t.audience, t.verifier_id) == (
            p["challenge_id"], p["challenge"], p["issued_at"], p["workspace_id"], p["receiver_id"],
            p["audience"], p["verifier_id"]), c["name"]
    for c in f["invalid_tokens"]:
        with pytest.raises(mcp.InvalidConnectTokenError):
            mcp.parse_connect_token(c["token"])


@needs_native
def test_connect_proofs():
    f = load("connect.json")
    agent = agent_key(f["agent_key"])
    for c in f["proofs"]:
        proof = mcp.prove_possession(c["token"], agent)
        assert proof.connect_challenge_id == c["expected"]["connect_challenge_id"]
        same_bundle(proof.possession_proof, c["expected"]["possession_proof"])
    for c in f["invalid_tokens"]:
        with pytest.raises(mcp.InvalidConnectTokenError):
            mcp.prove_possession(c["token"], agent)


@needs_native
def test_a_challenge_signs_only_the_tool_it_was_checked_for():
    # A challenge is issued for one tool's scope; letting it sign another
    # tool's call would hand the server a proof the signer never checked.
    f = load("tool-call.json")
    cfg = mcp.parse_client_config(f["client_config_json"])
    c = f["cases"][0]
    ch = cfg.check_challenge(c["tool"], c["challenge_response"], c["now"])
    other = mcp.new_tool_call("list_agents", {})
    with pytest.raises(mcp.ChallengeRefusedError):
        mcp.sign_tool_call(cfg, agent_key(f["agent_key"]), other, ch)


@pytest.mark.parametrize("value", [
    {"limit": 1.5}, {"x": None}, {1: "int key"}, {"s": "\ud800"}, {"t": ("ok", 2.0)},
    {"a": {"b": {"c": {"d": {"e": 1}}}}},
])
def test_python_values_outside_the_model_are_refused(value):
    # A dict is serialized before parsing; json.dumps would otherwise turn
    # an int key into a string and sign arguments the client never sent.
    with pytest.raises(mcp.InvalidArgumentsError):
        mcp.canonical_arguments(value)


def test_python_dict_and_json_text_bind_identically():
    assert mcp.canonical_arguments({"b": 1, "a": ["x", True]}) == mcp.canonical_arguments('{"a":["x",true],"b":1}')


@needs_native
def test_a_hand_built_tool_call_cannot_bind_other_arguments():
    # ToolCall is a public dataclass; a digest that does not match its
    # arguments would make the proof bind one call while another is sent.
    f = load("tool-call.json")
    cfg = mcp.parse_client_config(f["client_config_json"])
    c = f["cases"][0]
    ch = cfg.check_challenge(c["tool"], c["challenge_response"], c["now"])
    one, two = mcp.new_tool_call(c["tool"], '{"limit":1}'), mcp.new_tool_call(c["tool"], '{"limit":2}')
    for forged in (mcp.ToolCall(c["tool"], one.canonical_arguments, two.payload_digest),
                   mcp.ToolCall(c["tool"], b'{ "limit":1}', one.payload_digest)):
        with pytest.raises(mcp.InvalidArgumentsError):
            cfg.challenge_request(forged)
        with pytest.raises(mcp.InvalidArgumentsError):
            mcp.sign_tool_call(cfg, agent_key(f["agent_key"]), forged, ch)
