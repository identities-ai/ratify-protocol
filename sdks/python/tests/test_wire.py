"""Wire codec tests.

Round-trip guarantees against the Go-generated fixtures in testvectors/v1:
every bundle, delegation cert, and session token in the corpus must decode,
re-encode byte-identical to the canonical JSON of the original document,
and survive decode(encode(x)) with equality.

Strictness: the decoder fails closed on unknown fields, malformed base64,
wrong cryptographic byte lengths, type mismatches, and unpaired v1.1 stream
fields — with errors that name the offending field.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

from ratify_protocol import (
    canonical_json,
    decode_delegation_cert,
    decode_proof_bundle,
    decode_session_token,
    encode_delegation_cert,
    encode_proof_bundle,
    encode_session_token,
)

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "testvectors" / "v1"


def _canonical_text(value) -> str:
    return canonical_json(value).decode("utf-8")


# ----- Collect every bundle / cert / token in the fixture corpus -----

_BUNDLES: list[tuple[str, dict]] = []
_CERTS: list[tuple[str, dict]] = []
_TOKENS: list[tuple[str, dict]] = []

for _path in sorted(FIXTURE_DIR.glob("*.json")):
    with _path.open() as _f:
        _fx = json.load(_f)
    if _path.name == "cross_sdk_vectors.json":
        for _v in _fx["vectors"]:
            if _v["kind"] == "bundle_hash":
                _BUNDLES.append((f"{_path.name}:{_v['name']}", _v["input"]["bundle"]))
        continue
    if _fx.get("bundle"):
        _BUNDLES.append((_path.name, _fx["bundle"]))
    for _i, _c in enumerate(_fx.get("cert_chain") or []):
        _CERTS.append((f"{_path.name}:cert[{_i}]", _c))
    if _fx.get("session_token"):
        _TOKENS.append((_path.name, _fx["session_token"]["token"]))
    if _fx.get("transaction_receipt"):
        for _i, _p in enumerate(_fx["transaction_receipt"]["parties"]):
            _BUNDLES.append((f"{_path.name}:party[{_i}]", _p["proof_bundle"]))


def test_fixture_corpus_is_non_trivial():
    assert len(_BUNDLES) > 40
    assert len(_CERTS) > 40
    assert len(_TOKENS) >= 5


@pytest.mark.parametrize("name,raw", _BUNDLES, ids=[n for n, _ in _BUNDLES])
def test_bundle_round_trip(name: str, raw: dict):
    canon = _canonical_text(raw)
    bundle = decode_proof_bundle(json.dumps(raw))
    assert encode_proof_bundle(bundle) == canon
    assert decode_proof_bundle(encode_proof_bundle(bundle)) == bundle


@pytest.mark.parametrize("name,raw", _CERTS, ids=[n for n, _ in _CERTS])
def test_cert_round_trip(name: str, raw: dict):
    canon = _canonical_text(raw)
    cert = decode_delegation_cert(json.dumps(raw))
    assert encode_delegation_cert(cert) == canon
    assert decode_delegation_cert(encode_delegation_cert(cert)) == cert


@pytest.mark.parametrize("name,raw", _TOKENS, ids=[n for n, _ in _TOKENS])
def test_token_round_trip(name: str, raw: dict):
    canon = _canonical_text(raw)
    token = decode_session_token(json.dumps(raw))
    assert encode_session_token(token) == canon
    assert decode_session_token(encode_session_token(token)) == token


# ----- Negative wire-acceptance corpus (testvectors/wire-negative) -----
# Shared, byte-identical malformed documents consumed by all five SDKs.
# The Python codec is fully strict, so every corpus case is a decode error.

_NEGATIVE_CASES = json.loads(
    (FIXTURE_DIR.parent / "wire-negative" / "cases.json").read_text()
)["cases"]
assert len(_NEGATIVE_CASES) >= 10, "negative corpus too small"


@pytest.mark.parametrize(
    "case", _NEGATIVE_CASES, ids=[c["name"] for c in _NEGATIVE_CASES]
)
def test_negative_wire_corpus(case: dict):
    doc = base64.b64decode(case["doc_b64"])
    decoder = decode_proof_bundle if case["target"] == "bundle" else decode_session_token
    with pytest.raises(ValueError, match="wire: "):
        decoder(doc)


# ----- Strictness: fail closed with field-specific errors -----

def _load_bundle(file: str) -> dict:
    with (FIXTURE_DIR / file).open() as f:
        return json.load(f)["bundle"]


def _load_token() -> dict:
    with (FIXTURE_DIR / "session_token_valid.json").open() as f:
        return json.load(f)["session_token"]["token"]


def test_decode_accepts_bytes_input():
    raw = _load_bundle("happy_path_depth_1.json")
    assert decode_proof_bundle(json.dumps(raw).encode()) == decode_proof_bundle(json.dumps(raw))


def test_rejects_unknown_field_on_bundle():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["extra_field"] = 1
    with pytest.raises(ValueError, match='unknown field "extra_field"'):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_unknown_field_on_cert():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["delegations"][0]["note"] = "x"
    with pytest.raises(ValueError, match=r'delegations\[0\]: unknown field "note"'):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_unknown_field_on_pub_key():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["agent_pub_key"]["sphincs"] = "AA=="
    with pytest.raises(ValueError, match='agent_pub_key: unknown field "sphincs"'):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_unknown_field_on_constraint():
    with (FIXTURE_DIR / "constraint_geo_circle_inside.json").open() as f:
        raw = json.load(f)["bundle"]
    raw["delegations"][0]["constraints"][0]["altitude"] = 10
    with pytest.raises(ValueError, match=r'constraints\[0\]: unknown field "altitude"'):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_unknown_field_on_token():
    raw = _load_token()
    raw["nonce"] = "AA=="
    with pytest.raises(ValueError, match='unknown field "nonce"'):
        decode_session_token(json.dumps(raw))


def test_rejects_malformed_base64():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["challenge"] = "!not-base64!"
    with pytest.raises(ValueError, match=r"ProofBundle\.challenge: malformed base64"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_non_canonical_base64():
    raw = _load_token()
    # 32 bytes with nonzero trailing bits in the final sextet: decodes to the
    # same bytes as the all-"A" form, so re-encoding does not reproduce it.
    raw["mac"] = "A" * 42 + "B="
    with pytest.raises(ValueError, match=r"SessionToken\.mac: non-canonical base64"):
        decode_session_token(json.dumps(raw))


def test_rejects_wrong_ed25519_key_length():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["agent_pub_key"]["ed25519"] = "AAAA"  # 3 bytes
    with pytest.raises(ValueError, match=r"agent_pub_key\.ed25519: expected 32 bytes, got 3"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_wrong_mldsa_signature_length():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["challenge_sig"]["ml_dsa_65"] = "AAAA"
    with pytest.raises(ValueError, match=r"challenge_sig\.ml_dsa_65: expected 3309 bytes, got 3"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_missing_required_field():
    raw = _load_bundle("happy_path_depth_1.json")
    del raw["challenge_at"]
    with pytest.raises(ValueError, match=r"ProofBundle\.challenge_at: expected integer"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_missing_constraints_array():
    raw = _load_bundle("happy_path_depth_1.json")
    del raw["delegations"][0]["constraints"]
    with pytest.raises(ValueError, match=r"delegations\[0\]\.constraints: expected array"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_wrong_type_for_timestamps():
    raw = _load_token()
    raw["issued_at"] = "12345"
    with pytest.raises(ValueError, match=r"SessionToken\.issued_at: expected integer"):
        decode_session_token(json.dumps(raw))


def test_rejects_non_integer_lexical_forms_on_integer_fields():
    # json.loads parses these forms as float, so integer accessors reject
    # them — the same outcome the TS pre-scan enforces lexically.
    for lexeme in ("1000.0", "1e3", "20000e-1"):
        doc = re.sub(r'"issued_at": \d+', f'"issued_at": {lexeme}', json.dumps(_load_token()))
        with pytest.raises(ValueError, match="issued_at: expected integer"):
            decode_session_token(doc)


def test_float_constraint_fields_still_accept_fraction_and_exponent_forms():
    with (FIXTURE_DIR / "constraint_geo_circle_inside.json").open() as f:
        raw = json.load(f)["bundle"]
    doc = re.sub(r'"radius_m": [0-9.]+', '"radius_m": 5e2', json.dumps(raw))
    bundle = decode_proof_bundle(doc)  # must not raise
    assert bundle.delegations[0].constraints[0].radius_m == 500


def test_rejects_stream_id_without_stream_seq():
    raw = _load_bundle("stream_bound_first_turn.json")
    del raw["stream_seq"]
    with pytest.raises(ValueError, match="stream_id and stream_seq must be present together"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_stream_seq_below_one():
    raw = _load_bundle("stream_bound_first_turn.json")
    raw["stream_seq"] = 0
    with pytest.raises(ValueError, match="stream_seq: must be >= 1"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_wrong_session_context_length():
    raw = _load_bundle("session_bound_challenge.json")
    raw["session_context"] = "AAAA"  # 3 bytes, must be 32
    with pytest.raises(ValueError, match="session_context: expected 32 bytes, got 3"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_empty_delegations_array():
    raw = _load_bundle("happy_path_depth_1.json")
    raw["delegations"] = []
    with pytest.raises(ValueError, match=r"ProofBundle\.delegations: must contain at least one certificate"):
        decode_proof_bundle(json.dumps(raw))


def test_rejects_duplicate_json_keys():
    raw = _load_bundle("happy_path_depth_1.json")
    text = json.dumps(raw)
    # Splice a second agent_id member into the top-level object.
    dup = text.replace('"agent_id":', '"agent_id": "shadowed", "agent_id":', 1)
    assert dup != text
    with pytest.raises(ValueError, match='duplicate key "agent_id"'):
        decode_proof_bundle(dup)


# Duplicate-key cases. Inputs are IDENTICAL to the TypeScript suite
# (test/wire.test.ts) so both codecs demonstrably reject the same
# documents. Rejection happens at parse time, before schema validation,
# so minimal documents suffice.
_DUPLICATE_KEY_CASES = [
    ("top-level field", '{"agent_id":"x","agent_id":"y"}', "agent_id"),
    (
        "nested pubkey field",
        '{"agent_pub_key":{"ed25519":"AA==","ed25519":"BB=="}}',
        "ed25519",
    ),
    (
        "constraint field",
        '{"delegations":[{"constraints":[{"type":"geo_circle","type":"geo_circle"}]}]}',
        "type",
    ),
    (
        "signature field",
        '{"challenge_sig":{"ml_dsa_65":"AA==","ml_dsa_65":"AA=="}}',
        "ml_dsa_65",
    ),
    # "agent_id" spells "agent_id" with a Unicode escape — same key.
    ("unicode-escaped key", '{"agent_id":"x","agent\\u005fid":"y"}', "agent_id"),
]


@pytest.mark.parametrize(
    "name,doc,key", _DUPLICATE_KEY_CASES, ids=[c[0] for c in _DUPLICATE_KEY_CASES]
)
def test_rejects_duplicate_key(name: str, doc: str, key: str):
    with pytest.raises(ValueError, match=f'duplicate key "{key}" in JSON object'):
        decode_proof_bundle(doc)


def test_same_key_in_sibling_objects_is_not_a_duplicate():
    # The fixture carries "ed25519" and "ml_dsa_65" in many sibling objects
    # (agent, issuer, and subject keys; signatures) — that must decode fine.
    raw = _load_bundle("happy_path_depth_1.json")
    decode_proof_bundle(json.dumps(raw))


def test_rejects_non_object_input():
    with pytest.raises(ValueError, match="expected JSON object"):
        decode_proof_bundle("[1,2,3]")
    with pytest.raises(ValueError, match="invalid JSON"):
        decode_proof_bundle("not json")


# Byte-decoding strictness. Inputs are byte-identical to the TypeScript suite.

def test_rejects_malformed_utf8_bytes():
    # 0xff is never valid in UTF-8.
    data = b'{"agent_id":"' + bytes([0xFF]) + b'"}'
    with pytest.raises(ValueError, match="wire: invalid UTF-8"):
        decode_proof_bundle(data)


def test_rejects_bom_prefixed_json_bytes():
    # UTF-8 BOM (EF BB BF) is not stripped; U+FEFF is invalid JSON.
    data = b"\xef\xbb\xbf" + b'{"agent_id":"x"}'
    with pytest.raises(ValueError, match="wire: invalid JSON"):
        decode_proof_bundle(data)


def test_rejects_string_input_with_leading_bom():
    with pytest.raises(ValueError, match="wire: invalid JSON"):
        decode_proof_bundle('\ufeff{"agent_id":"x"}')


# Integer-domain boundaries (SPEC §6.2): JSON integer wire fields must
# lie within the IEEE-754 safe-integer range. Same field (issued_at on a
# SessionToken) as the TypeScript suite.

def test_accepts_issued_at_at_safe_integer_bounds():
    for bound in (2**53 - 1, -(2**53 - 1)):
        raw = _load_token()
        raw["issued_at"] = bound
        token = decode_session_token(json.dumps(raw))
        assert token.issued_at == bound


def test_rejects_issued_at_beyond_safe_integer_bounds():
    for outside in (2**53, -(2**53)):
        raw = _load_token()
        raw["issued_at"] = outside
        with pytest.raises(
            ValueError, match="issued_at: integer outside the safe-integer range"
        ):
            decode_session_token(json.dumps(raw))


# Encoder-side integer domain (mirrors the TypeScript suite): encoders must
# never emit an integer their own decoder rejects. Same two fields as
# TypeScript: a top-level timestamp and a nested constraint integer.

_SAFE_BOUNDS = (2**53 - 1, -(2**53 - 1))
_OUTSIDE_BOUNDS = (2**53, -(2**53))


def test_encoder_accepts_issued_at_at_safe_integer_bounds():
    for bound in _SAFE_BOUNDS:
        token = decode_session_token(json.dumps(_load_token()))
        token.issued_at = bound
        assert f'"issued_at":{bound}' in encode_session_token(token)


def test_encoder_rejects_issued_at_beyond_safe_integer_bounds():
    for outside in _OUTSIDE_BOUNDS:
        token = decode_session_token(json.dumps(_load_token()))
        token.issued_at = outside
        with pytest.raises(
            ValueError, match="issued_at: integer outside the safe-integer range"
        ):
            encode_session_token(token)


def test_encoder_accepts_constraint_window_s_at_safe_integer_bounds():
    for bound in _SAFE_BOUNDS:
        raw = _load_bundle("constraint_max_rate_denied.json")
        bundle = decode_proof_bundle(json.dumps(raw))
        bundle.delegations[0].constraints[0].window_s = bound
        assert f'"window_s":{bound}' in encode_proof_bundle(bundle)


def test_encoder_rejects_constraint_window_s_beyond_safe_integer_bounds():
    for outside in _OUTSIDE_BOUNDS:
        raw = _load_bundle("constraint_max_rate_denied.json")
        bundle = decode_proof_bundle(json.dumps(raw))
        bundle.delegations[0].constraints[0].window_s = outside
        with pytest.raises(
            ValueError,
            match=r"constraints\[0\]\.window_s: integer outside the safe-integer range",
        ):
            encode_proof_bundle(bundle)


def test_empty_constraints_stay_an_empty_array():
    raw = _load_bundle("happy_path_depth_1.json")
    encoded = encode_proof_bundle(decode_proof_bundle(json.dumps(raw)))
    assert '"constraints":[]' in encoded
