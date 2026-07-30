"""Unit tests for the alpha.16 resource_path constraint, extension-constraint
params value model, input bounds, agent-name bound, and VerificationReceipt
codec. Mirrors the Go reference resource_path_test.go.
"""
from __future__ import annotations

import json

import pytest

from ratify_protocol import (
    MAX_AGENT_NAME_LENGTH_BYTES,
    MAX_CONSTRAINTS_PER_CERT,
    MAX_IDENTIFIER_LENGTH_BYTES,
    MAX_JSON_NESTING_DEPTH,
    MAX_PROOF_BUNDLE_BYTES,
    MAX_SCOPE_LENGTH_BYTES,
    MAX_SCOPES_PER_CERT,
    PROTOCOL_VERSION,
    SCOPE_FILES_WRITE,
    Constraint,
    DelegationCert,
    HybridPublicKey,
    HybridSignature,
    ProofBundle,
    VerificationReceipt,
    decode_delegation_cert,
    decode_proof_bundle,
    decode_verification_receipt,
    derive_id,
    encode_delegation_cert,
    encode_proof_bundle,
    encode_verification_receipt,
    generate_agent,
    generate_hybrid_keypair,
    is_canonical_constraint_type,
    issue_delegation,
    normalize_resource_path,
    resource_path_matches,
    sign_both,
    sign_challenge,
    validate_params_value,
    validate_resource_constraints,
    verification_receipt_sign_bytes,
)


# ---------------------------------------------------------------------------
# Path model (SPEC §5.7.3)
# ---------------------------------------------------------------------------

def test_normalize_resource_path_valid():
    valid = {
        "/": "/",
        "/docs": "/docs",
        "/docs/": "/docs",
        "/docs/setup/g.md": "/docs/setup/g.md",
        "/docs/%2e%2e/notes": "/docs/%2e%2e/notes",  # % is a literal byte
        "/a b/c": "/a b/c",
        "/UPPER/Case": "/UPPER/Case",  # byte-exact; no case folding
    }
    for inp, want in valid.items():
        assert normalize_resource_path(inp) == want


@pytest.mark.parametrize("bad", [
    "",             # empty
    "docs",         # no leading slash
    "docs/",        # no leading slash
    "/docs/../x",   # dot-segment
    "/./x",         # dot-segment
    "/..",          # dot-segment
    "/a//b",        # empty interior segment
    "/docs//",      # empty segment after one-trailing-slash trim
    "//",           # empty segment
    "/a\\b",        # backslash
    "\\docs",       # backslash, no leading slash
    "/a\x00b",      # NUL
    "/docs/./g.md",  # dot-segment mid-path
])
def test_normalize_resource_path_invalid(bad):
    with pytest.raises(ValueError):
        normalize_resource_path(bad)


@pytest.mark.parametrize("prefix,path,want", [
    ("/docs", "/docs", True),
    ("/docs", "/docs/a.md", True),
    ("/docs/", "/docs", True),    # trailing slash trims
    ("/docs", "/docs/", True),    # both directions
    ("/", "/anything", True),     # root matches everything
    ("/", "/", True),             # root matches root
    ("/docs", "/docs-old", False),   # segment boundary, not string prefix
    ("/docs", "/docsx/a", False),    # segment boundary
    ("/docs", "/doc", False),        # shorter
    ("/docs", "/", False),           # parent of prefix
    ("/src/security", "/src", False),  # narrower prefix does not match wider path
    ("/docs", "/docs/../x", False),    # invalid path never matches
    ("/docs/../x", "/docs", False),    # invalid prefix never matches
])
def test_resource_path_matches(prefix, path, want):
    assert resource_path_matches(prefix, path) is want


# ---------------------------------------------------------------------------
# Issuance rule: jointly-satisfiable resource constraints (SPEC §5.7.3)
# ---------------------------------------------------------------------------

def _rp(rid, prefix=""):
    return Constraint(type="resource_path", resource_id=rid, path_prefix=prefix)


def test_validate_resource_constraints_ok():
    ok = [
        [],
        [_rp("git:github.com/acme/widgets", "/docs")],
        [_rp("git:github.com/acme/widgets", "")],  # whole resource
        [_rp("git:github.com/acme/widgets", "/src"),
         _rp("git:github.com/acme/widgets", "/src/security")],  # nested
        [_rp("git:github.com/acme/widgets", ""),
         _rp("git:github.com/acme/widgets", "/docs")],  # absent orders as /
        [Constraint(type="geo_circle", lat=1, lon=1, radius_m=5)],  # non-resource untouched
    ]
    for cs in ok:
        validate_resource_constraints(cs)  # must not raise


@pytest.mark.parametrize("cs", [
    [_rp("", "/docs")],  # empty resource_id
    [_rp("x" * (MAX_IDENTIFIER_LENGTH_BYTES + 1), "")],  # oversized id
    [_rp("git:github.com/acme/widgets", "docs")],  # invalid prefix
    [_rp("git:github.com/acme/widgets", "/docs"),
     _rp("git:github.com/acme/other", "/docs")],  # different resources
    [_rp("git:github.com/acme/widgets", "/src"),
     _rp("git:github.com/acme/widgets", "/docs")],  # incomparable prefixes
])
def test_validate_resource_constraints_bad(cs):
    with pytest.raises(ValueError):
        validate_resource_constraints(cs)


# ---------------------------------------------------------------------------
# Extension-constraint params value model (SPEC §5.7.1)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("v", [
    None, True, "s", 5, 42.0,  # integral float == wire integer
    -9007199254740991.0,
    [1, "two", None],
    {"a": 1, "b": [True]},
])
def test_validate_params_value_ok(v):
    validate_params_value(v, 0)  # must not raise


@pytest.mark.parametrize("v", [
    1.5,                     # non-integer number
    9007199254740993.0,      # beyond safe range (float)
    9007199254740992,        # beyond safe range (int)
    1 << 60,                 # beyond safe range
    b"\x01",                 # raw bytes
    {"a": 1.25},             # nested float
    [[[1.5]]],               # nested float in arrays
])
def test_validate_params_value_bad(v):
    with pytest.raises(ValueError):
        validate_params_value(v, 0)


def test_validate_params_value_nesting_bound():
    deep = "leaf"
    for _ in range(MAX_JSON_NESTING_DEPTH + 1):
        deep = [deep]
    with pytest.raises(ValueError):
        validate_params_value(deep, 0)


def test_geo_types_are_canonical():
    for t in ("geo_circle", "geo_polygon", "geo_bbox", "time_window",
              "max_speed_mps", "max_amount", "max_rate", "resource_path"):
        assert is_canonical_constraint_type(t)
    assert not is_canonical_constraint_type("com.example.max-sessions")


# ---------------------------------------------------------------------------
# Issuance hygiene through issue_delegation
# ---------------------------------------------------------------------------

def _pair():
    pub, priv = generate_hybrid_keypair()
    return derive_id(pub), pub, priv


def _base_cert():
    rid_id, rid_pub, rid_priv = _pair()
    ag_id, ag_pub, _ = _pair()
    cert = DelegationCert(
        cert_id="t-issue-1", version=PROTOCOL_VERSION,
        issuer_id=rid_id, issuer_pub_key=rid_pub,
        subject_id=ag_id, subject_pub_key=ag_pub,
        scope=[SCOPE_FILES_WRITE], issued_at=1000, expires_at=4070908799,
    )
    return cert, rid_priv


def test_issue_rejects_unsatisfiable_pair():
    cert, priv = _base_cert()
    cert.constraints = [
        Constraint(type="resource_path", resource_id="r1", path_prefix="/docs"),
        Constraint(type="resource_path", resource_id="r2", path_prefix="/docs"),
    ]
    with pytest.raises(ValueError):
        issue_delegation(cert, priv)


def test_issue_rejects_params_on_canonical_type():
    cert, priv = _base_cert()
    cert.constraints = [
        Constraint(type="geo_circle", lat=1, lon=1, radius_m=5, params={"x": 1}),
    ]
    with pytest.raises(ValueError):
        issue_delegation(cert, priv)


def test_issue_rejects_float_params():
    cert, priv = _base_cert()
    cert.constraints = [Constraint(type="com.example.limit", params={"max": 1.5})]
    with pytest.raises(ValueError):
        issue_delegation(cert, priv)


# ---------------------------------------------------------------------------
# path_prefix PRESENCE rejection through the decoders (SECURITY CRITICAL)
# ---------------------------------------------------------------------------

def _valid_resource_cert():
    cert, priv = _base_cert()
    cert.cert_id = "t-presence-1"
    cert.constraints = [Constraint(
        type="resource_path",
        resource_id="git:github.com/acme/widgets",
        path_prefix="/docs",
    )]
    issue_delegation(cert, priv)
    return cert


_FORBIDDEN_PREFIX = {
    "empty string": '"path_prefix":""',
    "null": '"path_prefix":null',
    "non-string": '"path_prefix":42',
}


def test_path_prefix_presence_rejected_through_cert_decode():
    cert = _valid_resource_cert()
    cert_json = encode_delegation_cert(cert)
    # Valid form decodes.
    decode_delegation_cert(cert_json)
    for name, replacement in _FORBIDDEN_PREFIX.items():
        doc = cert_json.replace('"path_prefix":"/docs"', replacement, 1)
        assert doc != cert_json, f"{name}: mutation not applied"
        with pytest.raises(ValueError):
            decode_delegation_cert(doc)


def test_path_prefix_presence_rejected_through_bundle_decode():
    cert = _valid_resource_cert()
    # Build a full bundle around the cert.
    _, ag_pub, ag_priv = _pair()  # unrelated agent key just to sign the challenge
    challenge = bytes([7]) * 32
    sig = sign_challenge(challenge, 2000, ag_priv)
    bundle = ProofBundle(
        agent_id=cert.subject_id, agent_pub_key=cert.subject_pub_key,
        delegations=[cert], challenge=challenge, challenge_at=2000,
        challenge_sig=sig,
    )
    bundle_json = encode_proof_bundle(bundle)
    decode_proof_bundle(bundle_json)  # valid bundle decodes
    for name, replacement in _FORBIDDEN_PREFIX.items():
        doc = bundle_json.replace('"path_prefix":"/docs"', replacement, 1)
        assert doc != bundle_json, f"{name}: mutation not applied"
        with pytest.raises(ValueError):
            decode_proof_bundle(doc)


def test_absent_path_prefix_is_whole_resource():
    # A cert with resource_id and no path_prefix decodes and encodes with the
    # field simply absent — absence is the sole encoding of whole-resource.
    cert, priv = _base_cert()
    cert.constraints = [Constraint(type="resource_path", resource_id="r1")]
    issue_delegation(cert, priv)
    j = encode_delegation_cert(cert)
    assert "path_prefix" not in j
    got = decode_delegation_cert(j)
    assert got.constraints[0].path_prefix == ""


# ---------------------------------------------------------------------------
# Input bounds
# ---------------------------------------------------------------------------

def test_decode_proof_bundle_size_bound_both_sides():
    # MAX_PROOF_BUNDLE_BYTES, both sides. At exactly the limit the size gate
    # passes and parsing is reached, so the failure is a parse error that does
    # NOT name the size bound.
    at_limit = "x" * MAX_PROOF_BUNDLE_BYTES
    with pytest.raises(ValueError) as at_ei:
        decode_proof_bundle(at_limit)
    assert "MAX_PROOF_BUNDLE_BYTES" not in str(at_ei.value)
    # One past the limit is rejected before parsing; the error names the bound.
    oversized = "x" * (MAX_PROOF_BUNDLE_BYTES + 1)
    with pytest.raises(ValueError) as ei:
        decode_proof_bundle(oversized)
    assert "MAX_PROOF_BUNDLE_BYTES" in str(ei.value)


def test_decode_rejects_excessive_nesting():
    deep = "[" * (MAX_JSON_NESTING_DEPTH + 1) + "]" * (MAX_JSON_NESTING_DEPTH + 1)
    with pytest.raises(ValueError) as ei:
        decode_proof_bundle(deep)
    assert "MAX_JSON_NESTING_DEPTH" in str(ei.value)


# ---------------------------------------------------------------------------
# §5.1 input-bound boundaries: every bound at exactly the limit (accept) and
# one past it (reject), through the public decoders. Mirrors Go's
# TestInputBoundBoundaries. The at-limit ACCEPT cases matter as much as the
# rejects: an off-by-one that rejected a legal maximum would be a silent
# availability regression.
# ---------------------------------------------------------------------------

def _bound_base_cert():
    """A cert whose bytes decode cleanly (correct key/sig lengths, no bound
    exceeded). Individual boundary cases mutate one field at a time. Like Go's
    baseCert, it carries raw zero-valued keys — the decoder checks byte lengths
    and §5.1 bounds, not signature validity."""
    return DelegationCert(
        cert_id="bound", version=PROTOCOL_VERSION,
        issuer_id="aa",
        issuer_pub_key=HybridPublicKey(ed25519=bytes(32), ml_dsa_65=bytes(1952)),
        subject_id="bb",
        subject_pub_key=HybridPublicKey(ed25519=bytes(32), ml_dsa_65=bytes(1952)),
        scope=["meeting:attend"], constraints=[],
        issued_at=1000, expires_at=2000,
        signature=HybridSignature(ed25519=bytes(64), ml_dsa_65=bytes(3309)),
    )


def _decode_roundtrip(cert):
    # The encoder applies no §5.1 bound checks (mirrors Go): the bounds are
    # enforced only on decode, so encoding an over-limit cert must succeed and
    # decoding it must raise.
    decode_delegation_cert(encode_delegation_cert(cert))


def test_input_bound_boundaries():
    # MAX_SCOPES_PER_CERT
    def scopes(n):
        return [f"custom:com.example:s{i}" for i in range(n)]
    c = _bound_base_cert()
    c.scope = scopes(MAX_SCOPES_PER_CERT)
    _decode_roundtrip(c)  # at limit: must decode
    c.scope = scopes(MAX_SCOPES_PER_CERT + 1)
    with pytest.raises(ValueError):
        _decode_roundtrip(c)

    # MAX_CONSTRAINTS_PER_CERT (geo_circle: no cross-field satisfiability rule
    # at decode)
    def geos(n):
        return [Constraint(type="geo_circle", lat=1, lon=1, radius_m=5)
                for _ in range(n)]
    c = _bound_base_cert()
    c.constraints = geos(MAX_CONSTRAINTS_PER_CERT)
    _decode_roundtrip(c)  # at limit: must decode
    c.constraints = geos(MAX_CONSTRAINTS_PER_CERT + 1)
    with pytest.raises(ValueError):
        _decode_roundtrip(c)

    # MAX_SCOPE_LENGTH_BYTES (a custom: scope so it is vocabulary-valid)
    def scope_of_len(n):
        return "custom:x:" + "a" * (n - len("custom:x:"))
    c = _bound_base_cert()
    c.scope = [scope_of_len(MAX_SCOPE_LENGTH_BYTES)]
    _decode_roundtrip(c)  # at limit: must decode
    c.scope = [scope_of_len(MAX_SCOPE_LENGTH_BYTES + 1)]
    with pytest.raises(ValueError):
        _decode_roundtrip(c)

    # MAX_IDENTIFIER_LENGTH_BYTES (resource_path resource_id)
    def rp_id(n):
        return [Constraint(type="resource_path", resource_id="r" * n)]
    c = _bound_base_cert()
    c.constraints = rp_id(MAX_IDENTIFIER_LENGTH_BYTES)
    _decode_roundtrip(c)  # at limit: must decode
    c.constraints = rp_id(MAX_IDENTIFIER_LENGTH_BYTES + 1)
    with pytest.raises(ValueError):
        _decode_roundtrip(c)

    # MAX_JSON_NESTING_DEPTH (container nesting, checked in the shared parse
    # path). Python exports no CheckWireJSON, so the at-limit ACCEPT is
    # observed indirectly: a bare nested array at exactly the limit clears the
    # nesting gate in _parse and is then rejected for a NON-nesting reason
    # (not a JSON object), while one level deeper is rejected AT the gate.
    at_limit = "[" * MAX_JSON_NESTING_DEPTH + "]" * MAX_JSON_NESTING_DEPTH
    with pytest.raises(ValueError) as ei:
        decode_proof_bundle(at_limit)
    assert "MAX_JSON_NESTING_DEPTH" not in str(ei.value), (
        "nesting at the limit must clear the depth gate, not be rejected by it"
    )
    over_limit = ("[" * (MAX_JSON_NESTING_DEPTH + 1)
                  + "]" * (MAX_JSON_NESTING_DEPTH + 1))
    with pytest.raises(ValueError) as ei:
        decode_proof_bundle(over_limit)
    assert "MAX_JSON_NESTING_DEPTH" in str(ei.value)

    # MAX_AGENT_NAME_LENGTH_BYTES (construction bound)
    generate_agent("n" * MAX_AGENT_NAME_LENGTH_BYTES, "custom")  # at limit
    with pytest.raises(ValueError):
        generate_agent("n" * (MAX_AGENT_NAME_LENGTH_BYTES + 1), "custom")


# ---------------------------------------------------------------------------
# Agent-name bound (SPEC §5.1)
# ---------------------------------------------------------------------------

def test_generate_agent_name_boundary():
    # Exactly the limit is accepted.
    generate_agent("n" * MAX_AGENT_NAME_LENGTH_BYTES, "custom")
    # One byte over is rejected.
    with pytest.raises(ValueError):
        generate_agent("n" * (MAX_AGENT_NAME_LENGTH_BYTES + 1), "custom")


# ---------------------------------------------------------------------------
# VerificationReceipt codec (SPEC §17.5)
# ---------------------------------------------------------------------------

def _signed_receipt(decision="revoked"):
    pub, priv = generate_hybrid_keypair()
    r = VerificationReceipt(
        version=PROTOCOL_VERSION, verifier_id=derive_id(pub), verifier_pub=pub,
        bundle_hash=bytes([0xAB]) * 32, decision=decision,
        human_id="", agent_id="b4a4c71795d676b69f454881a8300000",
        granted_scope=[], error_reason="delegation certificate has been revoked",
        verified_at=1800000000, prev_hash=bytes(32),
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    r.signature = sign_both(verification_receipt_sign_bytes(r), priv)
    return r


def test_verification_receipt_round_trip():
    r = _signed_receipt()
    encoded = encode_verification_receipt(r)
    decoded = decode_verification_receipt(encoded)
    re_encoded = encode_verification_receipt(decoded)
    assert encoded == re_encoded, "receipt round-trip is not byte-identical"


def test_verification_receipt_encoder_rejects_invalid():
    with pytest.raises(ValueError):
        encode_verification_receipt(None)

    mutations = [
        ("short bundle_hash", lambda r: setattr(r, "bundle_hash", r.bundle_hash[:16])),
        ("short prev_hash", lambda r: setattr(r, "prev_hash", r.prev_hash[:31])),
        ("unknown decision", lambda r: setattr(r, "decision", "approved")),
        ("empty verifier_id", lambda r: setattr(r, "verifier_id", "")),
        ("wrong version", lambda r: setattr(r, "version", 2)),
        ("short ed25519 sig",
         lambda r: setattr(r.signature, "ed25519", r.signature.ed25519[:63])),
        ("short ml_dsa_65 sig",
         lambda r: setattr(r.signature, "ml_dsa_65", r.signature.ml_dsa_65[:100])),
        ("short verifier pub",
         lambda r: setattr(r.verifier_pub, "ml_dsa_65", r.verifier_pub.ml_dsa_65[:100])),
    ]
    for name, mutate in mutations:
        r = _signed_receipt(decision="authorized_agent")
        mutate(r)
        with pytest.raises(ValueError):
            encode_verification_receipt(r)


def test_verification_receipt_decoder_rejects_malformed_wire():
    r = _signed_receipt(decision="authorized_agent")
    encoded = encode_verification_receipt(r)

    def mutate(old, new):
        out = encoded.replace(old, new, 1)
        assert out != encoded, f"mutation {old!r} not applied"
        return out

    cases = {
        "unknown field": mutate('"version":', '"versionx":1,"version":'),
        "wrong version": mutate('"version":1', '"version":2'),
        "unknown decision": mutate('"decision":"authorized_agent"', '"decision":"approved"'),
        "empty verifier_id": mutate(f'"verifier_id":"{r.verifier_id}"', '"verifier_id":""'),
        "non-object": "[1,2,3]",
    }
    for name, doc in cases.items():
        with pytest.raises(ValueError):
            decode_verification_receipt(doc)
