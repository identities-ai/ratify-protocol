"""Conformance tests — validate the Python SDK against the Go-generated
canonical test vectors. If this suite passes, the Python implementation is
byte-identical to the Go reference across canonical serialization, hybrid
signing bytes, scope semantics, and verifier behavior.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ratify_protocol import (
    Constraint,
    DelegationCert,
    HybridPublicKey,
    HybridSignature,
    KeyRotationStatement,
    ProofBundle,
    ReceiptParty,
    ReceiptPartySignature,
    RevocationList,
    RevocationPush,
    SessionToken,
    StreamContext,
    TransactionReceipt,
    VerifierContext,
    VerifyOptions,
    WitnessEntry,
    base64_standard_decode,
    challenge_sign_bytes,
    delegation_sign_bytes,
    expand_scopes,
    hex_encode,
    key_rotation_sign_bytes,
    revocation_push_sign_bytes,
    revocation_sign_bytes,
    session_token_sign_bytes,
    transaction_receipt_sign_bytes,
    verify_bundle,
    verify_key_rotation_statement_e,
    verify_revocation_list,
    verify_revocation_push,
    verify_streamed_turn,
    verify_transaction_receipt,
    verify_witness_entry,
    witness_entry_sign_bytes,
)

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "testvectors" / "v1"


def _decode_hybrid_pub(raw: dict) -> HybridPublicKey:
    return HybridPublicKey(
        ed25519=base64_standard_decode(raw["ed25519"]),
        ml_dsa_65=base64_standard_decode(raw["ml_dsa_65"]),
    )


def _decode_hybrid_sig(raw: dict) -> HybridSignature:
    return HybridSignature(
        ed25519=base64_standard_decode(raw["ed25519"]),
        ml_dsa_65=base64_standard_decode(raw["ml_dsa_65"]),
    )


def _decode_constraint(raw: dict) -> Constraint:
    # Build a Constraint from a sparse tagged-JSON object. Unknown keys are
    # ignored by the dataclass constructor via kwargs filtering below.
    known = {
        "type", "lat", "lon", "radius_m", "points", "min_lat", "min_lon",
        "max_lat", "max_lon", "min_alt_m", "max_alt_m", "start", "end",
        "tz", "max_mps", "max_amount", "currency", "count", "window_s",
    }
    kwargs = {k: v for k, v in raw.items() if k in known}
    return Constraint(**kwargs)


def _decode_cert(raw: dict) -> DelegationCert:
    # Constraints round-trip from the fixture JSON; missing / null decodes
    # to an empty list so non-constraint fixtures keep working.
    constraints_raw = raw.get("constraints")
    constraints = [_decode_constraint(c) for c in constraints_raw] if constraints_raw else []
    return DelegationCert(
        cert_id=raw["cert_id"],
        version=raw["version"],
        issuer_id=raw["issuer_id"],
        issuer_pub_key=_decode_hybrid_pub(raw["issuer_pub_key"]),
        subject_id=raw["subject_id"],
        subject_pub_key=_decode_hybrid_pub(raw["subject_pub_key"]),
        scope=raw["scope"],
        constraints=constraints,
        issued_at=raw["issued_at"],
        expires_at=raw["expires_at"],
        signature=_decode_hybrid_sig(raw["signature"]),
    )


def _decode_bundle(raw: dict) -> ProofBundle:
    return ProofBundle(
        agent_id=raw["agent_id"],
        agent_pub_key=_decode_hybrid_pub(raw["agent_pub_key"]),
        delegations=[_decode_cert(c) for c in raw["delegations"]],
        challenge=base64_standard_decode(raw["challenge"]),
        challenge_at=raw["challenge_at"],
        challenge_sig=_decode_hybrid_sig(raw["challenge_sig"]),
        session_context=(
            base64_standard_decode(raw["session_context"])
            if raw.get("session_context")
            else b""
        ),
        stream_id=(
            base64_standard_decode(raw["stream_id"])
            if raw.get("stream_id")
            else b""
        ),
        stream_seq=raw.get("stream_seq") or 0,
    )


def _decode_revocation(raw: dict) -> RevocationList:
    return RevocationList(
        issuer_id=raw["issuer_id"],
        updated_at=raw["updated_at"],
        revoked_certs=raw["revoked_certs"],
        signature=_decode_hybrid_sig(raw["signature"]),
    )


def _decode_session_token(raw: dict) -> SessionToken:
    return SessionToken(
        version=raw["version"],
        session_id=raw["session_id"],
        agent_id=raw["agent_id"],
        agent_pub_key=_decode_hybrid_pub(raw["agent_pub_key"]),
        human_id=raw["human_id"],
        granted_scope=list(raw["granted_scope"]),
        issued_at=raw["issued_at"],
        valid_until=raw["valid_until"],
        chain_hash=base64_standard_decode(raw["chain_hash"]),
        mac=base64_standard_decode(raw["mac"]),
    )


def _decode_key_rotation(raw: dict) -> KeyRotationStatement:
    return KeyRotationStatement(
        version=raw["version"],
        old_id=raw["old_id"],
        old_pub_key=_decode_hybrid_pub(raw["old_pub_key"]),
        new_id=raw["new_id"],
        new_pub_key=_decode_hybrid_pub(raw["new_pub_key"]),
        rotated_at=raw["rotated_at"],
        reason=raw["reason"],
        signature_old=_decode_hybrid_sig(raw["signature_old"]),
        signature_new=_decode_hybrid_sig(raw["signature_new"]),
    )


# Load all fixtures at collection time
# Exclude cross_sdk_vectors.json — different schema, loaded by test_cross_sdk.py.
_FIXTURE_FILES = sorted(
    p for p in FIXTURE_DIR.glob("*.json") if p.name != "cross_sdk_vectors.json"
)
assert _FIXTURE_FILES, f"no fixtures found in {FIXTURE_DIR}"


@pytest.mark.parametrize("fixture_path", _FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture(fixture_path: Path):
    with fixture_path.open() as f:
        fx = json.load(f)
    assert fx["protocol_version"] == 1

    kind = fx["kind"]
    if kind == "verify":
        _run_verify_fixture(fx)
    elif kind == "scope":
        _run_scope_fixture(fx)
    elif kind == "revocation":
        _run_revocation_fixture(fx)
    elif kind == "key_rotation":
        _run_key_rotation_fixture(fx)
    elif kind == "session_token":
        _run_session_token_fixture(fx)
    elif kind == "transaction_receipt":
        _run_transaction_receipt_fixture(fx)
    elif kind == "revocation_push":
        _run_revocation_push_fixture(fx)
    elif kind == "witness_entry":
        _run_witness_entry_fixture(fx)
    else:
        pytest.fail(f"unknown fixture kind: {kind}")


def _run_verify_fixture(fx: dict) -> None:
    chain_raw = fx["cert_chain"]
    expected_sign_bytes = fx["expected"]["delegation_sign_bytes_hex"]
    assert len(chain_raw) == len(expected_sign_bytes)

    chain = [_decode_cert(c) for c in chain_raw]

    # Canonical signing bytes per cert — must match Go byte-for-byte.
    for i, cert in enumerate(chain):
        got_hex = hex_encode(delegation_sign_bytes(cert))
        assert got_hex == expected_sign_bytes[i], (
            f"cert {i} canonical sign bytes drift\n"
            f"got:  {got_hex[:100]}...\n"
            f"want: {expected_sign_bytes[i][:100]}..."
        )

    # Challenge signing bytes.
    if "bundle" in fx and "challenge_sign_bytes_hex" in fx["expected"]:
        bundle = _decode_bundle(fx["bundle"])
        got_hex = hex_encode(
            challenge_sign_bytes(
                bundle.challenge,
                bundle.challenge_at,
                bundle.session_context,
                bundle.stream_id,
                bundle.stream_seq,
            )
        )
        assert got_hex == fx["expected"]["challenge_sign_bytes_hex"]

    # Full verify behavior.
    if not (fx.get("bundle") and fx["expected"].get("verify_result") and fx["expected"].get("verify_options")):
        return

    bundle = _decode_bundle(fx["bundle"])
    opts_in = fx["expected"]["verify_options"]
    expected = fx["expected"]["verify_result"]

    # revocation_middle_cert fixture exercises revocation. Use the
    # SPEC §17.1 RevocationProvider — the legacy `is_revoked` closure is
    # deprecated and emits a DeprecationWarning on use (which would fail
    # under pytest -W error).
    revocation = None
    if expected.get("identity_status") == "revoked" and len(bundle.delegations) > 1:
        revoked_id = bundle.delegations[1].cert_id

        class _ConformanceRevocation:
            def is_revoked(self, cert_id):
                return cert_id == revoked_id, None

        revocation = _ConformanceRevocation()

    # Thread the fixture's verifier_context into the verify call so
    # constraint fixtures exercise the real constraint-evaluation path.
    ctx_raw = fx.get("verifier_context")
    context = None
    if ctx_raw is not None:
        inv_count = ctx_raw.get("invocations_in_window_count")
        context = VerifierContext(
            current_lat=ctx_raw.get("current_lat"),
            current_lon=ctx_raw.get("current_lon"),
            current_alt_m=ctx_raw.get("current_alt_m"),
            current_speed_mps=ctx_raw.get("current_speed_mps"),
            requested_amount=ctx_raw.get("requested_amount"),
            requested_currency=ctx_raw.get("requested_currency"),
            invocations_in_window=(
                (lambda c=inv_count: (lambda _cid, _w: c))()
                if inv_count is not None
                else None
            ),
        )

    stream_opt = None
    if opts_in.get("stream"):
        stream_opt = StreamContext(
            stream_id=base64_standard_decode(opts_in["stream"]["stream_id"]),
            last_seen_seq=opts_in["stream"].get("last_seen_seq", 0),
        )

    opts = VerifyOptions(
        required_scope=opts_in.get("required_scope", ""),
        now=opts_in["now"],
        session_context=(
            base64_standard_decode(opts_in["session_context"])
            if opts_in.get("session_context")
            else b""
        ),
        stream=stream_opt,
        revocation=revocation,
        context=context,
    )
    got = verify_bundle(bundle, opts)

    assert got.valid == expected["valid"], f"Valid mismatch: got {got.valid}, want {expected['valid']}"
    assert got.identity_status == expected["identity_status"], (
        f"IdentityStatus: got {got.identity_status!r}, want {expected['identity_status']!r}"
    )
    assert got.human_id == expected.get("human_id", ""), f"HumanID mismatch: {got.human_id} vs {expected.get('human_id', '')}"
    assert got.agent_id == expected.get("agent_id", ""), f"AgentID mismatch"
    assert got.error_reason == expected.get("error_reason", ""), (
        f"ErrorReason: got {got.error_reason!r}, want {expected.get('error_reason', '')!r}"
    )
    assert sorted(got.granted_scope or []) == sorted(expected.get("granted_scope", [])), "GrantedScope"


def _run_scope_fixture(fx: dict) -> None:
    got = expand_scopes(fx["scope_input"])
    want = sorted(fx["expected"]["expanded_scopes"])
    assert got == want, f"expand_scopes: got {got}, want {want}"


def _run_revocation_fixture(fx: dict) -> None:
    lst = _decode_revocation(fx["revocation_list"])
    got_hex = hex_encode(revocation_sign_bytes(lst))
    assert got_hex == fx["expected"]["revocation_sign_bytes_hex"]

    entity = fx["entities"][0]
    issuer_pub = _decode_hybrid_pub(entity["public_key"])
    assert verify_revocation_list(lst, issuer_pub), "revocation signature failed to verify"


def _run_session_token_fixture(fx: dict) -> None:
    st = fx["session_token"]
    token = _decode_session_token(st["token"])

    got_sign_hex = hex_encode(session_token_sign_bytes(token))
    assert got_sign_hex == fx["expected"]["session_token_sign_bytes_hex"], (
        "session_token sign bytes drift"
    )
    assert hex_encode(token.mac) == fx["expected"]["session_token_mac_hex"], (
        "session_token MAC drift"
    )

    secret = bytes.fromhex(st["session_secret_hex"])
    challenge = base64_standard_decode(st["challenge"])
    challenge_sig = _decode_hybrid_sig(st["challenge_sig"])
    result = verify_streamed_turn(
        token=token,
        session_secret=secret,
        challenge=challenge,
        challenge_at=st["challenge_at"],
        challenge_sig=challenge_sig,
        now=st["verify_now"],
    )
    want = fx["expected"]["streamed_turn"]
    assert result.valid == want["valid"], (
        f"streamed_turn.valid got={result.valid} want={want['valid']} "
        f"reason={result.error_reason!r}"
    )
    assert result.identity_status == want["identity_status"]
    assert result.human_id == want.get("human_id", "")
    assert result.agent_id == want.get("agent_id", "")
    assert result.error_reason == want.get("error_reason", "")
    assert sorted(result.granted_scope or []) == sorted(want.get("granted_scope", []))


def _run_key_rotation_fixture(fx: dict) -> None:
    stmt = _decode_key_rotation(fx["key_rotation"])
    got_hex = hex_encode(key_rotation_sign_bytes(stmt))
    assert got_hex == fx["expected"]["key_rotation_sign_bytes_hex"]

    err = verify_key_rotation_statement_e(stmt)
    assert (err is None) == fx["expected"]["key_rotation_verify_ok"]
    assert (err or "") == fx["expected"].get("key_rotation_error_reason", "")


def _decode_receipt_party(raw: dict) -> ReceiptParty:
    return ReceiptParty(
        party_id=raw["party_id"],
        role=raw["role"],
        agent_id=raw["agent_id"],
        agent_pub_key=_decode_hybrid_pub(raw["agent_pub_key"]),
        proof_bundle=_decode_bundle(raw["proof_bundle"]),
    )


def _decode_receipt_party_signature(raw: dict) -> ReceiptPartySignature:
    return ReceiptPartySignature(
        party_id=raw["party_id"],
        signature=_decode_hybrid_sig(raw["signature"]),
    )


def _run_transaction_receipt_fixture(fx: dict) -> None:
    tr = fx["transaction_receipt"]
    receipt = TransactionReceipt(
        version=tr["version"],
        transaction_id=tr["transaction_id"],
        created_at=tr["created_at"],
        terms_schema_uri=tr["terms_schema_uri"],
        terms_canonical_json=base64_standard_decode(tr["terms_canonical_json"]),
        parties=[_decode_receipt_party(p) for p in tr["parties"]],
        party_signatures=[
            _decode_receipt_party_signature(s)
            for s in tr.get("party_signatures", [])
        ],
    )

    expected = fx["expected"]

    # Cross-check canonical sign bytes
    got_hex = hex_encode(transaction_receipt_sign_bytes(receipt))
    assert got_hex == expected["receipt_sign_bytes_hex"], (
        "transaction_receipt sign bytes drift"
    )

    # Verify the receipt
    now = fx.get("timestamps", {}).get("verifier_now")
    result = verify_transaction_receipt(receipt, now=now)
    assert result.valid == expected["receipt_valid"], (
        f"receipt_valid got={result.valid} want={expected['receipt_valid']} "
        f"reason={result.error_reason!r}"
    )
    assert result.error_reason == expected.get("receipt_error_reason", ""), (
        f"receipt_error_reason got={result.error_reason!r} "
        f"want={expected.get('receipt_error_reason', '')!r}"
    )


def _run_revocation_push_fixture(fx: dict) -> None:
    rp = fx["revocation_push"]
    push = RevocationPush(
        issuer_id=rp["issuer_id"],
        seq_no=rp["seq_no"],
        entries=rp["entries"],
        pushed_at=rp["pushed_at"],
        signature=_decode_hybrid_sig(rp["signature"]),
    )

    got_hex = hex_encode(revocation_push_sign_bytes(push))
    assert got_hex == fx["expected"]["revocation_push_sign_bytes_hex"], (
        "revocation_push sign bytes drift"
    )

    entity = fx["entities"][0]
    issuer_pub = _decode_hybrid_pub(entity["public_key"])
    assert verify_revocation_push(push, issuer_pub), "revocation_push signature failed to verify"


def _run_witness_entry_fixture(fx: dict) -> None:
    we = fx["witness_entry"]
    entry = WitnessEntry(
        prev_hash=base64_standard_decode(we["prev_hash"]),
        entry_data=base64_standard_decode(we["entry_data"]),
        timestamp=we["timestamp"],
        witness_id=we["witness_id"],
        signature=_decode_hybrid_sig(we["signature"]),
    )

    got_hex = hex_encode(witness_entry_sign_bytes(entry))
    assert got_hex == fx["expected"]["witness_entry_sign_bytes_hex"], (
        "witness_entry sign bytes drift"
    )

    entity = fx["entities"][0]
    witness_pub = _decode_hybrid_pub(entity["public_key"])
    assert verify_witness_entry(entry, witness_pub), "witness_entry signature failed to verify"
