"""Property tests for every strict v2 decoder (SPEC-v2 §2.1, §2.6).

For arbitrary bytes, arbitrary JSON, and single-byte mutations of valid
corpus objects, a decoder either returns an object that re-encodes to a
stable canonical form or raises a classified ``V2Error``; it never raises any
other exception, never accepts input past its byte limit, and never reads a
non-integer number."""
from __future__ import annotations

import base64
import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from corpus import b64, load
from ratify_protocol_v2 import _v2json, limits_v2
from ratify_protocol_v2 import checkpoint_ack_v2 as ck
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import status_batch_v2 as sb
from ratify_protocol_v2 import transaction_receipt_v2 as txv2
from ratify_protocol_v2 import verification_receipt_v2 as vrv2
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2.errors_v2 import ALL_ERROR_CLASSES, V2Error

OBJECTS = load("objects.json")["objects"]

# name -> (decoder, encoder, byte limit, seed wires)
DECODERS = {
    "delegation_certificate": (pv2.decode_delegation_cert_v2, pv2.encode_delegation_cert_v2,
                               limits_v2.MAX_DELEGATION_CERT_BYTES_V2),
    "proof_bundle": (pv2.decode_proof_bundle_v2, pv2.encode_proof_bundle_v2, limits_v2.MAX_PROOF_BUNDLE_BYTES_V2),
    "revocation_list": (pv2.decode_revocation_list_v2, pv2.encode_revocation_list_v2,
                        limits_v2.MAX_REVOCATION_LIST_BYTES_V2),
    "revocation_push": (pv2.decode_revocation_push_v2, pv2.encode_revocation_push_v2,
                        limits_v2.MAX_REVOCATION_PUSH_BYTES_V2),
    "key_rotation_statement": (kr.decode_key_rotation_statement_v2, kr.encode_key_rotation_statement_v2,
                               limits_v2.MAX_KEY_ROTATION_STATEMENT_BYTES_V2),
    "witness_entry": (wv2.decode_witness_entry_v2, wv2.encode_witness_entry_v2, limits_v2.MAX_WITNESS_ENTRY_BYTES_V2),
    "verification_receipt": (vrv2.decode_verification_receipt_v2, vrv2.encode_verification_receipt_v2,
                             limits_v2.MAX_VERIFICATION_RECEIPT_BYTES_V2),
    "verification_receipt_body": (vrv2.decode_verification_receipt_body_v2, vrv2.verification_receipt_v2_body,
                                  limits_v2.MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2),
    "transaction_receipt": (txv2.decode_transaction_receipt_v2, txv2.encode_transaction_receipt_v2,
                            limits_v2.MAX_TRANSACTION_RECEIPT_BYTES_V2),
    "checkpoint_acknowledgement": (ck.decode_v2_checkpoint_acknowledgement, ck.encode_v2_checkpoint_acknowledgement,
                                   limits_v2.MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2),
    "status_evidence_batch": (sb.decode_v2_status_evidence_batch, sb.encode_v2_status_evidence_batch,
                              limits_v2.MAX_STATUS_EVIDENCE_BATCH_BYTES_V2),
}


def _seeds() -> dict:
    seeds = {k: [] for k in DECODERS}
    for o in OBJECTS:
        seeds[o["kind"]].append(b64(o["wire_b64"]))
        if o["kind"] == "verification_receipt":
            seeds["verification_receipt_body"].append(b64(o["digests"]["receipt_outbox_body_b64"]))
        if o["kind"] in ("revocation_list", "revocation_push"):
            code = 3 if o["kind"] == "revocation_list" else 5
            seeds["status_evidence_batch"].append(
                b'[{"object":' + b64(o["wire_b64"]) + b',"object_type_code":' + str(code).encode() + b"}]")
    seeds["checkpoint_acknowledgement"].append(_v2json.canonical({
        "entry_hash": base64.b64encode(bytes(range(48))).decode(), "log_id": "c" * 32, "sequence": 3,
        "timestamp": 1800000000}))
    seeds["status_evidence_batch"].append(b"[]")
    return seeds


SEEDS = _seeds()
NAMES = sorted(DECODERS)


def _attempt(name: str, data: bytes):
    decode, encode, _ = DECODERS[name]
    try:
        value = decode(data)
    except V2Error as exc:
        assert exc.error_class in ALL_ERROR_CLASSES, (name, exc.error_class, exc)
        return None
    if name == "status_evidence_batch":
        # The batch decoder does not authenticate or decode its objects (Go
        # DecodeV2StatusEvidenceBatch); it keeps each object's exact bytes.
        for obj in value.objects:
            assert obj.object_type in (3, 5) and obj.wire[:1] == b"{" and obj.wire in data
        try:
            canonical = encode(value)
        except V2Error as exc:
            assert exc.error_class == "malformed"
            return value
        assert encode(decode(canonical)) == canonical
        return value
    # An accepted input has a canonical encoding that decodes to the same encoding.
    canonical = encode(value)
    assert encode(decode(canonical)) == canonical, name
    return value


JSON_SCALARS = st.one_of(st.none(), st.booleans(), st.integers(min_value=-(2**60), max_value=2**60),
                         st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=20))
JSON_VALUES = st.recursive(JSON_SCALARS, lambda children: st.one_of(
    st.lists(children, max_size=4), st.dictionaries(st.text(max_size=12), children, max_size=5)), max_leaves=25)

PROFILE = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@PROFILE
@given(name=st.sampled_from(NAMES), data=st.binary(max_size=512))
def test_arbitrary_bytes_are_classified(name, data):
    _attempt(name, data)


@PROFILE
@given(name=st.sampled_from(NAMES), value=JSON_VALUES)
def test_arbitrary_json_is_classified(name, value):
    _attempt(name, json.dumps(value).encode("utf-8"))


@PROFILE
@given(name=st.sampled_from(NAMES), data=st.data())
def test_mutated_corpus_objects_are_classified(name, data):
    seed = data.draw(st.sampled_from(SEEDS[name]))
    position = data.draw(st.integers(min_value=0, max_value=len(seed) - 1))
    action = data.draw(st.sampled_from(["flip", "delete", "insert", "replace_digit"]))
    if action == "flip":
        mutated = seed[:position] + bytes([seed[position] ^ data.draw(st.integers(1, 255))]) + seed[position + 1:]
    elif action == "delete":
        mutated = seed[:position] + seed[position + 1:]
    elif action == "insert":
        mutated = seed[:position] + data.draw(st.binary(min_size=1, max_size=4)) + seed[position:]
    else:
        mutated = seed[:position] + data.draw(st.sampled_from([b"-0", b"1.0", b"1e3", b"9007199254740992", b"\\ud800"])) + seed[position:]
    _attempt(name, mutated)


@PROFILE
@given(name=st.sampled_from(NAMES), data=st.data())
def test_replaced_members_are_classified(name, data):
    """Any member of a valid object replaced by any JSON value, or removed,
    is decoded or rejected with a class (wrong types never escape)."""
    seed = json.loads(data.draw(st.sampled_from(SEEDS[name])))
    target = seed[0] if isinstance(seed, list) and seed else seed
    if isinstance(target, dict) and target:
        key = data.draw(st.sampled_from(sorted(target)))
        if data.draw(st.booleans()):
            target[key] = data.draw(JSON_VALUES)
        else:
            del target[key]
    _attempt(name, json.dumps(seed, separators=(",", ":")).encode("utf-8"))


@PROFILE
@given(name=st.sampled_from(NAMES), extra=st.integers(min_value=1, max_value=64))
def test_byte_limit_is_checked_before_parsing(name, extra):
    decode, _, limit = DECODERS[name]
    oversized = SEEDS[name][0][:-1] + b" " * (limit + extra - len(SEEDS[name][0])) + SEEDS[name][0][-1:]
    assert len(oversized) == limit + extra
    try:
        decode(oversized)
    except V2Error as exc:
        assert exc.error_class == "malformed" and "rejected before parsing" in str(exc)
    else:
        raise AssertionError(f"{name}: over-limit input accepted")


@PROFILE
@given(digits=st.integers(min_value=17, max_value=200_000))
def test_huge_integer_tokens_are_rejected_cheaply(digits):
    data = b'{"a":' + b"9" * digits + b"}"
    try:
        _v2json.check_wire_json(data)
    except ValueError:
        return
    raise AssertionError("an out-of-range integer token was accepted")


@PROFILE
@given(depth=st.integers(min_value=17, max_value=50_000))
def test_deep_nesting_is_rejected_without_recursion_errors(depth):
    data = b"[" * depth + b"]" * depth
    try:
        _v2json.check_wire_json(data)
    except ValueError:
        return
    raise AssertionError("over-deep nesting was accepted")


def test_every_decoder_has_a_seed_that_decodes():
    for name in NAMES:
        assert SEEDS[name], name
        for seed in SEEDS[name]:
            assert _attempt(name, seed) is not None, name
