"""Hedged ML-DSA-65 signatures from "hedged-signatures.json".

Each object carries the same signed bodies as objects.json with ML-DSA-65
components produced by randomized signing. Every variant must verify, derive
identical projections and statement body digests, and a re-signed identical
log entry must be a replay, never a fork (SPEC-v2 §3.2 item 5)."""
from __future__ import annotations

import pytest

from corpus import b64, load
from ratify_protocol.v2 import key_rotation_v2 as kr
from ratify_protocol.v2 import verification_receipt_v2 as vrv2
from ratify_protocol.v2 import witness_v2 as wv2
from test_v2_conformance import CODECS, PUB, _head, _rotation_state, projection, verify_object

HEDGED = load("hedged-signatures.json")


def check_idempotency(kind: str, v: dict, deterministic: bytes, hedged: bytes) -> None:
    if kind == "witness_entry":
        first, again = wv2.decode_witness_entry_v2(deterministic), wv2.decode_witness_entry_v2(hedged)
        digest = wv2.witness_entry_v2_digest(first)
        assert wv2.witness_entry_v2_digest(again) == digest
        head = wv2.WitnessV2Head(**_head(v["head"]))
        head.sequence, head.head_hash, head.accepted_digests = first.sequence, digest, {first.sequence: digest}
        assert wv2.verify_witness_entry_v2(again, head, PUB[v["witness_key"]]) == wv2.WitnessEntryV2Result.REPLAY
    elif kind == "verification_receipt":
        first, again = vrv2.decode_verification_receipt_v2(deterministic), vrv2.decode_verification_receipt_v2(hedged)
        digest = vrv2.verification_receipt_v2_digest(first)
        assert vrv2.verification_receipt_v2_digest(again) == digest
        head = vrv2.ReceiptV2Head(verifier_id=v["head"]["verifier_id"], **_head(v["head"]))
        head.sequence, head.head_hash, head.accepted_digests = first.sequence, digest, {first.sequence: digest}
        assert vrv2.verify_verification_receipt_v2(again, PUB[v["verifier_key"]], head) == wv2.WitnessEntryV2Result.REPLAY
    elif kind == "key_rotation_statement":
        first, again = kr.decode_key_rotation_statement_v2(deterministic), kr.decode_key_rotation_statement_v2(hedged)
        assert kr.key_rotation_statement_v2_digest(again) == kr.key_rotation_statement_v2_digest(first)
        state = _rotation_state(v["rotation_state"])
        journal = kr.KeyRotationV2Journal(state=state)
        journal, result = kr.accept_key_rotation_statement_v2(first, journal, v["now"], v["future_skew_seconds"])
        assert result == wv2.WitnessEntryV2Result.APPENDED
        journal, result = kr.accept_key_rotation_statement_v2(again, journal, v["now"], v["future_skew_seconds"])
        assert result == wv2.WitnessEntryV2Result.REPLAY and not journal.frozen


@pytest.mark.parametrize("o", HEDGED["objects"], ids=lambda o: o["name"])
def test_hedged_object(o):
    deterministic = b64(o["deterministic_wire_b64"])
    assert len(o["hedged_wire_b64"]) >= 2 and o["resigned_fields"]
    seen = [deterministic]
    decode, encode = CODECS[o["kind"]]
    for i, encoded in enumerate(o["hedged_wire_b64"]):
        wire = b64(encoded)
        assert wire not in seen, f"variant {i} repeats an earlier signature"
        seen.append(wire)
        assert encode(decode(wire)) == wire, f"variant {i} does not re-encode identically"
        verify_object(o["kind"], wire, None, o["verify"])
        for field in o["resigned_fields"]:
            assert projection(wire, field) == projection(deterministic, field), (i, field)
        check_idempotency(o["kind"], o["verify"], deterministic, wire)


def test_hedged_objects_cover_every_kind():
    assert {o["kind"] for o in HEDGED["objects"]} == {
        "delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement",
        "witness_entry", "transaction_receipt", "verification_receipt"}
    assert len(HEDGED["objects"]) == 10
