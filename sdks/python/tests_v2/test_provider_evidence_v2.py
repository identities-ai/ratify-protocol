"""Provider evidence (testvectors/v2/provider-evidence/): every device
evidence record present, through the public v2 API. Each record's key must
issue its delegation certificate, prove possession in its key rotation
statement, and sign its revocation list; every object re-encodes to its wire
bytes, and a certificate with one flipped ML-DSA-65 signature byte fails.
Verification is pure Python and needs no native extension."""
from __future__ import annotations

import dataclasses
import json

import pytest

from corpus import PROVIDER_EVIDENCE_DIR, b64, pubkey
from ratify_protocol.v2 import key_rotation_v2 as kr
from ratify_protocol.v2 import protocol_v2 as pv2
from ratify_protocol.v2.errors_v2 import error_class_of
from ratify_protocol.v2.signing_v2 import (
    KEY_ROTATION_AUTHORIZATION,
    KEY_ROTATION_PROOF_OF_POSSESSION,
    key_id_v2,
    verify_v2_statement,
)

RECORDS = sorted(PROVIDER_EVIDENCE_DIR.glob("*.json")) if PROVIDER_EVIDENCE_DIR.exists() else []
KINDS = ["delegation_certificate", "key_rotation_statement", "revocation_list"]
# Checks per record: 4 record, 5 certificate (one negative), 4 rotation, 2 status.
CHECKS_PER_RECORD = 15


def check_record(path) -> int:
    """Runs every check of one record and returns how many ran."""
    checks = 0

    def check(ok, what):
        nonlocal checks
        assert ok, f"{path.name}: {what}"
        checks += 1

    r = json.loads(path.read_bytes())
    check(r["version"] == 1, "version is not 1")
    check(path.name == f"{r['platform']}-{r['provider']}.json", "file name is not <platform>-<provider>.json")
    key, kid = pubkey(r["public_key"]), r["key_id_v2"]
    check(key_id_v2(key) == kid, "key_id_v2 is not the v2 key ID of public_key")
    check([o["kind"] for o in r["objects"]] == KINDS, "objects are not one of each kind")

    for o in r["objects"]:
        wire = b64(o["wire_b64"])
        kind = o["kind"]
        if kind == "delegation_certificate":
            cert = pv2.decode_delegation_cert_v2(wire)
            pv2.verify_delegation_cert_v2_signature(cert)
            check(True, "certificate signature")
            check(cert.issuer_pub_key == key, "certificate issuer_pub_key is not public_key")
            check(cert.issuer_id == kid, "certificate issuer_id is not key_id_v2")
            check(pv2.encode_delegation_cert_v2(cert) == wire, "certificate re-encoding differs")
            ml = bytearray(cert.signature.ml_dsa_65)
            ml[0] ^= 1
            bad = dataclasses.replace(cert, signature=dataclasses.replace(cert.signature, ml_dsa_65=bytes(ml)))
            with pytest.raises(Exception) as info:
                pv2.verify_delegation_cert_v2_signature(bad)
            check(error_class_of(info.value) == "invalid_signature", "flipped ML-DSA-65 byte did not fail")
        elif kind == "key_rotation_statement":
            stmt = kr.decode_key_rotation_statement_v2(wire)
            signable = kr.key_rotation_signable_bytes_v2(stmt)
            check(stmt.new_key == key, "rotation new_key is not public_key")
            verify_v2_statement(KEY_ROTATION_AUTHORIZATION, signable, stmt.old_signature, stmt.old_key)
            check(True, "rotation old_signature")
            verify_v2_statement(KEY_ROTATION_PROOF_OF_POSSESSION, signable, stmt.new_signature, stmt.new_key)
            check(True, "rotation new_signature")
            check(kr.encode_key_rotation_statement_v2(stmt) == wire, "rotation re-encoding differs")
        elif kind == "revocation_list":
            lst = pv2.decode_revocation_list_v2(wire)
            pv2.verify_revocation_list_v2_signature(lst, kid, key)
            check(True, "revocation list signature")
            check(pv2.encode_revocation_list_v2(lst) == wire, "revocation list re-encoding differs")
        else:
            pytest.fail(f"{path.name}: unknown object kind {kind!r}")
    return checks


def test_provider_evidence_directory_holds_records():
    assert RECORDS, "provider-evidence/ has no records"
    assert {p.name for p in PROVIDER_EVIDENCE_DIR.iterdir()} == {p.name for p in RECORDS}


@pytest.mark.parametrize("path", RECORDS, ids=lambda p: p.name)
def test_provider_evidence_record(path):
    assert check_record(path) == CHECKS_PER_RECORD
