"""Cross-SDK fixtures (SPEC-v2 §8.1, testvectors/v2/README.md "cross-sdk/").

``build_fixture`` produces this SDK's ``cross-sdk/python.json`` from fresh
random keys and hedged ML-DSA-65 signatures, using only the typed signers.
``verify_fixture`` runs the documented verification procedure over any SDK's
fixture with the pure-Python verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json

from ratify_protocol_v2 import _mldsa65, _native, _v2json
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import transaction_receipt_v2 as txv2
from ratify_protocol_v2 import verification_receipt_v2 as vrv2
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2._version import __version__
from ratify_protocol_v2.challenge_claim_v2 import challenge_claim_digest_v2, protocol_claim_id_v2
from ratify_protocol_v2.constraints_v2 import ConstraintV2, is_registered_constraint_type_v2
from ratify_protocol_v2.operation_context_v2 import operation_context_v2_hash, session_context_v2_hash
from ratify_protocol_v2.signing_v2 import (
    key_id_v2,
    keypair_from_seeds_v2,
    mldsa_context_v2,
    signing_message_v2,
)
from ratify_protocol_v2.types import HybridPublicKey, HybridSignature
from ratify_protocol_v2.types_v2 import ConstraintEvaluatorRefV2, StatusEvidenceEntryV2

KEY_NAMES = ["root", "intermediate", "agent", "verifier", "status_root", "status_intermediate",
             "witness", "party_b_root", "party_b_agent", "rotation_genesis", "rotation_second"]
KINDS = ["delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement",
         "witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding"]
KIND_CODES = {"delegation_certificate": 1, "proof_bundle": 2, "revocation_list": 3, "key_rotation_statement": 4,
              "revocation_push": 5, "witness_entry": 6, "transaction_receipt": 7, "verification_receipt": 8}

NOW = 1800000000
WORKSPACE = "00000000-0000-4000-8000-000000000001"
NAMESPACE, REPLAY_EPOCH = "verify-test", 3
WITNESS_LOG = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
RECEIPT_LOG = "cccccccccccccccccccccccccccccc01"
EVALUATOR_RECEIPT_LOG = "cccccccccccccccccccccccccccccc02"
MAX_COUNT_TYPE = "com.ratifyprotocol.max_count"
MAX_COUNT_PROFILE = "com.ratifyprotocol.max_count/v1"
# The digest of the verifier session-context policy of SPEC-v2 §7.12, as pinned
# by operation-session-context.json.
CONTEXT_POLICY_DIGEST = "sha384:610c40faa472aa2a4f905988899733758cccf30f243aed35f1f42433228a28dbab1725cb2a4a6811029a8109da0b9b29"

DESCRIPTION = (
    "Cross-SDK fixture (SPEC-v2 §8.1) produced by the Python v2 SDK. keys are freshly generated (keys.json entry "
    "schema; seeds are throwaway test data). objects follow the objects.json object schema: every ML-DSA-65 "
    "component is hedged, so signature bytes are not reproducible. A verifying SDK MUST derive each public key and "
    "key_id_v2 from its seeds, and for every object decode wire_b64, re-encode it to identical bytes, derive each "
    "signable projection, transcript M, context, tr and mu, find each pinned signature in the wire object, verify "
    "every signature with the named verify context (key names resolve to this file's keys), and reproduce every "
    "digest. A receipt_bundle_binding object is verified by strict decode of wire_b64 (verification receipt) and "
    "bundle_b64 (proof bundle) and the receipt/bundle binding check. Timestamps are relative to the fixed "
    "evaluation time 1800000000."
)


def b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def profile_digest(profile: str, kind: str) -> str:
    """Go ``ConstraintProfileDigestV2`` of a descriptor."""
    body = _v2json.canonical({"profile": profile, "type": kind})
    return "sha384:" + hashlib.sha384(b"ratify-protocol-constraint-profile-v2\x00" + body).hexdigest()


# ---------------------------------------------------------------------------
# Projections and signature records


def projection(wire: bytes, field: str) -> bytes:
    """The SPEC-v2 §5 signable projection for one signature field."""
    obj = _v2json.parse(wire)

    def drop(*names):
        for n in names:
            obj.pop(n, None)
        return _v2json.canonical(obj)

    if field == "signature":
        return drop("signature")
    if field == "challenge_sig":
        return drop("delegations", "challenge_sig")
    if field in ("old_signature", "new_signature"):
        return drop("old_signature", "new_signature")
    if field.startswith("delegations["):
        index = int(field[len("delegations["):].split("]")[0])
        return projection(_v2json.canonical(obj["delegations"][index]), "signature")
    if field.startswith("party_signatures["):
        return txv2.transaction_receipt_v2_sign_bytes(txv2.decode_transaction_receipt_v2(wire))
    raise ValueError(f"unknown signature field {field!r}")


def _carried_signature(wire: bytes, field: str) -> dict:
    obj = _v2json.parse(wire)
    if field.startswith("delegations["):
        index = int(field[len("delegations["):].split("]")[0])
        return obj["delegations"][index]["signature"]
    if field.startswith("party_signatures["):
        party = field[len("party_signatures["):-1]
        return next(s for s in obj["party_signatures"] if s["party_id"] == party)["signature"]
    return obj[field]


def signature_record(wire: bytes, field: str, code: int, signer: str, pub: HybridPublicKey) -> dict:
    signable = projection(wire, field)
    message = signing_message_v2(code, signable)
    context = mldsa_context_v2(code)
    return {
        "field": field, "object_type_code": code, "signer": signer, "signer_key_id_v2": key_id_v2(pub),
        "signable_b64": b64(signable), "signable_sha384_hex": hashlib.sha384(signable).hexdigest(),
        "message_b64": b64(message), "mldsa_context": context.decode("ascii"),
        "mldsa_tr_b64": b64(_mldsa65.compute_tr(pub.ml_dsa_65)),
        "mldsa_mu_b64": b64(_mldsa65.compute_mu(pub.ml_dsa_65, message, context)),
        "signature": _carried_signature(wire, field),
    }


# ---------------------------------------------------------------------------
# Generation


class _Keys:
    def __init__(self, names):
        self.entries, self.pub, self.priv, self.id = [], {}, {}, {}
        import os

        for name in names:
            ed_seed, ml_seed = os.urandom(32), os.urandom(32)
            pub, priv = keypair_from_seeds_v2(ed_seed, ml_seed)
            self.pub[name], self.priv[name], self.id[name] = pub, priv, key_id_v2(pub)
            self.entries.append({
                "name": name, "ed25519_seed_hex": ed_seed.hex(), "ml_dsa_65_seed_hex": ml_seed.hex(),
                "public_key": {"ed25519": b64(pub.ed25519), "ml_dsa_65": b64(pub.ml_dsa_65)},
                "key_id_v2": self.id[name],
                "v1_key_id_128": hashlib.sha256(pub.ed25519 + pub.ml_dsa_65).hexdigest()[:32],
            })


def build_fixture(sdk_version: str = __version__, generator: str = "python sdks/python-v2/tests/gen_cross_sdk_fixture.py") -> dict:
    """A fresh fixture; it is verified with :func:`verify_fixture` before return."""
    k = _Keys(KEY_NAMES)
    objects: list[dict] = []

    def add(name, kind, description, wire, signatures, digests, verify=None, bundle_wire=None):
        o = {"name": name, "kind": kind, "description": description, "wire_b64": b64(wire),
             "verify": verify or {}, "signatures": signatures, "digests": digests}
        if bundle_wire is not None:
            o["bundle_b64"] = b64(bundle_wire)
        objects.append(o)

    def cert(issuer, subject, cert_id, scope, constraints=()):
        unsigned = pv2.DelegationCertV2(
            version=2, cert_id=cert_id, issuer_id=k.id[issuer], issuer_pub_key=k.pub[issuer],
            subject_id=k.id[subject], subject_pub_key=k.pub[subject], scope=list(scope),
            constraints=list(constraints), issued_at=NOW - 3600, expires_at=NOW + 86400)
        return pv2.sign_delegation_cert_v2(unsigned, k.priv[issuer])

    def sig_records(wire, fields):
        return [signature_record(wire, f, code, signer, k.pub[signer]) for f, code, signer in fields]

    def bundle(agent, certs, session, challenge=bytes(range(0xA0, 0xC0)), stream_id=None, stream_seq=None):
        unsigned = pv2.ProofBundleV2(
            version=2, verifier_id=k.id["verifier"], agent_id=k.id[agent], agent_pub_key=k.pub[agent],
            delegations=list(certs), delegation_digest=bytes(48), challenge=challenge, challenge_at=NOW - 10,
            challenge_sig=pv2.placeholder_signature_v2(), session_context=session, stream_id=stream_id,
            stream_seq=stream_seq)
        return pv2.sign_proof_bundle_v2(unsigned, k.priv[agent])

    # Delegation certificates.
    root_cert = cert("root", "intermediate", "cert-root", ["data:read", "files:read", "identity:delegate"])
    wire = pv2.encode_delegation_cert_v2(root_cert)
    add("delegation_root_to_intermediate", "delegation_certificate",
        "Root delegates to an intermediate, including identity:delegate.", wire,
        sig_records(wire, [("signature", 1, "root")]),
        {"issuer_key_id_v2": k.id["root"], "subject_key_id_v2": k.id["intermediate"]})
    constraints = [
        ConstraintV2(type="max_rate", count=5, window_s=60),
        ConstraintV2(type="ratify.receiver_audience", params={
            "exact_receiver_ids": ["receiver-1"], "trust_domain_ids": ["domain-a"], "max_membership_age_seconds": 3600}),
        ConstraintV2(type="resource_path", resource_id="customer/123", path_prefix="/v1/customers/"),
        ConstraintV2(type="time_window", start="22:00", end="06:00", tz="America/New_York"),
        ConstraintV2(type="max_amount", currency="USD", max_amount_micros=2500000),
        ConstraintV2(type=MAX_COUNT_TYPE, params={"counter": "nodes", "max": 10}),
    ]
    leaf_cons = cert("intermediate", "agent", "cert-leaf-constrained", ["data:read"], constraints)
    wire = pv2.encode_delegation_cert_v2(leaf_cons)
    add("delegation_every_registered_constraint_and_extension", "delegation_certificate",
        "Every type in the closed v2 constraint registry (max_rate, ratify.receiver_audience, resource_path, "
        "time_window, max_amount) plus the extension evaluator type com.ratifyprotocol.max_count.", wire,
        sig_records(wire, [("signature", 1, "intermediate")]),
        {"issuer_key_id_v2": k.id["intermediate"], "subject_key_id_v2": k.id["agent"]})

    # Proof bundles.
    request = operation_context_v2_hash("data:read", "records.get", "customer/123", "/v1/customers/123")
    session = session_context_v2_hash(k.id["verifier"], WORKSPACE, k.id["agent"], "session-01", "invocation-01", request)

    def bundle_digests(b, b_wire):
        return {"delegation_digest_hex": pv2.delegation_digest_v2(b.delegations).hex(),
                "bundle_hash_v2": pv2.bundle_hash_v2(b), "session_context_hex": session.hex()}

    chain_fields = [("challenge_sig", 2, "agent"), ("delegations[0].signature", 1, "intermediate"),
                    ("delegations[1].signature", 1, "root")]
    plain_leaf = cert("intermediate", "agent", "cert-leaf", ["data:read", "files:read"])
    plain = bundle("agent", [plain_leaf, root_cert], session)
    plain_wire = pv2.encode_proof_bundle_v2(plain)
    digests = bundle_digests(plain, plain_wire)
    digests["challenge_claim_digest_hex"] = challenge_claim_digest_v2(plain.challenge).hex()
    digests["claim_id"] = protocol_claim_id_v2(NAMESPACE, REPLAY_EPOCH, plain.challenge)
    digests["claim_verifier_namespace"] = NAMESPACE
    digests["claim_replay_epoch"] = str(REPLAY_EPOCH)
    add("proof_bundle_two_link_bound_context", "proof_bundle",
        "Leaf-to-root chain with a bound session_context and null stream fields.", plain_wire,
        sig_records(plain_wire, chain_fields), digests)
    ext = bundle("agent", [leaf_cons, root_cert], session, challenge=bytes(range(0xB0, 0xD0)))
    ext_wire = pv2.encode_proof_bundle_v2(ext)
    add("proof_bundle_constrained_chain", "proof_bundle",
        "Chain whose leaf is the constrained certificate above, with a bound session_context.", ext_wire,
        sig_records(ext_wire, chain_fields), bundle_digests(ext, ext_wire))
    stream = bundle("agent", [], None, stream_id=b"\x5a" * 32, stream_seq=1)
    stream_wire = pv2.encode_proof_bundle_v2(stream)
    add("proof_bundle_empty_chain_stream_bound", "proof_bundle",
        "Empty delegations array, null session_context, and a bound stream at sequence 1.", stream_wire,
        sig_records(stream_wire, [("challenge_sig", 2, "agent")]),
        {"delegation_digest_hex": pv2.delegation_digest_v2([]).hex(), "bundle_hash_v2": pv2.bundle_hash_v2(stream)})

    # Status objects.
    def status_digest(code, obj):
        return "sha384:" + pv2.status_evidence_digest(code, obj).hex()

    root_list = pv2.sign_revocation_list_v2(
        pv2.RevocationListV2(2, k.id["root"], NOW - 60, NOW + 3600, 7, ["cert-a", "cert-b"]),
        k.id["root"], k.pub["status_root"], k.priv["status_root"])
    wire = pv2.encode_revocation_list_v2(root_list)
    add("revocation_list_root", "revocation_list",
        "Snapshot signed under code 0x0003 by the status key bound to the root issuer.", wire,
        sig_records(wire, [("signature", 3, "status_root")]), {"status_evidence_digest": status_digest(3, root_list)},
        verify={"bound_issuer_id": k.id["root"], "status_key": "status_root"})
    inter_list = pv2.sign_revocation_list_v2(
        pv2.RevocationListV2(2, k.id["intermediate"], NOW - 60, NOW + 3600, 1, []),
        k.id["intermediate"], k.pub["status_intermediate"], k.priv["status_intermediate"])
    wire = pv2.encode_revocation_list_v2(inter_list)
    add("revocation_list_intermediate_empty", "revocation_list",
        "Empty snapshot signed by the status key bound to the intermediate issuer.", wire,
        sig_records(wire, [("signature", 3, "status_intermediate")]),
        {"status_evidence_digest": status_digest(3, inter_list)},
        verify={"bound_issuer_id": k.id["intermediate"], "status_key": "status_intermediate"})
    push = pv2.sign_revocation_push_v2(pv2.RevocationPushV2(2, k.id["root"], 8, NOW - 30, ["cert-c"]),
                                       k.id["root"], k.pub["status_root"], k.priv["status_root"])
    wire = pv2.encode_revocation_push_v2(push)
    add("revocation_push", "revocation_push", "Push signed under code 0x0005 by the bound status key.", wire,
        sig_records(wire, [("signature", 5, "status_root")]), {"status_evidence_digest": status_digest(5, push)},
        verify={"bound_issuer_id": k.id["root"], "status_key": "status_root"})

    # Key rotation and witness entry.
    authority = "0123456789abcdef0123456789abcdef"
    stmt = kr.KeyRotationStatementV2(
        version=2, authority_id=authority, recovery_epoch=1, role="issuer", sequence=1,
        previous_statement_hash=bytes(48), old_key=k.pub["rotation_genesis"], new_key=k.pub["rotation_second"],
        old_key_id=k.id["rotation_genesis"], new_key_id=k.id["rotation_second"], issued_at=NOW - 600,
        not_before=NOW - 600)
    stmt = kr.sign_key_rotation_statement_v2(stmt, k.priv["rotation_genesis"], k.priv["rotation_second"])
    wire = kr.encode_key_rotation_statement_v2(stmt)
    add("key_rotation_genesis", "key_rotation_statement",
        "Genesis rotation: the old key signs code 0x0004 and the new key signs the identical body under code 0x0009.",
        wire, sig_records(wire, [("old_signature", 4, "rotation_genesis"), ("new_signature", 9, "rotation_second")]),
        {"statement_body_digest_hex": kr.key_rotation_statement_v2_digest(stmt).hex()},
        verify={"rotation_state": {"authority_id": authority, "recovery_epoch": 1, "role": "issuer", "sequence": 0,
                                   "head_hash_b64": b64(bytes(48)), "current_key": "rotation_genesis",
                                   "used_key_ids": [k.id["rotation_genesis"]]},
                "now": NOW, "future_skew_seconds": 5})
    entry = wv2.sign_witness_entry_v2(
        wv2.WitnessEntryV2(version=2, log_id=WITNESS_LOG, sequence=1, prev_hash=bytes(48), entry_data=b"entry-1",
                           timestamp=NOW - 20, witness_id=k.id["witness"], signature=pv2.placeholder_signature_v2()),
        k.priv["witness"])
    wire = wv2.encode_witness_entry_v2(entry)
    add("witness_entry_genesis", "witness_entry", "Genesis witness entry; prev_hash is 48 zero bytes.", wire,
        sig_records(wire, [("signature", 6, "witness")]),
        {"statement_body_digest_hex": wv2.witness_entry_v2_digest(entry).hex()},
        verify={"witness_key": "witness", "head": {"log_id": WITNESS_LOG, "sequence": 0, "head_hash_b64": b64(bytes(48)),
                                                   "accepted_digests_b64": {}, "frozen": False}})

    # Transaction receipt.
    terms = b'{"amount":100,"currency":"USD","item":"widget"}'
    specs = [("party-a", "buyer", "agent", "root", "transact:purchase"),
             ("party-b", "seller", "party_b_agent", "party_b_root", "transact:sell")]
    skeleton = txv2.TransactionReceiptV2(version=2, transaction_id="tx-0001", created_at=NOW - 5,
                                         terms_schema_uri="https://example.com/terms/purchase/v1",
                                         terms_canonical_json=terms, parties=[])
    tx_context = txv2.transaction_context_hash_v2(skeleton)
    tx_digests = {"transaction_context_hex": tx_context.hex()}
    for party_id, role, agent, root, scope in specs:
        party_request = txv2.transaction_party_request_hash_v2(tx_context, scope)
        party_session = session_context_v2_hash(k.id["verifier"], WORKSPACE, k.id[agent], f"session-{party_id}",
                                                 f"invocation-{party_id}", party_request)
        party_bundle = bundle(agent, [cert(root, agent, f"cert-{party_id}", [scope])], party_session)
        bundle_hash = pv2.bundle_hash_v2(party_bundle)
        skeleton.parties.append(txv2.TransactionReceiptPartyV2(
            party_id=party_id, role=role, agent_id=k.id[agent], agent_pub_key=k.pub[agent],
            verifier_id=k.id["verifier"], workspace_id=WORKSPACE, session_id=f"session-{party_id}",
            invocation_id=f"invocation-{party_id}", required_scope=scope, proof_bundle_hash=bundle_hash,
            proof_bundle=party_bundle))
        tx_digests[f"{party_id}.transaction_party_request_hash_hex"] = party_request.hex()
        tx_digests[f"{party_id}.session_context_hex"] = party_session.hex()
        tx_digests[f"{party_id}.proof_bundle_hash"] = bundle_hash
    skeleton.party_signatures = [
        txv2.sign_transaction_receipt_party_v2(skeleton, party_id, k.priv[agent]) for party_id, _, agent, _, _ in specs]
    wire = txv2.encode_transaction_receipt_v2(skeleton)
    add("transaction_receipt_two_parties", "transaction_receipt",
        "Two parties sign the identical signable object under code 0x0007.", wire,
        sig_records(wire, [("party_signatures[party-a]", 7, "agent"), ("party_signatures[party-b]", 7, "party_b_agent")]),
        tx_digests)

    # Verification receipts, each paired with its bundle.
    evidence = sorted([
        StatusEvidenceEntryV2(k.id["root"], k.id["status_root"], 7, 3, status_digest(3, root_list)),
        StatusEvidenceEntryV2(k.id["intermediate"], k.id["status_intermediate"], 1, 3, status_digest(3, inter_list)),
    ], key=lambda e: (e.issuer_id, e.status_key_id, e.sequence, e.object_type, e.digest))

    def receipt(b, granted, log_id, evaluators=None):
        body = vrv2.VerificationReceiptV2(
            version=2, log_id=log_id, sequence=1, verifier_id=k.id["verifier"], agent_id=b.agent_id,
            bundle_hash=pv2.bundle_hash_v2(b), issuer_ids=sorted([k.id["root"], k.id["intermediate"]]),
            decision="allow", decision_reason="authorized", identity_status="authorized_agent",
            trust_assessment="trusted", status_assessment="current", challenge_assessment="current",
            context_assessment="bound", context_policy_digest=CONTEXT_POLICY_DIGEST, verified_at=NOW,
            required_scope="data:read", granted_scope=list(granted), status_evidence=list(evidence),
            previous_receipt_hash=bytes(48), constraint_evaluators=evaluators)
        return vrv2.sign_verification_receipt_v2(body, k.priv["verifier"])

    def add_receipt(name, description, signed, bundle_wire):
        wire = vrv2.encode_verification_receipt_v2(signed)
        add(name, "verification_receipt", description, wire, sig_records(wire, [("signature", 8, "verifier")]),
            {"statement_body_digest_hex": vrv2.verification_receipt_v2_digest(signed).hex(),
             "receipt_outbox_body_b64": b64(vrv2.verification_receipt_v2_body(signed))},
            verify={"verifier_key": "verifier", "head": {"log_id": signed.log_id, "verifier_id": k.id["verifier"],
                                                         "sequence": 0, "head_hash_b64": b64(bytes(48)),
                                                         "accepted_digests_b64": {}, "frozen": False}})
        add(name + "/bundle_binding", "receipt_bundle_binding",
            "The receipt above (wire_b64) with the proof bundle it was issued for (bundle_b64): bundle_hash, "
            "verifier_id, agent_id, and issuer_ids bind.", wire, [], {}, bundle_wire=bundle_wire)

    add_receipt("verification_receipt_allow_genesis",
                "Genesis allow receipt for proof_bundle_two_link_bound_context, signed under code 0x0008 by the "
                "caller-authenticated verifier key.", receipt(plain, ["data:read", "files:read"], RECEIPT_LOG), plain_wire)
    refs = [ConstraintEvaluatorRefV2(profile_digest=profile_digest(MAX_COUNT_PROFILE, MAX_COUNT_TYPE), type=MAX_COUNT_TYPE)]
    add_receipt("verification_receipt_constraint_evaluators",
                "Genesis allow receipt for proof_bundle_constrained_chain carrying the signed constraint_evaluators "
                "member for com.ratifyprotocol.max_count/v1.",
                receipt(ext, ["data:read"], EVALUATOR_RECEIPT_LOG, refs), ext_wire)

    fixture = {"version": 2, "description": DESCRIPTION, "sdk": "python", "sdk_version": sdk_version,
               "generator": generator, "kind_object_type_codes": dict(KIND_CODES), "keys": k.entries,
               "objects": objects}
    verify_fixture(json.dumps(fixture).encode("utf-8"), "python")
    return fixture


# ---------------------------------------------------------------------------
# Verification


class FixtureError(AssertionError):
    pass


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise FixtureError(message)


def verify_fixture(data: bytes, file_stem: str) -> dict:
    """Run the cross-SDK verification procedure over one fixture file.
    Returns per-kind object counts; raises on any failure."""
    from test_v2_conformance import CODECS, check_object, verify_object  # noqa: PLC0415

    f = json.loads(data)
    _require(f.get("version") == 2, "version must be 2")
    _require(f.get("sdk") == file_stem, f"sdk {f.get('sdk')!r} does not match the file name {file_stem!r}")
    for member in ("description", "sdk_version", "generator"):
        _require(isinstance(f.get(member), str) and f[member] != "", f"{member} is required")
    _require(f.get("kind_object_type_codes") == KIND_CODES, "kind_object_type_codes differs from objects.json")
    pub: dict[str, HybridPublicKey] = {}
    ids: dict[str, str] = {}
    for entry in f["keys"]:
        name = entry["name"]
        _require(name not in pub, f"duplicate key {name}")
        listed = HybridPublicKey(b64d(entry["public_key"]["ed25519"]), b64d(entry["public_key"]["ml_dsa_65"]))
        _require(len(bytes.fromhex(entry["ed25519_seed_hex"])) == 32 and len(bytes.fromhex(entry["ml_dsa_65_seed_hex"])) == 32,
                 f"key {name}: bad seed")
        derived = listed
        if _native.AVAILABLE:  # key derivation from seeds needs the native backend
            derived, _ = keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]),
                                               bytes.fromhex(entry["ml_dsa_65_seed_hex"]))
            _require(derived == listed, f"key {name}: seeds do not derive the public key")
        _require(key_id_v2(derived) == entry["key_id_v2"], f"key {name}: key_id_v2 differs")
        pub[name], ids[name] = derived, entry["key_id_v2"]
    for name in KEY_NAMES:
        _require(name in pub, f"missing key {name}")
    counts: dict[str, int] = {}
    codes: set[int] = set()
    all_constraints = evaluators = False
    for o in f["objects"]:
        counts[o["kind"]] = counts.get(o["kind"], 0) + 1
        if o["kind"] == "receipt_bundle_binding":
            wire, bundle_wire = b64d(o["wire_b64"]), b64d(o["bundle_b64"])
            _require(vrv2.encode_verification_receipt_v2(vrv2.decode_verification_receipt_v2(wire)) == wire,
                     f"{o['name']}: receipt does not re-encode identically")
            _require(pv2.encode_proof_bundle_v2(pv2.decode_proof_bundle_v2(bundle_wire)) == bundle_wire,
                     f"{o['name']}: bundle does not re-encode identically")
            verify_object("receipt_bundle_binding", wire, bundle_wire, {}, pub)
            _require(o["signatures"] == [] and o["digests"] == {}, f"{o['name']}: binding carries no signatures")
            continue
        _require(o["kind"] in CODECS, f"{o['name']}: unknown kind {o['kind']}")
        check_object(o, pub, ids)
        codes.update(s["object_type_code"] for s in o["signatures"])
        wire = b64d(o["wire_b64"])
        if o["kind"] == "delegation_certificate":
            types = {c.type for c in pv2.decode_delegation_cert_v2(wire).constraints}
            extension = any(not is_registered_constraint_type_v2(t) for t in types)
            registered = {"max_rate", "ratify.receiver_audience", "resource_path", "time_window", "max_amount"}
            all_constraints = all_constraints or (extension and registered <= types)
        if o["kind"] == "verification_receipt":
            evaluators = evaluators or bool(vrv2.decode_verification_receipt_v2(wire).constraint_evaluators)
    for kind in KINDS:
        _require(counts.get(kind, 0) > 0, f"no {kind} object")
    _require(codes == set(range(1, 10)), f"signature codes {sorted(codes)} do not cover 0x0001..0x0009")
    _require(all_constraints, "no delegation certificate with every registered constraint type and an extension type")
    _require(evaluators, "no verification receipt with constraint_evaluators")
    return counts

