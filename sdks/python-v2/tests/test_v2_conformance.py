"""Shared Protocol v2 conformance corpus runner for the pure-Python SDK.

Every file under testvectors/v2 is loaded. Positive vectors must be
reproduced byte-for-byte; negatives must be rejected with the exact error
class; verifier-ordering vectors must match the stage, class, terminal
tuple, receipt outbox body, allow horizon, rate batch, and every callback
count. A file or vector class this runner does not understand fails the run
(see test_every_corpus_file_is_consumed). Verification runs in pure Python.
Re-deriving keys from seeds and re-signing byte-for-byte need the native
extension (the only signer); those tests are marked ``requires_native`` and
skip, with that reason, only when the extension is absent and
RATIFY_REQUIRE_NATIVE is not set.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ratify_protocol_v2 import _mldsa65, _native
from ratify_protocol_v2 import _v2json
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import status_v2 as sv2
from ratify_protocol_v2 import transaction_receipt_v2 as txv2
from ratify_protocol_v2 import verification_receipt_v2 as vrv2
from ratify_protocol_v2 import verify_v2 as ver
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2.challenge_claim_v2 import challenge_claim_digest_v2, protocol_claim_id_v2
from ratify_protocol_v2.context_policy_v2 import V2AudienceMembership, new_v2_context_policy
from ratify_protocol_v2.errors_v2 import ClaimProofConflictError, RateLimitExceededError, error_class_of
from ratify_protocol_v2.operation_context_v2 import (
    decode_payload_digest,
    operation_context_v2_hash,
    session_context_v2_hash,
)
from ratify_protocol_v2.signing_v2 import (
    keypair_from_seeds_v2,
    key_id_v2,
    mldsa_context_v2,
    _sign_v2_statement,
    signing_message_v2,
    verify_v2_statement,
)
from ratify_protocol_v2._testing import deterministic_test_vector_signing
from ratify_protocol_v2.types import HybridPublicKey, HybridSignature, VerifierContext

requires_native = pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")


def derive_id(pub: HybridPublicKey) -> str:
    """The v1 128-bit key ID (v1 SDK crypto.derive_id), for v1/v2 mixing checks."""
    return hashlib.sha256(bytes(pub.ed25519) + bytes(pub.ml_dsa_65)).hexdigest()[:32]


# RATIFY_V2_VECTOR_DIR exists only so the runner itself can be mutation-tested
# against a tampered copy of the corpus.
V2_DIR = Path(os.environ.get("RATIFY_V2_VECTOR_DIR") or Path(__file__).resolve().parents[3] / "testvectors" / "v2")

# Every file in the corpus directory and the test that consumes it.
CONSUMED = {
    "README.md": "documentation (coverage notes), not a vector file",
    "keys.json": "test_keys / test_invalid_key_ids",
    "objects.json": "test_object",
    "object-negatives.json": "test_object_negative",
    "verifier-ordering.json": "test_verifier_ordering",
    "status-sequences.json": "test_status_sequence",
    "log-sequences.json": "test_log_sequence",
    "rotation-sequences.json": "test_rotation_sequence",
    "delegation-signature.json": "test_delegation_signature_vector",
    "operation-session-context.json": "test_operation_session_context_vector",
    "challenge-claim.json": "test_challenge_claim_vector",
    "key-rotation-signature.json": "test_key_rotation_signature_vector",
    "derive-external-mu.py": "test_derive_external_mu_script",
}


def load(name: str) -> dict:
    return json.loads((V2_DIR / name).read_text())


def b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def pubkey(d: dict) -> HybridPublicKey:
    return HybridPublicKey(ed25519=b64(d["ed25519"]), ml_dsa_65=b64(d["ml_dsa_65"]))


def sig(d: dict) -> HybridSignature:
    return HybridSignature(ed25519=b64(d["ed25519"]), ml_dsa_65=b64(d["ml_dsa_65"]))


KEYS = load("keys.json")
PUB = {k["name"]: pubkey(k["public_key"]) for k in KEYS["keys"]}
KEY_ID = {k["name"]: k["key_id_v2"] for k in KEYS["keys"]}
_PRIV_CACHE: dict = {}


def private_key(name: str):
    if name not in _PRIV_CACHE:
        entry = next(k for k in KEYS["keys"] if k["name"] == name)
        _PRIV_CACHE[name] = keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]),
                                                  bytes.fromhex(entry["ml_dsa_65_seed_hex"]))[1]
    return _PRIV_CACHE[name]


def test_every_corpus_file_is_consumed():
    present = {p.name for p in V2_DIR.iterdir() if p.is_file()}
    unknown = present - set(CONSUMED)
    missing = set(CONSUMED) - present
    assert not unknown, f"corpus files with no Python runner: {sorted(unknown)}"
    assert not missing, f"runner expects files that are absent: {sorted(missing)}"


# ---------------------------------------------------------------------------
# keys.json


@pytest.mark.parametrize("entry", KEYS["keys"], ids=lambda e: e["name"])
def test_keys(entry):
    pub = pubkey(entry["public_key"])
    independent = hashlib.sha256(b"ratify-key-id-v2\x00" + pub.ed25519 + pub.ml_dsa_65).hexdigest()
    assert key_id_v2(pub) == entry["key_id_v2"] == independent
    assert derive_id(pub) == entry["v1_key_id_128"] != entry["key_id_v2"][:32]


@requires_native
@pytest.mark.parametrize("entry", KEYS["keys"], ids=lambda e: e["name"])
def test_keys_derive_from_seeds(entry):
    pub, _ = keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]), bytes.fromhex(entry["ml_dsa_65_seed_hex"]))
    assert pub == pubkey(entry["public_key"]), "seeds do not derive the pinned public key"


def _set_top_level_string(wire: bytes, name: str, value: str) -> bytes:
    obj = _v2json.parse(wire)
    obj[name] = value
    return _v2json.canonical(obj)


OBJECTS = load("objects.json")


def _object_by_kind(kind: str) -> dict:
    return next(o for o in OBJECTS["objects"] if o["kind"] == kind)


@pytest.mark.parametrize("bad", KEYS["invalid_v2_key_ids"], ids=lambda e: e["name"])
def test_invalid_key_ids(bad):
    bundle_wire = b64(_object_by_kind("proof_bundle")["wire_b64"])
    witness_wire = b64(_object_by_kind("witness_entry")["wire_b64"])
    for decode, wire, name in ((pv2.decode_proof_bundle_v2, bundle_wire, "verifier_id"),
                               (wv2.decode_witness_entry_v2, witness_wire, "witness_id")):
        with pytest.raises(Exception) as info:
            decode(_set_top_level_string(wire, name, bad["value"]))
        assert error_class_of(info.value) == bad["expected_error_class"], (name, info.value)


# ---------------------------------------------------------------------------
# objects.json and object-negatives.json


def _head(h: dict) -> dict:
    return dict(log_id=h["log_id"], sequence=h["sequence"], head_hash=b64(h["head_hash_b64"]),
                accepted_digests={int(k): b64(v) for k, v in h["accepted_digests_b64"].items()}, frozen=h["frozen"])


def _rotation_state(rs: dict) -> kr.KeyRotationV2State:
    return kr.KeyRotationV2State(rs["authority_id"], rs["recovery_epoch"], rs["role"], rs["sequence"],
                                 b64(rs["head_hash_b64"]), PUB[rs["current_key"]], list(rs["used_key_ids"]))


def verify_object(kind: str, wire: bytes, bundle_wire, v: dict):
    """The per-kind procedure documented in object-negatives.json."""
    if kind == "delegation_certificate":
        return pv2.verify_delegation_cert_v2_signature(pv2.decode_delegation_cert_v2(wire))
    if kind == "proof_bundle":
        return pv2.verify_proof_bundle_v2_signatures(pv2.decode_proof_bundle_v2(wire))
    if kind == "revocation_list":
        return pv2.verify_revocation_list_v2_signature(pv2.decode_revocation_list_v2(wire), v["bound_issuer_id"], PUB[v["status_key"]])
    if kind == "revocation_push":
        return pv2.verify_revocation_push_v2_signature(pv2.decode_revocation_push_v2(wire), v["bound_issuer_id"], PUB[v["status_key"]])
    if kind == "key_rotation_statement":
        return kr.verify_key_rotation_statement_v2(kr.decode_key_rotation_statement_v2(wire),
                                                   _rotation_state(v["rotation_state"]), v["now"], v["future_skew_seconds"])
    if kind == "witness_entry":
        return wv2.verify_witness_entry_v2(wv2.decode_witness_entry_v2(wire), wv2.WitnessV2Head(**_head(v["head"])), PUB[v["witness_key"]])
    if kind == "transaction_receipt":
        return txv2.verify_transaction_receipt_v2_signatures(txv2.decode_transaction_receipt_v2(wire))
    if kind == "verification_receipt":
        head = vrv2.ReceiptV2Head(verifier_id=v["head"]["verifier_id"], **_head(v["head"]))
        return vrv2.verify_verification_receipt_v2(vrv2.decode_verification_receipt_v2(wire), PUB[v["verifier_key"]], head)
    if kind == "receipt_bundle_binding":
        return vrv2.check_verification_receipt_v2_bundle_binding(vrv2.decode_verification_receipt_v2(wire),
                                                                 pv2.decode_proof_bundle_v2(bundle_wire))
    pytest.fail(f"unknown vector kind {kind!r}")


_CODECS = {
    "delegation_certificate": (pv2.decode_delegation_cert_v2, pv2.encode_delegation_cert_v2),
    "proof_bundle": (pv2.decode_proof_bundle_v2, pv2.encode_proof_bundle_v2),
    "revocation_list": (pv2.decode_revocation_list_v2, pv2.encode_revocation_list_v2),
    "revocation_push": (pv2.decode_revocation_push_v2, pv2.encode_revocation_push_v2),
    "key_rotation_statement": (kr.decode_key_rotation_statement_v2, kr.encode_key_rotation_statement_v2),
    "witness_entry": (wv2.decode_witness_entry_v2, wv2.encode_witness_entry_v2),
    "transaction_receipt": (txv2.decode_transaction_receipt_v2, txv2.encode_transaction_receipt_v2),
    "verification_receipt": (vrv2.decode_verification_receipt_v2, vrv2.encode_verification_receipt_v2),
}


def _projection(wire: bytes, name: str) -> bytes:
    obj = _v2json.parse(wire)

    def drop(*names):
        for n in names:
            obj.pop(n, None)
        return _v2json.canonical(obj)

    if name == "signature":
        return drop("signature")
    if name == "challenge_sig":
        return drop("delegations", "challenge_sig")
    if name in ("old_signature", "new_signature"):
        return drop("old_signature", "new_signature")
    if name.startswith("delegations["):
        index = int(name[len("delegations["):].split("]")[0])
        return _projection(_v2json.canonical(obj["delegations"][index]), "signature")
    if name.startswith("party_signatures["):
        return txv2.transaction_receipt_v2_sign_bytes(txv2.decode_transaction_receipt_v2(wire))
    pytest.fail(f"unknown signature field {name!r}")


def _check_object_digests(o: dict, wire: bytes) -> None:
    digests = o["digests"]
    for name, want in digests.items():
        if name in ("issuer_key_id_v2", "subject_key_id_v2"):
            c = pv2.decode_delegation_cert_v2(wire)
            got = key_id_v2(c.issuer_pub_key if name == "issuer_key_id_v2" else c.subject_pub_key)
        elif name == "delegation_digest_hex":
            got = pv2.decode_proof_bundle_v2(wire).delegation_digest.hex()
        elif name == "bundle_hash_v2":
            got = pv2.bundle_hash_v2(pv2.decode_proof_bundle_v2(wire))
        elif name == "session_context_hex":
            b = pv2.decode_proof_bundle_v2(wire)
            request = operation_context_v2_hash("data:read", "records.get", "customer/123", "/v1/customers/123")
            ctx = session_context_v2_hash(b.verifier_id, "00000000-0000-4000-8000-000000000001", b.agent_id,
                                          "session-01", "invocation-01", request)
            assert b.session_context == ctx, "bundle session_context differs from the recomputed fixture context"
            got = ctx.hex()
        elif name == "challenge_claim_digest_hex":
            got = challenge_claim_digest_v2(pv2.decode_proof_bundle_v2(wire).challenge).hex()
        elif name == "claim_id":
            got = protocol_claim_id_v2(digests["claim_verifier_namespace"], int(digests["claim_replay_epoch"]),
                                       pv2.decode_proof_bundle_v2(wire).challenge)
        elif name in ("claim_verifier_namespace", "claim_replay_epoch", "transaction_context_hex"):
            continue  # inputs to claim_id / party digests, checked there
        elif name == "receipt_outbox_body_b64":
            got = base64.b64encode(vrv2.verification_receipt_v2_body(vrv2.decode_verification_receipt_v2(wire))).decode()
        elif name == "status_evidence_digest":
            if o["kind"] == "revocation_list":
                d = pv2.status_evidence_digest(3, pv2.decode_revocation_list_v2(wire))
            else:
                d = pv2.status_evidence_digest(5, pv2.decode_revocation_push_v2(wire))
            got = "sha384:" + d.hex()
        elif name == "statement_body_digest_hex":
            if o["kind"] == "key_rotation_statement":
                d = kr.key_rotation_statement_v2_digest(kr.decode_key_rotation_statement_v2(wire))
            elif o["kind"] == "witness_entry":
                d = wv2.witness_entry_v2_digest(wv2.decode_witness_entry_v2(wire))
            elif o["kind"] == "verification_receipt":
                d = vrv2.verification_receipt_v2_digest(vrv2.decode_verification_receipt_v2(wire))
            else:
                pytest.fail(f"statement digest for unexpected kind {o['kind']}")
            got = d.hex()
        elif name.startswith("party-"):
            got = _party_digest(wire, name, digests["transaction_context_hex"])
        else:
            pytest.fail(f"unknown digest {name!r}")
        assert got == want, f"digest {name}"


def _party_digest(wire: bytes, name: str, tx_context_hex: str) -> str:
    receipt = txv2.decode_transaction_receipt_v2(wire)
    party_id, _, field_name = name.partition(".")
    tx_context = txv2.transaction_context_hash_v2(receipt)
    assert tx_context.hex() == tx_context_hex
    party = next(p for p in receipt.parties if p.party_id == party_id)
    request = txv2.transaction_party_request_hash_v2(tx_context, party.required_scope)
    if field_name == "transaction_party_request_hash_hex":
        return request.hex()
    if field_name == "session_context_hex":
        return session_context_v2_hash(party.verifier_id, party.workspace_id, party.agent_id, party.session_id,
                                       party.invocation_id, request).hex()
    if field_name == "proof_bundle_hash":
        return pv2.bundle_hash_v2(party.proof_bundle)
    pytest.fail(f"unknown transaction digest {name!r}")


@pytest.mark.parametrize("o", OBJECTS["objects"], ids=lambda o: o["name"])
def test_object(o):
    wire = b64(o["wire_b64"])
    decode, encode = _CODECS[o["kind"]]
    assert encode(decode(wire)) == wire, "re-encoding is not byte-identical"
    verify_object(o["kind"], wire, None, o["verify"])
    for s in o["signatures"]:
        signable = b64(s["signable_b64"])
        assert _projection(wire, s["field"]) == signable, f"{s['field']}: signable projection differs"
        assert hashlib.sha384(signable).hexdigest() == s["signable_sha384_hex"]
        code = s["object_type_code"]
        message = signing_message_v2(code, signable)
        assert message == b64(s["message_b64"]) and len(message) == 77
        context = mldsa_context_v2(code)
        assert s["mldsa_context"] == context.decode() and len(context) == 22
        assert KEY_ID[s["signer"]] == s["signer_key_id_v2"]
        signer = PUB[s["signer"]]
        assert _mldsa65.compute_tr(signer.ml_dsa_65) == b64(s["mldsa_tr_b64"])
        assert _mldsa65.compute_mu(signer.ml_dsa_65, message, context) == b64(s["mldsa_mu_b64"])
        pinned = sig(s["signature"])
        assert base64.b64encode(pinned.ml_dsa_65) in wire and base64.b64encode(pinned.ed25519) in wire
        verify_v2_statement(code, signable, pinned, signer)
    _check_object_digests(o, wire)


@requires_native
@pytest.mark.parametrize("o", OBJECTS["objects"], ids=lambda o: o["name"])
def test_object_native_resign(o):
    """The native signer reproduces every pinned signature byte-for-byte
    (deterministic Ed25519, unhedged ML-DSA-65 from the fixture seeds)."""
    for s in o["signatures"]:
        signable = b64(s["signable_b64"])
        with deterministic_test_vector_signing():
            resigned = _sign_v2_statement(s["object_type_code"], signable, private_key(s["signer"]))
        assert resigned == sig(s["signature"]), s["field"]


def test_objects_cover_every_object_code():
    codes = {s["object_type_code"] for o in OBJECTS["objects"] for s in o["signatures"]}
    assert codes == set(range(1, 10))


NEGATIVES = load("object-negatives.json")


@pytest.mark.parametrize("v", NEGATIVES["vectors"], ids=lambda v: v["name"])
def test_object_negative(v):
    bundle = b64(v["bundle_b64"]) if v.get("bundle_b64") else None
    with pytest.raises(Exception) as info:
        verify_object(v["kind"], b64(v["wire_b64"]), bundle, v.get("verify") or {})
    assert error_class_of(info.value) == v["expected_error_class"], f"{v['mutation']}: {info.value!r}"


def test_object_negatives_cover_every_kind():
    kinds = {v["kind"] for v in NEGATIVES["vectors"]}
    assert kinds == {"delegation_certificate", "proof_bundle", "revocation_list", "revocation_push",
                     "key_rotation_statement", "witness_entry", "transaction_receipt", "verification_receipt",
                     "receipt_bundle_binding"}


# ---------------------------------------------------------------------------
# verifier-ordering.json

ORDERING = load("verifier-ordering.json")


def _evidence(e: dict) -> sv2.StatusEvidenceEntryV2:
    return sv2.StatusEvidenceEntryV2(e["issuer_id"], e["status_key_id"], e["sequence"], e["object_type_code"], e["digest"])


class ScriptedClaimStore:
    """Single-claim in-memory test double; not a production store."""

    def __init__(self, mode, now, counts):
        self.mode, self.now, self.counts, self.final_body = mode, now, counts, None

    def claim_v2(self, claim):
        self.counts["claim"] += 1
        if self.mode == "create":
            return ver.V2ClaimResult(ver.V2_CLAIM_CREATED, self.now, bytes([7]) * 32)
        if self.mode == "proof_conflict":
            raise ClaimProofConflictError()
        if self.mode == "in_progress":
            return ver.V2ClaimResult(ver.V2_CLAIM_IN_PROGRESS, self.now)
        if self.mode == "terminal_replay":
            return ver.V2ClaimResult(ver.V2_CLAIM_TERMINAL_REPLAY, self.now)
        raise RuntimeError("scripted claim store unavailable")

    def finalize_v2_claim(self, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until):
        self.counts["finalize"] += 1
        self.final_body = bytes(receipt_body)
        return True

    def recover_interrupted_v2_claim(self, claim_id, terminal_result, receipt_body):
        raise RuntimeError("not used by conformance vectors")


class ScriptedRateStore:
    def __init__(self, mode, counts):
        self.mode, self.counts, self.batch = mode, counts, None

    def reserve_v2_rate_batch(self, claim_id, owner_token, bundle_hash, batch):
        self.counts["rate"] += 1
        self.batch = list(batch)
        if self.mode == "reserve":
            return
        if self.mode == "exceeded":
            raise RateLimitExceededError()
        raise RuntimeError("scripted rate store unavailable")


@pytest.mark.parametrize("v", ORDERING["vectors"], ids=lambda v: v["name"])
def test_verifier_ordering(v):
    counts = dict.fromkeys(("receiver_binding", "claim", "trust", "status", "audience", "rate", "finalize"), 0)
    req = ver.V2VerifyRequest(
        bundle=b64(ORDERING["bundles_b64"][v["bundle"]]), required_scope=v["required_scope"],
        verifier_namespace=v["configured_namespace"], replay_epoch=v["configured_replay_epoch"], now=v["now"],
        max_challenge_age_seconds=v["max_challenge_age_seconds"], future_skew_seconds=v["future_skew_seconds"],
    )
    e = v.get("expected_challenge")
    if e is not None:
        exp = ver.ExpectedChallengeV2(b64(e["value_b64"]), e["issued_at"], e["expires_at"], e["verifier_namespace"],
                                      e["replay_epoch"], e["verifier_id"])
        if e.get("expected_agent_id") is not None:
            exp.expected_agent_id = e["expected_agent_id"]
            exp.expected_agent_public_key = pubkey(e["expected_agent_public_key"]) if e.get("expected_agent_public_key") else None
        if e.get("expected_receiver_id") is not None:
            exp.expected_receiver_id = e["expected_receiver_id"]
        if e.get("expected_session_context_b64") is not None:
            exp.expected_session_context = b64(e["expected_session_context_b64"])
        req.expected = exp
    p = v.get("context_policy")
    if p is not None:
        expected_ctx = b64(p["expected_session_context_b64"]) if p.get("expected_session_context_b64") is not None else None
        req.context_policy = new_v2_context_policy(p["profile"], p["require_bound"], p["required_fields"], expected_ctx)
        assert req.context_policy.digest == p["digest"]
    c = v.get("request_context")
    if c is not None:
        req.context = VerifierContext(has_resource=c.get("has_resource", False),
                                      requested_resource_id=c.get("requested_resource_id", ""),
                                      requested_path=c.get("requested_path", ""))
    roles = v["status_roles"]
    req.status_roles = sv2.V2StatusRoleBindings(dict(roles.get("status_key_issuers") or {}),
                                                dict(roles.get("current_status_key_ids") or {}),
                                                set(roles.get("reserved_key_ids") or []))
    store = ScriptedClaimStore(v["claim_store"], v["now"], counts)

    def trust(chain):
        counts["trust"] += 1
        t = v.get("trust")
        if t is None or not t["available"]:
            return ver.V2TrustResolution()
        return ver.V2TrustResolution(True, t["root_key_id"], pubkey(t["root_public_key"]))

    def status(issuer_id, cert_id):
        counts["status"] += 1
        r = (v.get("status") or {}).get(f"{issuer_id}/{cert_id}")
        if r is None:
            return sv2.RevocationStatusResultV2("indeterminate", "unavailable", [])
        return sv2.RevocationStatusResultV2(r["status"], r.get("reason", ""), [_evidence(x) for x in r.get("evidence") or []],
                                            r.get("fresh_until", 0))

    def audience(deferred, receiver_id):
        counts["audience"] += 1
        return [V2AudienceMembership(m["delegation_index"], m["constraint_index"], m["receiver_id"],
                                     list(m["trust_domain_ids"] or []), m["issued_at"], m["expires_at"], m["evidence_digest"])
                for m in v.get("audience_memberships") or []]

    cb = ver.V2VerifyCallbacks(claim_store=store, trust=trust, status=status, audience=audience)
    hook = v.get("receiver_binding_hook")
    if hook in ("accept", "reject"):
        def receiver_binding(bundle, expected):
            counts["receiver_binding"] += 1
            if hook == "reject":
                raise RuntimeError("application receiver binding rejected")
        cb.receiver_binding = receiver_binding
    else:
        assert hook in (None, "", "absent"), f"unknown receiver_binding_hook {hook!r}"
    rate = None
    if v["rate"] != "absent":
        rate = ScriptedRateStore(v["rate"], counts)
        cb.rate = rate

    outcome = ver.verify_proof_bundle_v2(req, cb)
    want = v["expected"]
    assert outcome.stage == want["stage"], (outcome.error_class, outcome.error, outcome.decision, outcome.reason)
    assert outcome.error_class == want.get("error_class", ""), outcome.error
    if want.get("disposition"):
        assert outcome.disposition == want["disposition"]
    assert counts == want["callback_counts"]
    if want["stage"] != "terminal":
        return
    r = outcome.receipt
    got = (outcome.decision, outcome.reason, outcome.identity_status, r.trust_assessment, r.status_assessment, r.context_assessment)
    exp = (want["decision"], want["decision_reason"], want["identity_status"], want["trust_assessment"],
           want["status_assessment"], want["context_assessment"])
    assert got == exp
    assert r.context_policy_digest == want.get("context_policy_digest")
    assert outcome.receipt_body == b64(want["receipt_body_b64"]) == store.final_body
    assert outcome.allow_valid_until == want.get("allow_valid_until", 0)
    if want.get("granted_scope") is not None:
        assert r.granted_scope == want["granted_scope"]
    if want.get("status_evidence") is not None:
        assert r.status_evidence == [_evidence(x) for x in want["status_evidence"]]
    if want.get("rate_batch"):
        assert rate is not None and [(b.issuer_id, b.cert_id, b.window_s, b.limit) for b in rate.batch] == [
            (b["issuer_id"], b["cert_id"], b["window_s"], b["limit"]) for b in want["rate_batch"]]


# ---------------------------------------------------------------------------
# status-sequences.json

STATUS = load("status-sequences.json")


def _policy(d: dict) -> sv2.RevocationStatusPolicyV2:
    return sv2.RevocationStatusPolicyV2(d["max_list_lifetime_seconds"], d["max_status_age_seconds"], d["clock_skew_seconds"])


@pytest.mark.parametrize("sc", STATUS["scenarios"], ids=lambda s: s["name"])
def test_status_sequence(sc):
    state = sv2.RevocationStatusStateV2()
    for i, step in enumerate(sc["steps"]):
        key = PUB.get(step.get("status_key", ""))
        policy = _policy(step["policy"]) if step.get("policy") else _policy(sc["policy"])
        epoch, now, op = step.get("status_key_epoch", 0), step.get("now", 0), step["op"]
        where = f"step {i} {op} {step.get('label', '')}"
        if op == "query":
            r = sv2.revocation_status_for_cert_v2(state, sc["issuer_id"], step["cert_id"], epoch, key, policy, now)
            w = step["expect_result"]
            assert (r.status, r.reason) == (w["status"], w.get("reason", "")), where
            assert r.evidence == [_evidence(e) for e in w.get("evidence") or []], where
            continue
        err, nxt = None, state
        try:
            if op == "apply_list":
                nxt = sv2.apply_revocation_list_v2(state, pv2.decode_revocation_list_v2(b64(step["wire_b64"])),
                                                   sc["issuer_id"], epoch, key, policy, now)
            elif op == "apply_push":
                nxt = sv2.apply_revocation_push_v2(state, pv2.decode_revocation_push_v2(b64(step["wire_b64"])),
                                                   sc["issuer_id"], epoch, key, policy, now)
            elif op == "transition_epoch":
                nxt = sv2.transition_revocation_status_epoch_v2(state, sc["issuer_id"], epoch, key)
            else:
                pytest.fail(f"unknown status op {op!r}")
        except Exception as exc:  # noqa: BLE001
            err = exc
        if step.get("expect_error_class"):
            assert error_class_of(err) == step["expect_error_class"], (where, err)
            continue
        assert err is None, (where, err)
        state = nxt
        w = step.get("expect_state")
        if w:
            actual = {
                "has_floor": state.has_floor, "floor": state.floor, "max_observed_sequence": state.max_observed_sequence,
                "fork_sequence": state.fork_sequence, "reconciliation_required": state.reconciliation_required,
                "future_dated_object_observed": state.future_dated_object_observed,
                "accepted_set": list(state.accepted_cert_ids), "deny_union": list(state.deny_union_cert_ids),
            }
            for name, value in w.items():
                assert name in actual, f"unknown expect_state field {name}"
                if value is not None:
                    assert actual[name] == value, (where, name)


# ---------------------------------------------------------------------------
# log-sequences.json

LOGS = load("log-sequences.json")


def test_log_sequences_have_both_logs():
    assert sorted(sc["kind"] for sc in LOGS["scenarios"]) == ["verification_receipt", "witness_entry"]


@pytest.mark.parametrize("sc", LOGS["scenarios"], ids=lambda s: s["name"])
def test_log_sequence(sc):
    def genesis(log_id):
        return wv2.WitnessV2Head(log_id=log_id, sequence=0, head_hash=bytes(48), accepted_digests={})

    head = genesis(sc["initial_log_id"])
    for i, step in enumerate(sc["steps"]):
        if step["op"] == "recover":
            head = genesis(step["log_id"])
            continue
        wire = b64(step["wire_b64"])
        err = result = None
        try:
            if sc["kind"] == "witness_entry":
                obj = wv2.decode_witness_entry_v2(wire)
                result = wv2.verify_witness_entry_v2(obj, head, PUB[step["key"]])
                digest = wv2.witness_entry_v2_digest(obj)
            elif sc["kind"] == "verification_receipt":
                obj = vrv2.decode_verification_receipt_v2(wire)
                receipt_head = vrv2.ReceiptV2Head(head.log_id, sc["verifier_id"], head.sequence, head.head_hash,
                                                  head.accepted_digests, head.frozen)
                result = vrv2.verify_verification_receipt_v2(obj, PUB[step["key"]], receipt_head)
                digest = vrv2.verification_receipt_v2_digest(obj)
            else:
                pytest.fail(f"unknown log kind {sc['kind']!r}")
        except Exception as exc:  # noqa: BLE001
            err = exc
        if err is not None:
            got = error_class_of(err)
        else:
            got = {wv2.WitnessEntryV2Result.APPENDED: "appended", wv2.WitnessEntryV2Result.REPLAY: "replay"}[result]
        assert got == step["expect"], (i, step.get("label"), err)
        if got == "appended":
            head.sequence = obj.sequence
            head.head_hash = digest
            head.accepted_digests[obj.sequence] = digest
        elif got == "log_fork":
            head.frozen = True


# ---------------------------------------------------------------------------
# rotation-sequences.json

ROTATION = load("rotation-sequences.json")


@pytest.mark.parametrize("sc", ROTATION["scenarios"], ids=lambda s: s["name"])
def test_rotation_sequence(sc):
    journal = kr.new_key_rotation_v2_journal(sc["authority_id"], sc["recovery_epoch"], sc["role"], PUB[sc["genesis_key"]])
    for i, step in enumerate(sc["steps"]):
        err = None
        if step["op"] == "recover":
            try:
                journal = kr.recover_key_rotation_v2(journal, step["new_recovery_epoch"], PUB[step["new_genesis_key"]])
                got = "recovered"
            except Exception as exc:  # noqa: BLE001
                err, got = exc, error_class_of(exc)
        elif step["op"] == "accept":
            stmt = kr.decode_key_rotation_statement_v2(b64(step["wire_b64"]))
            try:
                journal, result = kr.accept_key_rotation_statement_v2(stmt, journal, step["now"], sc["future_skew_seconds"])
                got = {wv2.WitnessEntryV2Result.APPENDED: "appended", wv2.WitnessEntryV2Result.REPLAY: "replay"}[result]
            except Exception as exc:  # noqa: BLE001
                err, got = exc, error_class_of(exc)
                if hasattr(exc, "journal"):
                    journal = exc.journal  # the frozen journal the caller must persist
        else:
            pytest.fail(f"unknown rotation op {step['op']!r}")
        assert got == step["expect"], (i, step.get("label"), err)
        st = journal.state
        assert st.sequence == step["expect_sequence"], (i, step.get("label"))
        assert st.current_key.ml_dsa_65 == PUB[step["expect_current_key"]].ml_dsa_65, (i, step.get("label"))
        assert st.recovery_epoch == step["expect_recovery_epoch"], (i, step.get("label"))
        assert journal.frozen == step["expect_frozen"], (i, step.get("label"))


# ---------------------------------------------------------------------------
# Hand-maintained vectors


def test_delegation_signature_vector():
    v = load("delegation-signature.json")
    assert v["object_type_code"] == 1
    signable, message = b64(v["signable_bytes"]), b64(v["message"])
    context = b64(v["mldsa_context"])
    pub = pubkey(v["issuer_public_key"])
    assert signing_message_v2(1, signable) == message and mldsa_context_v2(1) == context
    assert key_id_v2(pub) == v["key_id_v2"]
    assert _mldsa65.compute_tr(pub.ml_dsa_65) == b64(v["mldsa_tr"])
    assert _mldsa65.compute_mu(pub.ml_dsa_65, message, context) == b64(v["mldsa_mu"])
    signature = sig(v["signature"])
    verify_v2_statement(1, signable, signature, pub)
    assert not _mldsa65.verify(pub.ml_dsa_65, message, b64(v["alternate_mldsa_context"]), signature.ml_dsa_65)
    mask = v["negative_mutations"]["xor_mask"]
    targets = v["negative_mutations"]["targets"]
    assert targets, "no negative mutations"
    for target in targets:
        s, k, data = HybridSignature(signature.ed25519, signature.ml_dsa_65), HybridPublicKey(pub.ed25519, pub.ml_dsa_65), signable
        flip = lambda b: bytes([b[0] ^ mask]) + b[1:]  # noqa: E731
        if target == "signable_bytes":
            data = flip(data)
        elif target == "signature.ed25519":
            s.ed25519 = flip(s.ed25519)
        elif target == "signature.ml_dsa_65":
            s.ml_dsa_65 = flip(s.ml_dsa_65)
        elif target == "issuer_public_key.ed25519":
            k.ed25519 = flip(k.ed25519)
        elif target == "issuer_public_key.ml_dsa_65":
            k.ml_dsa_65 = flip(k.ml_dsa_65)
        else:
            pytest.fail(f"unknown mutation target {target!r}")
        with pytest.raises(Exception) as info:
            verify_v2_statement(1, data, s, k)
        assert error_class_of(info.value) == "invalid_signature", target


@requires_native
def test_delegation_signature_vector_native_resign():
    v = load("delegation-signature.json")
    derived, priv = keypair_from_seeds_v2(b64(v["issuer_seeds"]["ed25519"]), b64(v["issuer_seeds"]["ml_dsa_65"]))
    assert derived == pubkey(v["issuer_public_key"])
    with deterministic_test_vector_signing():
        assert _sign_v2_statement(1, b64(v["signable_bytes"]), priv) == sig(v["signature"])


def test_derive_external_mu_script():
    script = V2_DIR / "derive-external-mu.py"
    out = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, check=True).stdout
    v = load("delegation-signature.json")
    assert f"mldsa_tr: {v['mldsa_tr']}" in out and f"mldsa_mu: {v['mldsa_mu']}" in out


def test_operation_session_context_vector():
    v = load("operation-session-context.json")
    policy = v["context_policy"]
    built = new_v2_context_policy(policy["profile"], policy["require_bound"], policy["required_fields"], bytes(32))
    assert policy["version"] == 1 and built.digest == v["context_policy_digest"]
    i = v["input"]
    assert session_context_v2_hash(i["verifier_id"], i["workspace_id"], i["agent_id"], i["session_id"],
                                   i["invocation_id"], bytes.fromhex(i["request_hash_hex"])).hex() == v["expected_session_context_hex"]

    def op_hash(o, digest):
        return operation_context_v2_hash(o["required_scope"], o["operation"], o["resource_id"], o["requested_path"], digest)

    o = v["operation_input"]
    assert op_hash(o, bytes.fromhex(o["payload_digest_hex"])).hex() == v["expected_request_hash_hex"]
    e = v["empty_payload_operation_input"]
    assert e["payload_digest_hex"] is None
    empty = op_hash(e, None)
    assert empty.hex() == v["expected_empty_request_hash_hex"]
    assert session_context_v2_hash(i["verifier_id"], i["workspace_id"], i["agent_id"], i["session_id"],
                                   i["invocation_id"], empty).hex() == v["expected_empty_session_context_hex"]
    api = v["verify_api_operation_input"]
    assert op_hash(api, decode_payload_digest(api["payload_digest"])).hex() == v["expected_verify_api_request_hash_hex"]
    for scope in v["invalid_required_scopes"]:
        with pytest.raises(ValueError):
            operation_context_v2_hash(scope, "op", "res", "/p")
        with pytest.raises(ValueError):
            pv2.validate_required_scope_v2(scope)
    for case in v["verify_api_payload_digest_decode_cases"]:
        if case["valid"]:
            decoded = decode_payload_digest(case["encoded"])
            assert (decoded or b"").hex() == case["expected_hex"], case["name"]
        else:
            with pytest.raises((ValueError, TypeError)):
                decode_payload_digest(case["encoded"])


def test_challenge_claim_vector():
    v = load("challenge-claim.json")
    challenge = bytes.fromhex(v["challenge_hex"])
    assert challenge_claim_digest_v2(challenge).hex() == v["expected_challenge_claim_digest_hex"]
    c = v["claim_id_input"]
    assert protocol_claim_id_v2(c["verifier_namespace"], c["replay_epoch"], challenge) == v["expected_claim_id"]
    assert v["additional_claim_id_cases"]
    for case in v["additional_claim_id_cases"]:
        assert protocol_claim_id_v2(case["verifier_namespace"], case["replay_epoch"], challenge) == case["expected_claim_id"]


ROTATION_SIGNATURE = load("key-rotation-signature.json")


@pytest.mark.parametrize("v", [ROTATION_SIGNATURE, ROTATION_SIGNATURE["continuation"]], ids=["genesis", "continuation"])
def test_key_rotation_signature_vector(v):
    wire = b64(v["wire"])
    stmt = kr.decode_key_rotation_statement_v2(wire)
    assert kr.encode_key_rotation_statement_v2(stmt) == wire
    assert (stmt.version, stmt.authority_id, stmt.recovery_epoch, stmt.role, stmt.sequence, stmt.issued_at,
            stmt.not_before, stmt.old_key_id, stmt.new_key_id) == (
        int(v["version"]), v["authority_id"], int(v["recovery_epoch"]), v["role"], int(v["sequence"]),
        int(v["issued_at"]), int(v["not_before"]), v["old_key_id"], v["new_key_id"])
    assert int(v["object_type_code"]) == 4
    assert stmt.previous_statement_hash == b64(v["previous_statement_hash"])
    assert stmt.old_key == pubkey(v["old_key"]) and stmt.new_key == pubkey(v["new_key"])
    signable = kr.key_rotation_signable_bytes_v2(stmt)
    assert signable == b64(v["signable_bytes"])
    assert kr.key_rotation_statement_v2_digest(stmt).hex() == v["statement_body_digest"]
    assert mldsa_context_v2(4).decode() == v["old_mldsa_context"] and mldsa_context_v2(9).decode() == v["new_mldsa_context"]
    assert stmt.old_signature == sig(v["old_signature"]) and stmt.new_signature == sig(v["new_signature"])
    old_pub, new_pub = stmt.old_key, stmt.new_key
    verify_v2_statement(4, signable, stmt.old_signature, old_pub)
    verify_v2_statement(9, signable, stmt.new_signature, new_pub)
    for code, signature, key in ((9, stmt.old_signature, old_pub), (4, stmt.new_signature, new_pub)):
        with pytest.raises(Exception) as info:
            verify_v2_statement(code, signable, signature, key)
        assert error_class_of(info.value) == "invalid_signature"


@requires_native
@pytest.mark.parametrize("v", [ROTATION_SIGNATURE, ROTATION_SIGNATURE["continuation"]], ids=["genesis", "continuation"])
def test_key_rotation_signature_vector_native_resign(v):
    wire = b64(v["wire"])
    stmt = kr.decode_key_rotation_statement_v2(wire)
    old_pub, old_priv = keypair_from_seeds_v2(bytes.fromhex(v["old_key_seeds"]["ed25519"]), bytes.fromhex(v["old_key_seeds"]["ml_dsa_65"]))
    new_pub, new_priv = keypair_from_seeds_v2(bytes.fromhex(v["new_key_seeds"]["ed25519"]), bytes.fromhex(v["new_key_seeds"]["ml_dsa_65"]))
    assert old_pub == stmt.old_key and new_pub == stmt.new_key
    with deterministic_test_vector_signing():
        signed = kr.sign_key_rotation_statement_v2(stmt, old_priv, new_priv)
    assert kr.encode_key_rotation_statement_v2(signed) == wire
