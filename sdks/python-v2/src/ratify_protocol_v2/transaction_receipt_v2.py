"""Protocol v2 transaction receipts (mirrors Go transaction_receipt_v2.go).

A receipt binds canonical application terms to one signed v2 proof per party.
Each embedded proof still needs independent trust and status evaluation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256, sha384
from typing import Any, Optional

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, RawJSON, canonical
from .errors_v2 import V2Error, V2ErrorClass
from .operation_context_v2 import session_context_v2_hash
from .protocol_v2 import (
    ProofBundleV2,
    _run,
    bundle_hash_v2,
    check_keys,
    decode_proof_bundle_v2,
    decode_public_key,
    decode_signature,
    encode_proof_bundle_v2,
    get_bytes,
    get_int,
    get_str,
    key_dict,
    require_fields,
    valid_v2_id,
    verify_proof_bundle_v2_signatures,
)
from .clock_bounds_v2 import valid_v2_timestamp
from .context_v2 import Context, background
from .limits_v2 import (
    MAX_JSON_NESTING_DEPTH,
    MAX_TRANSACTION_PARTIES,
    MAX_TRANSACTION_RECEIPT_BYTES,
    MAX_TRANSACTION_RECEIPT_BYTES_V2,
    check_v2_wire_size,
)
from .scope import validate_required_scope_v2
from .signing_v2 import (
    TRANSACTION_PARTY_STATEMENT,
    SignerV2,
    V2SigningError,
    _as_signer,
    equal_public_keys,
    key_id_v2,
    _sign_v2_statement_with_signer,
    signer_public_key_v2,
    verify_v2_statement,
)
from .types import HybridPrivateKey, HybridPublicKey, HybridSignature
_WORKSPACE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass
class TransactionReceiptPartyV2:
    party_id: str
    role: str
    agent_id: str
    agent_pub_key: HybridPublicKey
    verifier_id: str
    workspace_id: str
    session_id: str
    invocation_id: str
    required_scope: str
    proof_bundle_hash: str
    proof_bundle: Optional[ProofBundleV2]


@dataclass
class TransactionReceiptSignatureV2:
    party_id: str
    signature: HybridSignature


@dataclass
class TransactionReceiptV2:
    version: int
    transaction_id: str
    created_at: int
    terms_schema_uri: str
    terms_canonical_json: bytes
    parties: list[TransactionReceiptPartyV2]
    party_signatures: list[TransactionReceiptSignatureV2] = field(default_factory=list)


_TOP_FIELDS = ("version", "transaction_id", "created_at", "terms_schema_uri", "terms_canonical_json",
               "parties", "party_signatures")
_PARTY_FIELDS = ("agent_id", "agent_pub_key", "invocation_id", "party_id", "proof_bundle", "proof_bundle_hash",
                 "required_scope", "role", "session_id", "verifier_id", "workspace_id")


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def transaction_context_hash_v2(receipt: TransactionReceiptV2) -> bytes:
    preimage = (
        b"ratify/transaction-context/v2" + _lp(receipt.transaction_id.encode("utf-8"))
        + _lp(receipt.terms_schema_uri.encode("utf-8")) + sha384(bytes(receipt.terms_canonical_json)).digest()
    )
    return sha256(preimage).digest()


def transaction_party_request_hash_v2(transaction_hash: bytes, required_scope: str) -> bytes:
    return sha256(
        b"ratify/transaction-party-request/v2" + _lp(transaction_hash) + _lp(required_scope.encode("utf-8"))
    ).digest()


def _valid_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _depth_ok(value: Any, depth: int) -> None:
    if isinstance(value, (dict, list)):
        if depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError("transaction terms nesting exceeds MAX_JSON_NESTING_DEPTH")
        for item in value.values() if isinstance(value, dict) else value:
            _depth_ok(item, depth + 1)


def _ratify_json_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, float):
        raise ValueError("non-integer JSON numbers are not permitted")
    if isinstance(value, int):
        return  # range and -0 already rejected by the strict parser
    if isinstance(value, list):
        for item in value:
            _ratify_json_value(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _ratify_json_value(item)
        return
    raise ValueError("unsupported Ratify JSON value")


def validate_canonical_transaction_terms_v2(data: bytes) -> None:
    value = _v2json.parse(data)
    if not isinstance(value, dict):
        raise ValueError("terms must be a JSON object")
    _depth_ok(value, 1)
    _ratify_json_value(value)
    if canonical(value) != bytes(data):
        raise ValueError("terms bytes differ from RatifyCanonicalJSON")


def transaction_receipt_v2_sign_bytes(receipt: TransactionReceiptV2) -> bytes:
    """The exact object-type 0x0007 bytes each party signs."""
    if receipt is None or not receipt.parties:
        raise ValueError("v2 transaction receipt and parties are required")
    if len(receipt.parties) > MAX_TRANSACTION_PARTIES:
        raise ValueError("v2 transaction receipt exceeds MAX_TRANSACTION_PARTIES")
    parties = sorted(
        (
            {
                "agent_id": p.agent_id, "agent_pub_key": key_dict(p.agent_pub_key), "invocation_id": p.invocation_id,
                "party_id": p.party_id, "proof_bundle_hash": p.proof_bundle_hash, "required_scope": p.required_scope,
                "role": p.role, "session_id": p.session_id, "verifier_id": p.verifier_id, "workspace_id": p.workspace_id,
            }
            for p in receipt.parties
        ),
        key=lambda d: d["party_id"].encode("utf-8"),
    )
    return canonical({
        "created_at": receipt.created_at, "parties": parties,
        "terms_canonical_json": bytes(receipt.terms_canonical_json),
        "terms_schema_uri": receipt.terms_schema_uri, "transaction_id": receipt.transaction_id,
        "version": receipt.version,
    })


def validate_transaction_receipt_v2(receipt: TransactionReceiptV2, require_signatures: bool) -> None:
    if (
        not isinstance(receipt, TransactionReceiptV2) or receipt.version != 2 or receipt.transaction_id == ""
        or not valid_v2_timestamp(receipt.created_at)
        or receipt.terms_schema_uri == "" or not isinstance(receipt.terms_canonical_json, (bytes, bytearray))
        or not receipt.terms_canonical_json or not isinstance(receipt.parties, list) or not receipt.parties
    ):
        raise ValueError("wire v2: transaction receipt header or terms are invalid")
    if len(receipt.parties) > MAX_TRANSACTION_PARTIES:
        raise ValueError("wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES")
    try:
        validate_canonical_transaction_terms_v2(receipt.terms_canonical_json)
    except ValueError as exc:
        raise ValueError(f"wire v2: transaction terms are not canonical Ratify JSON: {exc}") from exc
    for name in ("transaction_id", "terms_schema_uri"):
        if not _valid_text(getattr(receipt, name)):
            raise ValueError(f"wire v2: {name} is not valid UTF-8")
    seen_parties: set[str] = set()
    seen_agents: set[str] = set()
    transaction_hash = transaction_context_hash_v2(receipt)
    for i, party in enumerate(receipt.parties):
        if not isinstance(party, TransactionReceiptPartyV2):
            raise ValueError(f"wire v2: transaction party {i} must be a TransactionReceiptPartyV2")
        for name in ("party_id", "role", "session_id", "invocation_id", "verifier_id", "workspace_id",
                     "agent_id", "required_scope", "proof_bundle_hash"):
            if not _valid_text(getattr(party, name)):
                raise ValueError(f"wire v2: transaction party {i} {name} is not valid UTF-8")
        if (
            party.party_id == "" or party.role == "" or party.session_id == "" or party.invocation_id == ""
            or not valid_v2_id(party.verifier_id) or not _WORKSPACE.fullmatch(party.workspace_id)
            or not valid_v2_id(party.agent_id)
        ):
            raise ValueError(f"wire v2: transaction party {i} has invalid identity or context fields")
        if i > 0 and receipt.parties[i - 1].party_id.encode("utf-8") >= party.party_id.encode("utf-8"):
            raise ValueError("wire v2: transaction parties must be sorted by unique party_id")
        if party.party_id in seen_parties:
            raise ValueError(f"wire v2: duplicate transaction party {party.party_id!r}")
        seen_parties.add(party.party_id)
        if party.agent_id in seen_agents:
            raise ValueError(f"wire v2: agent {party.agent_id!r} cannot represent multiple transaction parties")
        seen_agents.add(party.agent_id)
        validate_required_scope_v2(party.required_scope)
        if party.proof_bundle is None:
            raise ValueError(f"wire v2: party {party.party_id!r} proof_bundle is required")
        try:
            key_id = key_id_v2(party.agent_pub_key)
        except ValueError:
            key_id = None
        if key_id != party.agent_id:
            raise V2Error(V2ErrorClass.KEY_ID_MISMATCH,
                          f"wire v2: party {party.party_id!r} agent ID does not match its complete public key")
        bundle = party.proof_bundle
        try:
            bundle_hash = bundle_hash_v2(bundle)
        except (ValueError, V2Error):
            bundle_hash = None
        if bundle_hash != party.proof_bundle_hash:
            raise V2Error(V2ErrorClass.BUNDLE_HASH_MISMATCH,
                          f"wire v2: party {party.party_id!r} proof_bundle_hash does not match its bundle")
        verify_proof_bundle_v2_signatures(bundle)
        if (
            bundle.agent_id != party.agent_id or not equal_public_keys(bundle.agent_pub_key, party.agent_pub_key)
            or bundle.verifier_id != party.verifier_id or not bundle.delegations
            or bundle.delegations[0].subject_id != party.agent_id
        ):
            raise V2Error(V2ErrorClass.TRANSACTION_PARTY_MISMATCH,
                          f"wire v2: party {party.party_id!r} proof bundle identity does not match its signed party")

        try:
            expected = session_context_v2_hash(
                party.verifier_id, party.workspace_id, party.agent_id, party.session_id, party.invocation_id,
                transaction_party_request_hash_v2(transaction_hash, party.required_scope),
            )
        except (ValueError, TypeError):
            expected = None
        if expected is None or bundle.session_context is None or bytes(bundle.session_context) != expected:
            raise V2Error(V2ErrorClass.TRANSACTION_CONTEXT_MISMATCH,
                          f"wire v2: party {party.party_id!r} proof bundle session context does not bind this transaction and scope")
    if require_signatures:
        if len(receipt.party_signatures) != len(receipt.parties):
            raise V2Error(V2ErrorClass.TRANSACTION_SIGNATURE_SET_INVALID,
                          "wire v2: transaction receipt must have one signature per party")
        seen: set[str] = set()
        for item in receipt.party_signatures:
            if item.party_id not in seen_parties or item.party_id in seen:
                raise V2Error(V2ErrorClass.TRANSACTION_SIGNATURE_SET_INVALID,
                              f"wire v2: unknown or duplicate transaction party signature {item.party_id!r}")
            seen.add(item.party_id)
    transaction_receipt_v2_sign_bytes(receipt)


def verify_transaction_receipt_v2_signatures(receipt: TransactionReceiptV2) -> None:
    """Typed party signatures, bundle hashes, party bindings, and the
    transaction-derived session contexts. Trust and status are not resolved."""
    _run(V2ErrorClass.MALFORMED, lambda: validate_transaction_receipt_v2(receipt, True))
    signable = _run(V2ErrorClass.MALFORMED, lambda: transaction_receipt_v2_sign_bytes(receipt))
    signatures: dict[str, HybridSignature] = {}
    for item in receipt.party_signatures:
        if item.party_id in signatures:
            raise V2Error(V2ErrorClass.TRANSACTION_SIGNATURE_SET_INVALID,
                          f"v2 transaction receipt has duplicate signature for party {item.party_id!r}")
        signatures[item.party_id] = item.signature
    if len(signatures) != len(receipt.parties):
        raise V2Error(V2ErrorClass.TRANSACTION_SIGNATURE_SET_INVALID,
                      "v2 transaction receipt must contain exactly one signature per party")
    for party in receipt.parties:
        signature = signatures.get(party.party_id)
        if signature is None:
            raise V2Error(V2ErrorClass.TRANSACTION_SIGNATURE_SET_INVALID,
                          f"v2 transaction receipt is missing signature for party {party.party_id!r}")
        verify_v2_statement(TRANSACTION_PARTY_STATEMENT, signable, signature, party.agent_pub_key)


def sign_transaction_receipt_party_v2(receipt: TransactionReceiptV2, party_id: str,
                                      key: HybridPrivateKey) -> TransactionReceiptSignatureV2:
    """Go ``SignTransactionReceiptPartyV2``: one party's signature over the
    shared transaction statement (code 0x0007)."""
    return sign_transaction_receipt_party_v2_with_signer(background(), receipt, party_id, _as_signer(key))


def sign_transaction_receipt_party_v2_with_signer(ctx: Context, receipt: TransactionReceiptV2, party_id: str,
                                                  signer: SignerV2) -> TransactionReceiptSignatureV2:
    """Go ``SignTransactionReceiptPartyV2WithSigner``: the signer's complete
    key must equal the party agent key."""
    if not isinstance(receipt, TransactionReceiptV2):
        raise V2SigningError("transaction receipt is required")
    party = next((p for p in receipt.parties if p.party_id == party_id), None)
    if party is None:
        raise V2SigningError(f"party {party_id!r} is not listed in the transaction receipt")
    party_public = signer_public_key_v2(signer)
    if not equal_public_keys(party_public, party.agent_pub_key):
        raise V2SigningError(f"signing key does not match party {party_id!r} agent public key")
    try:
        validate_transaction_receipt_v2(receipt, False)
    except (ValueError, V2Error) as exc:
        raise V2SigningError(f"cannot sign invalid transaction receipt: {exc}") from exc
    signable = transaction_receipt_v2_sign_bytes(receipt)
    signature = _sign_v2_statement_with_signer(ctx, TRANSACTION_PARTY_STATEMENT, signable, signer, party_public)
    return TransactionReceiptSignatureV2(party_id, signature)


def _encode_canonical(receipt: TransactionReceiptV2) -> bytes:
    parties = []
    for p in receipt.parties:
        parties.append({
            "agent_id": p.agent_id, "agent_pub_key": key_dict(p.agent_pub_key), "invocation_id": p.invocation_id,
            "party_id": p.party_id, "proof_bundle": RawJSON(encode_proof_bundle_v2(p.proof_bundle)),
            "proof_bundle_hash": p.proof_bundle_hash, "required_scope": p.required_scope, "role": p.role,
            "session_id": p.session_id, "verifier_id": p.verifier_id, "workspace_id": p.workspace_id,
        })
    signatures = sorted(receipt.party_signatures, key=lambda s: s.party_id.encode("utf-8"))
    encoded = canonical({
        "created_at": receipt.created_at, "parties": parties,
        "party_signatures": [{"party_id": s.party_id, "signature": key_dict(s.signature)} for s in signatures],
        "terms_canonical_json": bytes(receipt.terms_canonical_json), "terms_schema_uri": receipt.terms_schema_uri,
        "transaction_id": receipt.transaction_id, "version": receipt.version,
    })
    if len(encoded) > MAX_TRANSACTION_RECEIPT_BYTES:
        raise ValueError("wire v2: transaction receipt exceeds MAX_TRANSACTION_RECEIPT_BYTES")
    return encoded


def encode_transaction_receipt_v2(receipt: TransactionReceiptV2) -> bytes:
    verify_transaction_receipt_v2_signatures(receipt)
    return _encode_canonical(receipt)


def decode_transaction_receipt_v2(data: bytes) -> TransactionReceiptV2:
    """Strict decode that also verifies party signatures and embedded bundle
    identity and context bindings."""

    def run() -> TransactionReceiptV2:
        check_v2_wire_size(data, "transaction receipt", "MAX_TRANSACTION_RECEIPT_BYTES_V2",
                           MAX_TRANSACTION_RECEIPT_BYTES_V2)
        obj = _v2json.check_wire_json(data, ("terms_canonical_json",))
        require_fields(obj, _TOP_FIELDS)
        raw_parties = obj.get("parties")
        if not isinstance(raw_parties, list):
            raise ValueError("wire v2: parties must be an array")
        if len(raw_parties) > MAX_TRANSACTION_PARTIES:
            raise ValueError("wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES")
        check_keys(obj, _TOP_FIELDS, "transaction receipt")
        raw_signatures = obj.get("party_signatures")
        if not isinstance(raw_signatures, list):
            raise ValueError("wire v2: party_signatures must be an array")
        text = bytes(data).decode("utf-8")
        top_spans = _v2json.raw_member_spans(text)
        party_spans = _v2json.raw_array_spans(text, top_spans["parties"][0])
        party_values = []
        for raw_party, span in zip(raw_parties, party_spans):
            if not isinstance(raw_party, dict):
                raise ValueError("wire v2: transaction party must be an object")
            check_keys(raw_party, _PARTY_FIELDS, "transaction party")
            require_fields(raw_party, _PARTY_FIELDS)
            if not isinstance(raw_party["proof_bundle"], dict):
                raise ValueError("wire v2: party proof_bundle must be a JSON object")
            member = _v2json.raw_member_spans(text, span[0])["proof_bundle"]
            raw_bundle = text[member[0]:member[1]].encode("utf-8")
            party_values.append((dict(
                party_id=get_str(raw_party, "party_id"), role=get_str(raw_party, "role"),
                agent_id=get_str(raw_party, "agent_id"),
                agent_pub_key=decode_public_key(raw_party.get("agent_pub_key"), "agent_pub_key"),
                verifier_id=get_str(raw_party, "verifier_id"), workspace_id=get_str(raw_party, "workspace_id"),
                session_id=get_str(raw_party, "session_id"), invocation_id=get_str(raw_party, "invocation_id"),
                required_scope=get_str(raw_party, "required_scope"),
                proof_bundle_hash=get_str(raw_party, "proof_bundle_hash"),
            ), raw_bundle))
        signatures = []
        for raw_sig in raw_signatures:
            if not isinstance(raw_sig, dict):
                raise ValueError("wire v2: party signature must be an object")
            check_keys(raw_sig, ("party_id", "signature"), "party signature")
            require_fields(raw_sig, ("party_id", "signature"))
            signatures.append(TransactionReceiptSignatureV2(get_str(raw_sig, "party_id"),
                                                            decode_signature(raw_sig.get("signature"))))
        version = get_int(obj, "version")
        transaction_id = get_str(obj, "transaction_id")
        created_at = get_int(obj, "created_at")
        terms_schema_uri = get_str(obj, "terms_schema_uri")
        terms = get_bytes(obj, "terms_canonical_json") or b""
        parties = []
        for fields, raw_bundle in party_values:
            party_id = fields["party_id"]
            actual = "sha384:" + sha384(b"ratify-protocol-bundle-v2\x00" + raw_bundle).hexdigest()
            if fields["proof_bundle_hash"] != actual:
                raise V2Error(V2ErrorClass.BUNDLE_HASH_MISMATCH,
                              f"wire v2: party {party_id!r} proof_bundle_hash does not match its canonical bundle bytes")
            parties.append(TransactionReceiptPartyV2(proof_bundle=decode_proof_bundle_v2(raw_bundle), **fields))
        receipt = TransactionReceiptV2(
            version=version, transaction_id=transaction_id, created_at=created_at,
            terms_schema_uri=terms_schema_uri, terms_canonical_json=terms, parties=parties,
            party_signatures=signatures,
        )
        verify_transaction_receipt_v2_signatures(receipt)
        if _encode_canonical(receipt) != bytes(data):
            raise ValueError("wire v2: transaction receipt is not canonical JSON")
        return receipt

    return _run(V2ErrorClass.MALFORMED, run)
