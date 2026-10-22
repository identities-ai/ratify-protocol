"""Protocol v2 wire objects: delegation certificates, proof bundles, and
issuer status objects (Go protocol_v2_wire.go).

Decoders are strict and bounded: the per-object byte limit is checked before
parsing, then canonical-JSON acceptance, required and nullable members,
unknown-member rejection, and field validation. Field semantics follow Go
encoding/json: a JSON ``null`` in a nested member takes its zero value (the
top-level required-member check rejects null where the schema forbids it).
Every decode failure is classified (``malformed`` unless a later stage names a
more specific class).
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field, replace
from hashlib import sha384
from typing import Any, Callable, Optional

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .clock_bounds_v2 import V2_MAX_DELEGATION_LIFETIME_SECONDS, valid_v2_timestamp
from .constraints_v2 import (
    CONSTRAINT_RECEIVER_AUDIENCE,
    CONSTRAINT_RESOURCE_PATH,
    ConstraintV2,
    constraint_v2_from_fields,
)
from .context_v2 import Context, background
from .errors_v2 import V2Error, V2ErrorClass, classify
from .limits_v2 import (
    MAX_CONSTRAINTS_PER_CERT,
    MAX_DELEGATION_CERT_BYTES_V2,
    MAX_DELEGATION_CHAIN_DEPTH,
    MAX_IDENTIFIER_LENGTH_BYTES,
    MAX_PROOF_BUNDLE_BYTES_V2,
    MAX_REVOCATION_LIST_BYTES_V2,
    MAX_REVOCATION_LIST_REFS_V2,
    MAX_REVOCATION_PUSH_BYTES_V2,
    MAX_REVOCATION_PUSH_REFS_V2,
    MAX_SCOPE_LENGTH_BYTES,
    MAX_SCOPES_PER_CERT,
    check_v2_wire_size,
)
from .resource_path import normalize_resource_path, resource_paths_nested
from .scope import validate_required_scope_v2, validate_scopes_v2  # noqa: F401 - re-exported
from .signing_v2 import (
    CHALLENGE_PRESENTATION,
    DELEGATION_CERTIFICATE,
    REVOCATION_LIST,
    REVOCATION_PUSH,
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
from .types_v2 import lower_hex_string, valid_prefixed_digest_v2, valid_v2_id  # noqa: F401 - re-exported

RECEIVER_AUDIENCE = CONSTRAINT_RECEIVER_AUDIENCE
SCOPE_IDENTITY_DELEGATE = "identity:delegate"

# ---------------------------------------------------------------------------
# Generic strict member access (Go encoding/json semantics)


def _run(class_: str, fn: Callable[[], Any]) -> Any:
    """Run ``fn`` and classify any unclassified failure with ``class_``."""
    try:
        return fn()
    except V2Error:
        raise
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, AttributeError, UnicodeError) as exc:
        raise classify(class_, exc) from exc


def require_fields(obj: Any, names, nullable=()) -> dict:
    """Go ``requireV2Fields``: an object whose required members are present
    and non-null unless listed in ``nullable``."""
    if not isinstance(obj, dict):
        raise ValueError("wire v2: expected a JSON object")
    for name in names:
        if name not in obj:
            raise ValueError(f'wire v2: required field "{name}" is missing')
        if obj[name] is None and name not in nullable:
            raise ValueError(f'wire v2: required field "{name}" must not be null')
    check_v2_schema_key_case(obj)
    reject_v2_unexpected_null(obj)
    return obj


# Every member name of a v2 schema. A member name that differs from one of
# these only by case (ASCII or Unicode simple case folding) is malformed at
# any nesting level outside constraint ``params`` (Go ``v2SchemaFieldNames``).
V2_SCHEMA_FIELD_NAMES = frozenset((
    "version cert_id issuer_id issuer_pub_key subject_id subject_pub_key scope constraints signature ed25519 "
    "ml_dsa_65 issued_at expires_at verifier_id agent_id agent_pub_key delegations delegation_digest challenge "
    "challenge_at challenge_sig session_context stream_id stream_seq type params count currency end lat lon "
    "max_alt_m max_amount max_amount_micros max_lat max_lon max_mps min_alt_m min_lat min_lon path_prefix points "
    "radius_m resource_id start tz window_s exact_receiver_ids trust_domain_ids max_membership_age_seconds "
    "next_update sequence pushed_at revoked authority_id recovery_epoch role previous_statement_hash old_key "
    "new_key old_key_id new_key_id not_before old_signature new_signature log_id bundle_hash issuer_ids decision "
    "decision_reason identity_status trust_assessment status_assessment challenge_assessment context_assessment "
    "context_policy_digest verified_at required_scope granted_scope status_evidence_digests previous_receipt_hash "
    "human_id status_key_id object_type_code digest transaction_id created_at terms_schema_uri "
    "terms_canonical_json parties party_id proof_bundle_hash proof_bundle party_signatures invocation_id "
    "workspace_id session_id").split())

# The only v2 schema members whose value may be null (SPEC-v2 §2.1). Every
# other null, including every array element, is malformed.
V2_NULLABLE_MEMBERS = frozenset((
    "session_context", "stream_id", "stream_seq", "context_policy_digest",
    "floor", "accepted_snapshot", "preceding_checkpoint",
))

# Go strings.EqualFold folds these non-ASCII letters onto ASCII ones.
_SIMPLE_FOLD_TO_ASCII = {"\u017f": "s", "\u212a": "k"}


def _equal_fold_ascii_name(key: str, name: str) -> bool:
    """Go ``strings.EqualFold(key, name)`` for an ASCII lowercase ``name``."""
    if len(key) != len(name):
        return False
    for a, b in zip(key, name):
        if a == b:
            continue
        if ("A" <= a <= "Z" and chr(ord(a) + 32) == b) or _SIMPLE_FOLD_TO_ASCII.get(a) == b:
            continue
        return False
    return True


def check_v2_schema_key_case(value: Any) -> None:
    """Go ``checkV2SchemaKeyCase``: reject a member name that equals a v2
    schema name under case folding but differs from it in any byte."""
    if isinstance(value, dict):
        for key, member in value.items():
            if key not in V2_SCHEMA_FIELD_NAMES:
                for name in V2_SCHEMA_FIELD_NAMES:
                    if _equal_fold_ascii_name(key, name):
                        raise ValueError(f'wire v2: field "{key}" has incorrect case; use "{name}"')
            if key != "params":
                check_v2_schema_key_case(member)
    elif isinstance(value, list):
        for item in value:
            check_v2_schema_key_case(item)


def reject_v2_unexpected_null(value: Any, path: str = "$") -> None:
    """Go ``rejectV2UnexpectedNull``: null only as the value of a member in
    :data:`V2_NULLABLE_MEMBERS`; values inside ``params`` follow the general
    value model and are not checked here."""
    if value is None:
        raise ValueError(f"wire v2: {path} must not be null")
    if isinstance(value, dict):
        for key, member in value.items():
            if key == "params" or (member is None and key in V2_NULLABLE_MEMBERS):
                continue
            reject_v2_unexpected_null(member, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            reject_v2_unexpected_null(item, f"{path}[{i}]")


def check_keys(obj: dict, allowed, where: str = "object") -> None:
    for key in obj:
        if key not in allowed:
            raise ValueError(f'wire v2: {where}: unknown field "{key}"')


def get_str(obj: dict, key: str) -> str:
    value = obj.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"wire v2: {key} must be a string")
    return value


def get_int(obj: dict, key: str) -> int:
    value = obj.get(key)
    if value is None:
        return 0
    if type(value) is not int:
        raise ValueError(f"wire v2: {key} must be an integer")
    return value


def decode_bytes_value(value: Any, key: str) -> Optional[bytes]:
    """Go ``[]byte`` member: null is nil, otherwise strict padded base64."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"wire v2: {key} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"wire v2: {key} is not valid base64") from exc


def get_bytes(obj: dict, key: str) -> Optional[bytes]:
    return decode_bytes_value(obj.get(key), key)


def get_str_list(obj: dict, key: str) -> Optional[list[str]]:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"wire v2: {key} must be an array")
    out = []
    for item in value:
        if item is None:
            out.append("")
        elif isinstance(item, str):
            out.append(item)
        else:
            raise ValueError(f"wire v2: {key} must contain strings")
    return out


def decode_public_key(value: Any, key: str = "public key") -> HybridPublicKey:
    if value is None:
        return HybridPublicKey(ed25519=b"", ml_dsa_65=b"")
    if not isinstance(value, dict):
        raise ValueError(f"wire v2: {key} must be an object")
    check_keys(value, ("ed25519", "ml_dsa_65"), key)
    if "ed25519" not in value or "ml_dsa_65" not in value:
        raise ValueError(f"wire v2: {key} must have both ed25519 and ml_dsa_65 members")
    return HybridPublicKey(ed25519=get_bytes(value, "ed25519") or b"", ml_dsa_65=get_bytes(value, "ml_dsa_65") or b"")


def decode_signature(value: Any, key: str = "signature") -> HybridSignature:
    pub = decode_public_key(value, key)
    return HybridSignature(ed25519=pub.ed25519, ml_dsa_65=pub.ml_dsa_65)


def key_dict(key) -> dict:
    return {"ed25519": bytes(key.ed25519), "ml_dsa_65": bytes(key.ml_dsa_65)}


def utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


def validate_hybrid_signature_v2(sig: HybridSignature) -> None:
    if (not isinstance(sig, HybridSignature) or not isinstance(sig.ed25519, (bytes, bytearray))
            or not isinstance(sig.ml_dsa_65, (bytes, bytearray)) or len(sig.ed25519) != 64
            or len(sig.ml_dsa_65) != 3309):
        raise ValueError("wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components")


def placeholder_signature_v2() -> HybridSignature:
    return HybridSignature(ed25519=bytes(64), ml_dsa_65=bytes(3309))


def _check_int(value: Any, name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    return value


# ---------------------------------------------------------------------------
# Delegation certificates


@dataclass
class DelegationCertV2:
    version: int
    cert_id: str
    issuer_id: str
    issuer_pub_key: HybridPublicKey
    subject_id: str
    subject_pub_key: HybridPublicKey
    scope: Optional[list[str]]
    constraints: Optional[list[ConstraintV2]]
    issued_at: int
    expires_at: int
    signature: HybridSignature = field(default_factory=placeholder_signature_v2)


DELEGATION_V2_FIELDS = ("version", "cert_id", "issuer_id", "issuer_pub_key", "subject_id",
                        "subject_pub_key", "scope", "constraints", "issued_at", "expires_at", "signature")


def _validate_v2_scope_array(value: Any) -> None:
    """Go ``validateV2ScopeArray``: wire shape and resource bounds only."""
    if not isinstance(value, list):
        raise ValueError("wire v2: scope must be an array of strings")
    if len(value) > MAX_SCOPES_PER_CERT:
        raise ValueError("wire v2: scope count exceeds protocol bound")
    for i, item in enumerate(value):
        if item is not None and not isinstance(item, str):
            raise ValueError(f"wire v2: scope {i} must be a bounded string")
        if item is not None and utf8_len(item) > MAX_SCOPE_LENGTH_BYTES:
            raise ValueError(f"wire v2: scope {i} must be a bounded string")


def _cert_from_obj(obj: dict) -> DelegationCertV2:
    """Pre-struct shape checks plus the strict struct decode."""
    raw_constraints = obj.get("constraints")
    if not isinstance(raw_constraints, list):
        raise ValueError("wire v2: constraints must be an array")
    _validate_v2_scope_array(obj.get("scope"))
    constraints = [constraint_v2_from_fields(raw) for raw in raw_constraints]
    check_keys(obj, DELEGATION_V2_FIELDS, "delegation")
    return DelegationCertV2(
        version=get_int(obj, "version"),
        cert_id=get_str(obj, "cert_id"),
        issuer_id=get_str(obj, "issuer_id"),
        issuer_pub_key=decode_public_key(obj.get("issuer_pub_key"), "issuer_pub_key"),
        subject_id=get_str(obj, "subject_id"),
        subject_pub_key=decode_public_key(obj.get("subject_pub_key"), "subject_pub_key"),
        scope=get_str_list(obj, "scope"),
        constraints=constraints,
        issued_at=get_int(obj, "issued_at"),
        expires_at=get_int(obj, "expires_at"),
        signature=decode_signature(obj.get("signature")),
    )


def validate_delegation_cert_v2(c: DelegationCertV2) -> None:
    """Go ``validateDelegationCertV2`` (raises V2Error key_id_mismatch or ValueError)."""
    if not isinstance(c, DelegationCertV2):
        raise ValueError("v2 delegation certificate is required")
    if _check_int(c.version, "version") != 2:
        raise ValueError("version must be 2")
    if not valid_v2_timestamp(c.issued_at) or not valid_v2_timestamp(c.expires_at):
        raise ValueError("issued_at and expires_at must be inside the v2 timestamp domain")
    if not isinstance(c.cert_id, str) or c.cert_id == "" or utf8_len(c.cert_id) > MAX_IDENTIFIER_LENGTH_BYTES:
        raise ValueError("cert_id must be non-empty and within the identifier byte limit")
    if not valid_v2_id(c.issuer_id) or not valid_v2_id(c.subject_id):
        raise ValueError("issuer_id and subject_id must be 64 lowercase hexadecimal characters")
    issuer = key_id_v2(c.issuer_pub_key)
    subject = key_id_v2(c.subject_pub_key)
    if c.issuer_id != issuer or c.subject_id != subject:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "key ID does not match complete public key")
    if not isinstance(c.scope, list):
        raise ValueError("scope must be an array")
    for scope in c.scope:
        if not isinstance(scope, str) or utf8_len(scope) > MAX_SCOPE_LENGTH_BYTES:
            raise ValueError("scope exceeds the protocol byte limit")
    if not isinstance(c.constraints, list):
        raise ValueError("constraints must be an array")
    if len(c.scope) > MAX_SCOPES_PER_CERT or len(c.constraints) > MAX_CONSTRAINTS_PER_CERT:
        raise ValueError("scope or constraint count exceeds protocol bound")
    for i, constraint in enumerate(c.constraints):
        if not isinstance(constraint, ConstraintV2):
            raise ValueError(f"constraint {i} must be a ConstraintV2")
        constraint.to_canonical_dict()


def _constraints_list(c: DelegationCertV2) -> list:
    return [x.to_canonical_dict() for x in (c.constraints or [])]


def _cert_canonical_dict(c: DelegationCertV2, *, signature: bool) -> dict:
    out = {
        "cert_id": c.cert_id,
        "constraints": None if c.constraints is None else _constraints_list(c),
        "expires_at": c.expires_at,
        "issued_at": c.issued_at,
        "issuer_id": c.issuer_id,
        "issuer_pub_key": key_dict(c.issuer_pub_key),
        "scope": c.scope,
        "subject_id": c.subject_id,
        "subject_pub_key": key_dict(c.subject_pub_key),
        "version": c.version,
    }
    if signature:
        out["signature"] = key_dict(c.signature)
    return out


def cert_signable_bytes_v2(c: DelegationCertV2) -> bytes:
    """Go ``certSignableBytesV2``: every member except ``signature``."""
    d = _cert_canonical_dict(c, signature=False)
    if d["constraints"] is None:
        d["constraints"] = []
    return canonical(d)


def decode_delegation_cert_v2(data: bytes) -> DelegationCertV2:
    def run() -> DelegationCertV2:
        check_v2_wire_size(data, "certificate", "MAX_DELEGATION_CERT_BYTES_V2", MAX_DELEGATION_CERT_BYTES_V2)
        obj = _v2json.check_wire_json(data)
        require_fields(obj, DELEGATION_V2_FIELDS)
        cert = _cert_from_obj(obj)
        validate_delegation_cert_v2(cert)
        validate_hybrid_signature_v2(cert.signature)
        return cert

    return _run(V2ErrorClass.MALFORMED, run)


def encode_delegation_cert_v2(c: DelegationCertV2) -> bytes:
    def run() -> bytes:
        validate_delegation_cert_v2(c)
        validate_hybrid_signature_v2(c.signature)
        encoded = canonical(_cert_canonical_dict(c, signature=True))
        decode_delegation_cert_v2(encoded)
        return encoded

    return _run(V2ErrorClass.MALFORMED, run)


def verify_delegation_cert_v2_signature(cert: DelegationCertV2) -> None:
    """Go ``VerifyDelegationCertV2Signature``: structure, key-ID bindings,
    and the issuer signature under code 0x0001. Does not establish trust."""
    if cert is None:
        raise V2Error(V2ErrorClass.MALFORMED, "v2 delegation certificate is nil")

    def structure() -> bytes:
        validate_delegation_cert_v2(cert)
        validate_hybrid_signature_v2(cert.signature)
        return cert_signable_bytes_v2(cert)

    signable = _run(V2ErrorClass.MALFORMED, structure)
    verify_v2_statement(DELEGATION_CERTIFICATE, signable, cert.signature, cert.issuer_pub_key)


def validate_delegation_issuance_v2(cert: DelegationCertV2) -> None:
    """Go ``validateDelegationIssuanceV2``: the issuer duties a decoder does
    not enforce (SPEC-v2 §5.1, §5.2). Raises ``V2SigningError``."""
    if cert.issued_at >= cert.expires_at:
        raise V2SigningError("v2 issuer duty: issued_at must be earlier than expires_at")
    if cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS:
        raise V2SigningError(f"v2 issuer duty: delegation lifetime exceeds {V2_MAX_DELEGATION_LIFETIME_SECONDS} seconds")
    resource_id = ""
    prefixes: list[str] = []
    for i, c in enumerate(cert.constraints or []):
        if c.type != CONSTRAINT_RESOURCE_PATH:
            continue
        if c.path_prefix != "":
            try:
                normalize_resource_path(c.path_prefix)
            except ValueError as exc:
                raise V2SigningError(f"v2 issuer duty: constraint {i} path_prefix can never match: {exc}") from exc
        if resource_id == "":
            resource_id = c.resource_id
        elif c.resource_id != resource_id:
            raise V2SigningError(
                f"v2 issuer duty: constraint {i} names a different resource_id; the resource_path set is jointly unsatisfiable")
        for prior in prefixes:
            if not resource_paths_nested(prior, c.path_prefix):
                raise V2SigningError(
                    f"v2 issuer duty: constraint {i} path_prefix {c.path_prefix!r} does not nest with {prior!r}; "
                    "the resource_path set is jointly unsatisfiable")
        prefixes.append(c.path_prefix)


def sign_delegation_cert_v2(cert: DelegationCertV2, issuer_key: HybridPrivateKey) -> DelegationCertV2:
    """Go ``SignDelegationCertV2``: a signed copy of ``cert`` under the
    issuer's private key (native extension)."""
    if cert is None:
        raise V2SigningError("v2 delegation certificate is nil")
    _check_issuer_duties(cert)
    return sign_delegation_cert_v2_with_signer(background(), cert, _as_signer(issuer_key))


def _check_issuer_duties(cert: DelegationCertV2) -> None:
    validate_delegation_cert_v2(cert)
    try:
        validate_scopes_v2(cert.scope)
    except ValueError as exc:
        raise V2SigningError(f"v2 issuer scope: {exc}") from exc
    validate_delegation_issuance_v2(cert)


def sign_delegation_cert_v2_with_signer(ctx: Context, cert: DelegationCertV2, signer: SignerV2) -> DelegationCertV2:
    """Go ``SignDelegationCertV2WithSigner``. The issuer duties are checked
    before any signer method runs, so a refused certificate never reaches the
    signer."""
    if cert is None:
        raise V2SigningError("v2 delegation certificate is nil")
    _check_issuer_duties(cert)
    issuer_pub = signer_public_key_v2(signer)
    issuer_id = key_id_v2(issuer_pub)
    if cert.issuer_id != issuer_id or not equal_public_keys(cert.issuer_pub_key, issuer_pub):
        raise V2SigningError("v2 issuer key does not match certificate issuer")
    prepared = decode_delegation_cert_v2(encode_delegation_cert_v2(replace(cert, signature=placeholder_signature_v2())))
    signable = cert_signable_bytes_v2(prepared)
    prepared.signature = _sign_v2_statement_with_signer(ctx, DELEGATION_CERTIFICATE, signable, signer, issuer_pub)
    signed = decode_delegation_cert_v2(encode_delegation_cert_v2(prepared))
    verify_v2_statement(DELEGATION_CERTIFICATE, signable, signed.signature, issuer_pub)
    return signed


# ---------------------------------------------------------------------------
# Proof bundles


@dataclass
class ProofBundleV2:
    version: int
    verifier_id: str
    agent_id: str
    agent_pub_key: HybridPublicKey
    delegations: Optional[list[DelegationCertV2]]
    delegation_digest: bytes
    challenge: bytes
    challenge_at: int
    challenge_sig: HybridSignature
    session_context: Optional[bytes] = None
    stream_id: Optional[bytes] = None
    stream_seq: Optional[int] = None


PROOF_BUNDLE_V2_FIELDS = ("version", "verifier_id", "agent_id", "agent_pub_key", "delegations",
                          "delegation_digest", "challenge", "challenge_at", "challenge_sig",
                          "session_context", "stream_id", "stream_seq")


def decode_proof_bundle_v2(data: bytes) -> ProofBundleV2:
    def run() -> ProofBundleV2:
        check_v2_wire_size(data, "proof bundle", "MAX_PROOF_BUNDLE_BYTES_V2", MAX_PROOF_BUNDLE_BYTES_V2)
        obj = _v2json.check_wire_json(data, ("delegation_digest",))
        require_fields(obj, PROOF_BUNDLE_V2_FIELDS, ("session_context", "stream_id", "stream_seq"))
        raw_delegations = obj.get("delegations")
        if not isinstance(raw_delegations, list):
            raise ValueError("wire v2: delegations must be an array")
        delegations = []
        for raw_cert in raw_delegations:
            require_fields(raw_cert, DELEGATION_V2_FIELDS)
            delegations.append(_cert_from_obj(raw_cert))
        check_keys(obj, PROOF_BUNDLE_V2_FIELDS, "proof bundle")
        stream_seq = obj.get("stream_seq")
        if stream_seq is not None:
            stream_seq = get_int(obj, "stream_seq")
        bundle = ProofBundleV2(
            version=get_int(obj, "version"),
            verifier_id=get_str(obj, "verifier_id"),
            agent_id=get_str(obj, "agent_id"),
            agent_pub_key=decode_public_key(obj.get("agent_pub_key"), "agent_pub_key"),
            delegations=delegations,
            delegation_digest=get_bytes(obj, "delegation_digest") or b"",
            challenge=get_bytes(obj, "challenge") or b"",
            challenge_at=get_int(obj, "challenge_at"),
            challenge_sig=decode_signature(obj.get("challenge_sig"), "challenge_sig"),
            session_context=get_bytes(obj, "session_context"),
            stream_id=get_bytes(obj, "stream_id"),
            stream_seq=stream_seq,
        )
        if bundle.version != 2:
            raise ValueError("wire v2: version must be 2")
        if not valid_v2_id(bundle.verifier_id) or not valid_v2_id(bundle.agent_id):
            raise ValueError("wire v2: verifier_id and agent_id must be 64 lowercase hexadecimal characters")
        if len(delegations) > MAX_DELEGATION_CHAIN_DEPTH:
            raise ValueError(f"wire v2: delegation chain exceeds MAX_DELEGATION_CHAIN_DEPTH ({MAX_DELEGATION_CHAIN_DEPTH})")
        if len(bundle.challenge) != 32:
            raise ValueError("wire v2: challenge must be 32 bytes")
        if not valid_v2_timestamp(bundle.challenge_at):
            raise ValueError("wire v2: challenge_at is outside 0..253402300799")
        if len(bundle.delegation_digest) != 48:
            raise ValueError("wire v2: delegation_digest must be 48 bytes")
        if bundle.session_context is not None and len(bundle.session_context) != 32:
            raise ValueError("wire v2: session_context must be null or 32 bytes")
        if (bundle.stream_id is None) != (bundle.stream_seq is None):
            raise ValueError("wire v2: stream_id and stream_seq must both be null or both set")
        if bundle.stream_id is not None and (len(bundle.stream_id) != 32 or bundle.stream_seq <= 0):
            raise ValueError("wire v2: bound stream requires 32-byte stream_id and positive stream_seq")
        if bundle.stream_seq is not None and bundle.stream_seq > MAX_SAFE_INTEGER:
            raise ValueError("wire v2: stream_seq exceeds the safe integer range")
        validate_hybrid_signature_v2(bundle.challenge_sig)
        for i, cert in enumerate(delegations):
            validate_delegation_cert_v2(cert)
            validate_hybrid_signature_v2(cert.signature)
        return bundle

    return _run(V2ErrorClass.MALFORMED, run)


def _bundle_canonical_dict(b: ProofBundleV2) -> dict:
    return {
        "agent_id": b.agent_id,
        "agent_pub_key": key_dict(b.agent_pub_key),
        "challenge": bytes(b.challenge),
        "challenge_at": b.challenge_at,
        "challenge_sig": key_dict(b.challenge_sig),
        "delegation_digest": bytes(b.delegation_digest),
        "delegations": None if b.delegations is None else [
            _cert_canonical_dict(c, signature=True) for c in b.delegations
        ],
        "session_context": None if b.session_context is None else bytes(b.session_context),
        "stream_id": None if b.stream_id is None else bytes(b.stream_id),
        "stream_seq": b.stream_seq,
        "verifier_id": b.verifier_id,
        "version": b.version,
    }


def encode_proof_bundle_v2(b: ProofBundleV2) -> bytes:
    if b is None:
        raise V2Error(V2ErrorClass.MALFORMED, "v2 proof bundle is nil")
    encoded = _run(V2ErrorClass.MALFORMED, lambda: canonical(_bundle_canonical_dict(b)))
    try:
        decode_proof_bundle_v2(encoded)
    except V2Error as exc:
        raise V2Error(exc.error_class, f"invalid v2 proof bundle: {exc}") from exc
    return encoded


def presentation_signable_bytes_v2(b: ProofBundleV2) -> bytes:
    return canonical({
        "agent_id": b.agent_id,
        "agent_pub_key": key_dict(b.agent_pub_key),
        "challenge": bytes(b.challenge),
        "challenge_at": b.challenge_at,
        "delegation_digest": bytes(b.delegation_digest),
        "session_context": None if b.session_context is None else bytes(b.session_context),
        "stream_id": None if b.stream_id is None else bytes(b.stream_id),
        "stream_seq": b.stream_seq,
        "verifier_id": b.verifier_id,
        "version": b.version,
    })


def delegation_digest_v2(certs: list[DelegationCertV2]) -> bytes:
    """Go ``delegationDigestV2``: SHA-384 over the canonical signed chain."""
    ordered = []
    for c in certs:
        d = _cert_canonical_dict(c, signature=True)
        if d["constraints"] is None:
            d["constraints"] = []
        ordered.append(d)
    return sha384(b"ratify-protocol-delegations-v2\x00" + canonical(ordered)).digest()


def bundle_hash_v2(bundle: ProofBundleV2) -> str:
    """BundleHashV2: ``sha384:`` hex over the complete canonical signed bundle."""
    encoded = encode_proof_bundle_v2(bundle)
    return "sha384:" + sha384(b"ratify-protocol-bundle-v2\x00" + encoded).hexdigest()


def verify_proof_bundle_v2_structure(b: ProofBundleV2) -> None:
    """Every key ID, the delegation digest, duplicate CertificateRefs, and linkage."""
    malformed = V2ErrorClass.MALFORMED
    if not isinstance(b, ProofBundleV2):
        raise V2Error(malformed, "v2 proof bundle is nil")
    if b.version != 2:
        raise V2Error(malformed, "v2 proof bundle version must be 2")
    if not isinstance(b.delegations, list):
        raise V2Error(malformed, "v2 delegations must be an array")
    if (len(b.delegations) > MAX_DELEGATION_CHAIN_DEPTH or len(b.challenge or b"") != 32
            or len(b.delegation_digest or b"") != 48):
        raise V2Error(malformed, "v2 proof bundle exceeds a chain bound or has an invalid challenge/digest length")
    if b.stream_seq is not None and (type(b.stream_seq) is not int or b.stream_seq > MAX_SAFE_INTEGER):
        raise V2Error(malformed, "v2 stream sequence exceeds the safe integer range")
    if b.session_context is not None and len(b.session_context) != 32:
        raise V2Error(malformed, "v2 session_context must be null or 32 bytes")
    stream_null = b.stream_id is None
    if stream_null != (b.stream_seq is None) or (not stream_null and (len(b.stream_id) != 32 or b.stream_seq <= 0)):
        raise V2Error(malformed, "v2 stream_id and stream_seq must both be null or a 32-byte ID and positive sequence")
    if not valid_v2_id(b.agent_id) or not valid_v2_id(b.verifier_id):
        raise V2Error(malformed, "v2 verifier and agent IDs must be canonical")
    agent_id = _run(malformed, lambda: key_id_v2(b.agent_pub_key))
    if agent_id != b.agent_id:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "agent_id does not match agent_pub_key")
    for cert in b.delegations:
        _run(malformed, lambda cert=cert: validate_delegation_cert_v2(cert))
    digest = _run(malformed, lambda: delegation_digest_v2(b.delegations))
    if digest != bytes(b.delegation_digest):
        raise V2Error(V2ErrorClass.DELEGATION_DIGEST_MISMATCH, "delegation_digest mismatch")
    seen = set()
    for i, c in enumerate(b.delegations):
        ref = (c.issuer_id, c.cert_id)
        if ref in seen:
            raise V2Error(V2ErrorClass.DUPLICATE_CERTIFICATE_REF, "duplicate delegation reference")
        seen.add(ref)
        if i + 1 < len(b.delegations):
            parent = b.delegations[i + 1]
            if c.issuer_id != parent.subject_id or not equal_public_keys(c.issuer_pub_key, parent.subject_pub_key):
                raise V2Error(V2ErrorClass.CHAIN_LINKAGE_MISMATCH, f"delegation chain link {i} does not match parent subject")
    if b.delegations:
        leaf = b.delegations[0]
        if leaf.subject_id != b.agent_id or not equal_public_keys(leaf.subject_pub_key, b.agent_pub_key):
            raise V2Error(V2ErrorClass.CHAIN_LINKAGE_MISMATCH, "agent key does not match leaf delegation subject")


def verify_proof_bundle_v2_signatures_only(b: ProofBundleV2) -> None:
    for c in b.delegations:
        signable = _run(V2ErrorClass.MALFORMED, lambda c=c: cert_signable_bytes_v2(c))
        verify_v2_statement(DELEGATION_CERTIFICATE, signable, c.signature, c.issuer_pub_key)
    signable = _run(V2ErrorClass.MALFORMED, lambda: presentation_signable_bytes_v2(b))
    verify_v2_statement(CHALLENGE_PRESENTATION, signable, b.challenge_sig, b.agent_pub_key)


def verify_proof_bundle_v2_signatures(b: ProofBundleV2) -> None:
    """Go ``VerifyProofBundleV2Signatures``: every structural check first,
    then each certificate signature and the challenge signature. Does not
    resolve trust, consume a challenge, or query status."""
    verify_proof_bundle_v2_structure(b)
    verify_proof_bundle_v2_signatures_only(b)


def sign_proof_bundle_v2(bundle: ProofBundleV2, agent_key: HybridPrivateKey) -> ProofBundleV2:
    """Go ``SignProofBundleV2``: compute the delegation digest and sign the
    challenge presentation with the agent key."""
    return sign_proof_bundle_v2_with_signer(background(), bundle, _as_signer(agent_key))


def sign_proof_bundle_v2_with_signer(ctx: Context, bundle: ProofBundleV2, signer: SignerV2) -> ProofBundleV2:
    """Go ``SignProofBundleV2WithSigner``."""
    if bundle is None:
        raise V2SigningError("v2 proof bundle is nil")
    agent_pub = signer_public_key_v2(signer)
    agent_id = key_id_v2(agent_pub)
    if bundle.agent_id != agent_id or not equal_public_keys(bundle.agent_pub_key, agent_pub):
        raise V2SigningError("v2 agent key does not match proof bundle agent")
    unsigned = replace(bundle, challenge_sig=placeholder_signature_v2(), delegation_digest=bytes(48))
    prepared = decode_proof_bundle_v2(encode_proof_bundle_v2(unsigned))
    prepared.delegation_digest = delegation_digest_v2(prepared.delegations)
    signable = presentation_signable_bytes_v2(prepared)
    prepared.challenge_sig = _sign_v2_statement_with_signer(ctx, CHALLENGE_PRESENTATION, signable, signer, agent_pub)
    signed = decode_proof_bundle_v2(encode_proof_bundle_v2(prepared))
    verify_proof_bundle_v2_signatures(signed)
    return signed


# ---------------------------------------------------------------------------
# Revocation list and push


@dataclass
class RevocationListV2:
    version: int
    issuer_id: str
    updated_at: int
    next_update: int
    sequence: int
    revoked: Optional[list[str]]  # issuer-scoped cert IDs, wire [{"cert_id": ...}]
    signature: HybridSignature = field(default_factory=placeholder_signature_v2)


@dataclass
class RevocationPushV2:
    version: int
    issuer_id: str
    sequence: int
    pushed_at: int
    revoked: Optional[list[str]]
    signature: HybridSignature = field(default_factory=placeholder_signature_v2)


REVOCATION_LIST_V2_FIELDS = ("version", "issuer_id", "updated_at", "next_update", "sequence", "revoked", "signature")
REVOCATION_PUSH_V2_FIELDS = ("version", "issuer_id", "sequence", "pushed_at", "revoked", "signature")


def _decode_revoked(value: Any) -> Optional[list[str]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("wire v2: revoked must be an array")
    out = []
    for item in value:
        if item is None:
            out.append("")
            continue
        if not isinstance(item, dict):
            raise ValueError("wire v2: revoked entries must be objects")
        check_keys(item, ("cert_id",), "revoked entry")
        out.append(get_str(item, "cert_id"))
    return out


def _validate_revoked(refs: Optional[list[str]]) -> None:
    if not isinstance(refs, list):
        raise ValueError("v2 revoked must be an array")
    seen = set()
    for ref in refs:
        if not isinstance(ref, str) or ref == "" or ref in seen:
            raise ValueError("v2 revoked cert IDs must be non-empty and unique")
        seen.add(ref)


def _positive_safe(value: Any) -> bool:
    return type(value) is int and 0 < value <= MAX_SAFE_INTEGER


def validate_revocation_list_v2(lst: RevocationListV2) -> None:
    if (
        not isinstance(lst, RevocationListV2) or lst.version != 2 or not valid_v2_id(lst.issuer_id)
        or not _positive_safe(lst.sequence) or not valid_v2_timestamp(lst.updated_at)
        or not valid_v2_timestamp(lst.next_update) or lst.next_update <= lst.updated_at
    ):
        raise ValueError("v2 revocation list has invalid version, issuer, sequence, or time bounds")
    if isinstance(lst.revoked, list) and len(lst.revoked) > MAX_REVOCATION_LIST_REFS_V2:
        raise ValueError(f"v2 revocation list exceeds MAX_REVOCATION_LIST_REFS_V2 ({MAX_REVOCATION_LIST_REFS_V2})")
    _validate_revoked(lst.revoked)


def validate_revocation_push_v2(push: RevocationPushV2) -> None:
    if (
        not isinstance(push, RevocationPushV2) or push.version != 2 or not valid_v2_id(push.issuer_id)
        or not _positive_safe(push.sequence) or not valid_v2_timestamp(push.pushed_at)
    ):
        raise ValueError("v2 revocation push has invalid version, issuer, sequence, or timestamp")
    if isinstance(push.revoked, list) and len(push.revoked) > MAX_REVOCATION_PUSH_REFS_V2:
        raise ValueError(f"v2 revocation push exceeds MAX_REVOCATION_PUSH_REFS_V2 ({MAX_REVOCATION_PUSH_REFS_V2})")
    _validate_revoked(push.revoked)


def _revoked_dicts(refs: Optional[list[str]]) -> Optional[list[dict]]:
    return None if refs is None else [{"cert_id": ref} for ref in refs]


def revocation_list_signable_bytes_v2(lst: RevocationListV2) -> bytes:
    validate_revocation_list_v2(lst)
    return canonical({
        "issuer_id": lst.issuer_id, "next_update": lst.next_update, "revoked": _revoked_dicts(lst.revoked),
        "sequence": lst.sequence, "updated_at": lst.updated_at, "version": lst.version,
    })


def revocation_push_signable_bytes_v2(push: RevocationPushV2) -> bytes:
    validate_revocation_push_v2(push)
    return canonical({
        "issuer_id": push.issuer_id, "pushed_at": push.pushed_at, "revoked": _revoked_dicts(push.revoked),
        "sequence": push.sequence, "version": push.version,
    })


def decode_revocation_list_v2(data: bytes) -> RevocationListV2:
    def run() -> RevocationListV2:
        check_v2_wire_size(data, "revocation list", "MAX_REVOCATION_LIST_BYTES_V2", MAX_REVOCATION_LIST_BYTES_V2)
        obj = _v2json.check_wire_json(data)
        require_fields(obj, REVOCATION_LIST_V2_FIELDS)
        check_keys(obj, REVOCATION_LIST_V2_FIELDS, "revocation list")
        lst = RevocationListV2(
            version=get_int(obj, "version"), issuer_id=get_str(obj, "issuer_id"),
            updated_at=get_int(obj, "updated_at"), next_update=get_int(obj, "next_update"),
            sequence=get_int(obj, "sequence"), revoked=_decode_revoked(obj.get("revoked")),
            signature=decode_signature(obj.get("signature")),
        )
        validate_revocation_list_v2(lst)
        validate_hybrid_signature_v2(lst.signature)
        return lst

    return _run(V2ErrorClass.MALFORMED, run)


def decode_revocation_push_v2(data: bytes) -> RevocationPushV2:
    def run() -> RevocationPushV2:
        check_v2_wire_size(data, "revocation push", "MAX_REVOCATION_PUSH_BYTES_V2", MAX_REVOCATION_PUSH_BYTES_V2)
        obj = _v2json.check_wire_json(data)
        require_fields(obj, REVOCATION_PUSH_V2_FIELDS)
        check_keys(obj, REVOCATION_PUSH_V2_FIELDS, "revocation push")
        push = RevocationPushV2(
            version=get_int(obj, "version"), issuer_id=get_str(obj, "issuer_id"),
            sequence=get_int(obj, "sequence"), pushed_at=get_int(obj, "pushed_at"),
            revoked=_decode_revoked(obj.get("revoked")), signature=decode_signature(obj.get("signature")),
        )
        validate_revocation_push_v2(push)
        validate_hybrid_signature_v2(push.signature)
        return push

    return _run(V2ErrorClass.MALFORMED, run)


def encode_revocation_list_v2(lst: RevocationListV2) -> bytes:
    def run() -> bytes:
        validate_revocation_list_v2(lst)
        validate_hybrid_signature_v2(lst.signature)
        encoded = canonical({
            "issuer_id": lst.issuer_id, "next_update": lst.next_update, "revoked": _revoked_dicts(lst.revoked),
            "sequence": lst.sequence, "signature": key_dict(lst.signature), "updated_at": lst.updated_at,
            "version": lst.version,
        })
        decode_revocation_list_v2(encoded)
        return encoded

    return _run(V2ErrorClass.MALFORMED, run)


def encode_revocation_push_v2(push: RevocationPushV2) -> bytes:
    def run() -> bytes:
        validate_revocation_push_v2(push)
        validate_hybrid_signature_v2(push.signature)
        encoded = canonical({
            "issuer_id": push.issuer_id, "pushed_at": push.pushed_at, "revoked": _revoked_dicts(push.revoked),
            "sequence": push.sequence, "signature": key_dict(push.signature), "version": push.version,
        })
        decode_revocation_push_v2(encoded)
        return encoded

    return _run(V2ErrorClass.MALFORMED, run)


def verify_revocation_list_v2_signature(lst: RevocationListV2, trusted_issuer_id: str, status_key: HybridPublicKey) -> None:
    """Status signatures are checked only against the caller-authenticated
    status key bound to this issuer; the object never supplies its own key."""
    _run(V2ErrorClass.MALFORMED, lambda: validate_revocation_list_v2(lst))
    if trusted_issuer_id != lst.issuer_id:
        raise V2Error(V2ErrorClass.STATUS_KEY_BINDING_MISMATCH,
                      "v2 revocation list issuer does not match authenticated status-key binding")
    signable = revocation_list_signable_bytes_v2(lst)
    verify_v2_statement(REVOCATION_LIST, signable, lst.signature, status_key)


def verify_revocation_push_v2_signature(push: RevocationPushV2, trusted_issuer_id: str, status_key: HybridPublicKey) -> None:
    _run(V2ErrorClass.MALFORMED, lambda: validate_revocation_push_v2(push))
    if trusted_issuer_id != push.issuer_id:
        raise V2Error(V2ErrorClass.STATUS_KEY_BINDING_MISMATCH,
                      "v2 revocation push issuer does not match authenticated status-key binding")
    signable = revocation_push_signable_bytes_v2(push)
    verify_v2_statement(REVOCATION_PUSH, signable, push.signature, status_key)


def _sign_status(ctx: Context, kind: str, obj, bound_issuer_id: str, bound_status_key: HybridPublicKey,
                 signer: SignerV2):
    if kind == "list":
        validate, encode, decode, signable_of, code, verify = (
            validate_revocation_list_v2, encode_revocation_list_v2, decode_revocation_list_v2,
            revocation_list_signable_bytes_v2, REVOCATION_LIST, verify_revocation_list_v2_signature)
    else:
        validate, encode, decode, signable_of, code, verify = (
            validate_revocation_push_v2, encode_revocation_push_v2, decode_revocation_push_v2,
            revocation_push_signable_bytes_v2, REVOCATION_PUSH, verify_revocation_push_v2_signature)
    validate(obj)
    if not bound_issuer_id or obj.issuer_id != bound_issuer_id:
        raise V2SigningError(f"revocation-{kind} issuer does not match caller-authenticated status-key binding")
    derived = signer_public_key_v2(signer)
    if not isinstance(bound_status_key, HybridPublicKey) or not equal_public_keys(bound_status_key, derived):
        raise V2SigningError("status private key does not match caller-authenticated issuer status-key binding")
    prepared = decode(encode(replace(obj, signature=placeholder_signature_v2())))
    prepared.signature = _sign_v2_statement_with_signer(ctx, code, signable_of(prepared), signer, derived)
    signed = decode(encode(prepared))
    verify(signed, bound_issuer_id, bound_status_key)
    return signed


def sign_revocation_list_v2(lst: RevocationListV2, bound_issuer_id: str, bound_status_key: HybridPublicKey,
                            status_key: HybridPrivateKey) -> RevocationListV2:
    return _sign_status(background(), "list", lst, bound_issuer_id, bound_status_key, _as_signer(status_key))


def sign_revocation_list_v2_with_signer(ctx: Context, lst: RevocationListV2, bound_issuer_id: str,
                                        bound_status_key: HybridPublicKey, signer: SignerV2) -> RevocationListV2:
    return _sign_status(ctx, "list", lst, bound_issuer_id, bound_status_key, signer)


def sign_revocation_push_v2(push: RevocationPushV2, bound_issuer_id: str, bound_status_key: HybridPublicKey,
                            status_key: HybridPrivateKey) -> RevocationPushV2:
    return _sign_status(background(), "push", push, bound_issuer_id, bound_status_key, _as_signer(status_key))


def sign_revocation_push_v2_with_signer(ctx: Context, push: RevocationPushV2, bound_issuer_id: str,
                                        bound_status_key: HybridPublicKey, signer: SignerV2) -> RevocationPushV2:
    return _sign_status(ctx, "push", push, bound_issuer_id, bound_status_key, signer)


def status_evidence_digest(object_type: int, obj: Any) -> bytes:
    """Go ``StatusEvidenceDigest``: SHA-384 over the complete canonical signed
    status object. It is a reference to evidence, not proof of validity."""
    if object_type == REVOCATION_LIST:
        if not isinstance(obj, RevocationListV2):
            raise ValueError("status evidence type 0x0003 requires RevocationListV2")
        encoded = encode_revocation_list_v2(obj)
    elif object_type == REVOCATION_PUSH:
        if not isinstance(obj, RevocationPushV2):
            raise ValueError("status evidence type 0x0005 requires RevocationPushV2")
        encoded = encode_revocation_push_v2(obj)
    else:
        raise ValueError(f"unsupported status evidence object type: {object_type!r}")
    return sha384(b"ratify-protocol-status-evidence-v2\x00" + object_type.to_bytes(2, "big") + encoded).digest()
