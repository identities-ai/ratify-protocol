"""Protocol v2 key rotation statements and the AcceptRotation journal
(mirrors Go key_rotation_v2.go and key_rotation_journal_v2.go)."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .errors_v2 import (
    KeyRotationForkError,
    KeyRotationFrozenError,
    V2Error,
    V2ErrorClass,
)
from .protocol_v2 import (
    _run,
    check_keys,
    decode_public_key,
    decode_signature,
    get_bytes,
    get_int,
    get_str,
    key_dict,
    lower_hex_string,
    require_fields,
    valid_v2_id,
    validate_hybrid_signature_v2,
)
from .clock_bounds_v2 import valid_v2_timestamp
from .context_v2 import Context, background
from .limits_v2 import MAX_KEY_ROTATION_STATEMENT_BYTES_V2, check_v2_wire_size
from .signing_v2 import (
    KEY_ROTATION_AUTHORIZATION,
    KEY_ROTATION_PROOF_OF_POSSESSION,
    SignerV2,
    V2SigningError,
    _as_signer,
    clone_public_key,
    equal_public_keys,
    key_id_v2,
    sign_v2_statement_with_signer,
    signer_public_key_v2,
    verify_v2_statement,
)
from .types import HybridPrivateKey, HybridPublicKey, HybridSignature
from .witness_v2 import ZERO_HASH, WitnessEntryV2Result, statement_body_digest_v2

ROTATION_ROLES = ("organization_root", "issuer", "agent")


@dataclass
class KeyRotationStatementV2:
    version: int
    authority_id: str
    recovery_epoch: int
    role: str
    sequence: int
    previous_statement_hash: bytes
    old_key: HybridPublicKey
    new_key: HybridPublicKey
    old_key_id: str
    new_key_id: str
    issued_at: int
    not_before: int
    old_signature: HybridSignature = field(default_factory=lambda: HybridSignature(b"", b""))
    new_signature: HybridSignature = field(default_factory=lambda: HybridSignature(b"", b""))


@dataclass
class KeyRotationV2State:
    authority_id: str
    recovery_epoch: int
    role: str
    sequence: int
    head_hash: bytes
    current_key: HybridPublicKey
    used_key_ids: list[str]


@dataclass
class KeyRotationV2AcceptedEntry:
    sequence: int
    body_digest: bytes
    old_key: HybridPublicKey


@dataclass
class KeyRotationV2Journal:
    state: KeyRotationV2State
    accepted: list[KeyRotationV2AcceptedEntry] = field(default_factory=list)
    frozen: bool = False


KEY_ROTATION_V2_FIELDS = (
    "version", "authority_id", "recovery_epoch", "role", "sequence", "previous_statement_hash",
    "old_key", "new_key", "old_key_id", "new_key_id", "issued_at", "not_before", "old_signature", "new_signature",
)
_SIGNABLE_FIELDS = ("authority_id", "issued_at", "new_key", "new_key_id", "not_before", "old_key", "old_key_id",
                    "previous_statement_hash", "recovery_epoch", "role", "sequence", "version")


def validate_key_rotation_statement_v2(stmt: KeyRotationStatementV2, signatures: bool) -> None:
    if not isinstance(stmt, KeyRotationStatementV2) or stmt.version != 2:
        raise ValueError("wire v2: rotation version must be 2")
    if not isinstance(stmt.authority_id, str) or len(stmt.authority_id) != 32 or not lower_hex_string(stmt.authority_id):
        raise ValueError("wire v2: authority_id must be 32 lowercase hexadecimal characters")
    if (type(stmt.recovery_epoch) is not int or type(stmt.sequence) is not int
            or not (0 < stmt.recovery_epoch <= MAX_SAFE_INTEGER) or not (0 < stmt.sequence <= MAX_SAFE_INTEGER)):
        raise ValueError("wire v2: recovery_epoch and sequence must be positive safe integers")
    if not valid_v2_timestamp(stmt.issued_at) or not valid_v2_timestamp(stmt.not_before):
        raise ValueError("wire v2: issued_at and not_before must be inside the v2 timestamp domain")
    if stmt.role not in ROTATION_ROLES:
        raise ValueError("wire v2: rotation role is invalid")
    if not isinstance(stmt.previous_statement_hash, (bytes, bytearray)) or len(stmt.previous_statement_hash) != 48:
        raise ValueError("wire v2: previous_statement_hash must be 48 bytes")
    if stmt.sequence == 1 and bytes(stmt.previous_statement_hash) != ZERO_HASH:
        raise ValueError("wire v2: genesis rotation must use a zero previous_statement_hash")
    if stmt.sequence > 1 and bytes(stmt.previous_statement_hash) == ZERO_HASH:
        raise ValueError("wire v2: non-genesis rotation must link to a prior statement")
    if not valid_v2_id(stmt.old_key_id) or not valid_v2_id(stmt.new_key_id):
        raise ValueError("wire v2: old_key_id and new_key_id must be 64 lowercase hexadecimal characters")
    old_id = key_id_v2(stmt.old_key)
    new_id = key_id_v2(stmt.new_key)
    if old_id != stmt.old_key_id or new_id != stmt.new_key_id:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "wire v2: rotation key IDs must match distinct complete keys")
    if old_id == new_id or equal_public_keys(stmt.old_key, stmt.new_key):
        raise ValueError("wire v2: rotation key IDs must match distinct complete keys")
    if signatures:
        validate_hybrid_signature_v2(stmt.old_signature)
        validate_hybrid_signature_v2(stmt.new_signature)


def _signable_dict(stmt: KeyRotationStatementV2) -> dict:
    return {
        "authority_id": stmt.authority_id, "issued_at": stmt.issued_at, "new_key": key_dict(stmt.new_key),
        "new_key_id": stmt.new_key_id, "not_before": stmt.not_before, "old_key": key_dict(stmt.old_key),
        "old_key_id": stmt.old_key_id, "previous_statement_hash": bytes(stmt.previous_statement_hash),
        "recovery_epoch": stmt.recovery_epoch, "role": stmt.role, "sequence": stmt.sequence, "version": stmt.version,
    }


def key_rotation_signable_bytes_v2(stmt: KeyRotationStatementV2) -> bytes:
    validate_key_rotation_statement_v2(stmt, False)
    return canonical(_signable_dict(stmt))


def _stmt_from_obj(obj: dict, allowed) -> KeyRotationStatementV2:
    check_keys(obj, allowed, "rotation statement")
    return KeyRotationStatementV2(
        version=get_int(obj, "version"), authority_id=get_str(obj, "authority_id"),
        recovery_epoch=get_int(obj, "recovery_epoch"), role=get_str(obj, "role"),
        sequence=get_int(obj, "sequence"), previous_statement_hash=get_bytes(obj, "previous_statement_hash") or b"",
        old_key=decode_public_key(obj.get("old_key"), "old_key"), new_key=decode_public_key(obj.get("new_key"), "new_key"),
        old_key_id=get_str(obj, "old_key_id"), new_key_id=get_str(obj, "new_key_id"),
        issued_at=get_int(obj, "issued_at"), not_before=get_int(obj, "not_before"),
        old_signature=decode_signature(obj.get("old_signature"), "old_signature"),
        new_signature=decode_signature(obj.get("new_signature"), "new_signature"),
    )


def validate_key_rotation_signable_body_v2(body: bytes) -> None:
    obj = _v2json.parse(body)
    require_fields(obj, _SIGNABLE_FIELDS)
    stmt = _stmt_from_obj(obj, _SIGNABLE_FIELDS)
    if canonical(_signable_dict(stmt)) != body:
        raise ValueError("rotation signable body must use RatifyCanonicalJSON")
    validate_key_rotation_statement_v2(stmt, False)


def key_rotation_statement_v2_digest(stmt: KeyRotationStatementV2) -> bytes:
    """StatementBodyDigestV2(0x0004, body); both signatures are excluded."""
    return statement_body_digest_v2(KEY_ROTATION_AUTHORIZATION, key_rotation_signable_bytes_v2(stmt))


def decode_key_rotation_statement_v2(data: bytes) -> KeyRotationStatementV2:
    def run() -> KeyRotationStatementV2:
        check_v2_wire_size(data, "rotation statement", "MAX_KEY_ROTATION_STATEMENT_BYTES_V2",
                           MAX_KEY_ROTATION_STATEMENT_BYTES_V2)
        obj = _v2json.check_wire_json(data, ("previous_statement_hash",))
        require_fields(obj, KEY_ROTATION_V2_FIELDS)
        stmt = _stmt_from_obj(obj, KEY_ROTATION_V2_FIELDS)
        validate_key_rotation_statement_v2(stmt, True)
        return stmt

    return _run(V2ErrorClass.MALFORMED, run)


def encode_key_rotation_statement_v2(stmt: KeyRotationStatementV2) -> bytes:
    validate_key_rotation_statement_v2(stmt, True)
    return canonical({
        **_signable_dict(stmt),
        "new_signature": key_dict(stmt.new_signature),
        "old_signature": key_dict(stmt.old_signature),
    })


def sign_key_rotation_statement_v2(stmt: KeyRotationStatementV2, old_key: HybridPrivateKey,
                                   new_key: HybridPrivateKey) -> KeyRotationStatementV2:
    """Go ``SignKeyRotationStatementV2``: the old key signs 0x0004 and the new
    key signs 0x0009 over the same body. Callers still authenticate the
    current key and validate rotation-chain state."""
    return sign_key_rotation_statement_v2_with_signers(background(), stmt, _as_signer(old_key), _as_signer(new_key))


def sign_key_rotation_statement_v2_with_signers(ctx: Context, stmt: KeyRotationStatementV2, old_signer: SignerV2,
                                                new_signer: SignerV2) -> KeyRotationStatementV2:
    """Go ``SignKeyRotationStatementV2WithSigners``."""
    validate_key_rotation_statement_v2(stmt, False)
    try:
        old_pub = signer_public_key_v2(old_signer)
    except V2SigningError as exc:
        raise V2SigningError(f"old rotation key: {exc}") from exc
    try:
        new_pub = signer_public_key_v2(new_signer)
    except V2SigningError as exc:
        raise V2SigningError(f"new rotation key: {exc}") from exc
    if not equal_public_keys(old_pub, stmt.old_key) or not equal_public_keys(new_pub, stmt.new_key):
        raise V2SigningError("rotation private keys do not match the statement keys")
    signable = key_rotation_signable_bytes_v2(stmt)
    old_signature = sign_v2_statement_with_signer(ctx, KEY_ROTATION_AUTHORIZATION, signable, old_signer, old_pub)
    new_signature = sign_v2_statement_with_signer(ctx, KEY_ROTATION_PROOF_OF_POSSESSION, signable, new_signer, new_pub)
    return replace(stmt, previous_statement_hash=bytes(stmt.previous_statement_hash),
                   old_key=clone_public_key(stmt.old_key), new_key=clone_public_key(stmt.new_key),
                   old_signature=old_signature, new_signature=new_signature)


def verify_key_rotation_statement_v2(stmt: KeyRotationStatementV2, state: KeyRotationV2State, now_unix: int,
                                     future_skew: int) -> None:
    """Signatures and linkage against caller-authenticated state; does not accept."""
    _run(V2ErrorClass.MALFORMED, lambda: validate_key_rotation_statement_v2(stmt, True))
    cfg = V2ErrorClass.CONFIGURATION_INVALID
    try:
        current_id = key_id_v2(state.current_key)
    except ValueError as exc:
        raise V2Error(cfg, f"caller state current key: {exc}") from exc
    if (type(state.sequence) is not int or type(state.recovery_epoch) is not int or state.sequence < 0
            or state.sequence >= MAX_SAFE_INTEGER or not (0 < state.recovery_epoch <= MAX_SAFE_INTEGER)
            or not isinstance(state.head_hash, (bytes, bytearray)) or len(state.head_hash) != 48):
        raise V2Error(cfg, "caller rotation state is invalid")
    if state.sequence == 0 and bytes(state.head_hash) != ZERO_HASH:
        raise V2Error(cfg, "caller genesis state must have a zero head hash")
    if state.sequence > 0 and bytes(state.head_hash) == ZERO_HASH:
        raise V2Error(cfg, "caller non-genesis state must have a linked head hash")
    if not state.used_key_ids:
        raise V2Error(cfg, "caller state must include retained used key IDs")
    used = set()
    for key_id in state.used_key_ids:
        if not valid_v2_id(key_id):
            raise V2Error(cfg, "caller state contains an invalid used key ID")
        if key_id in used:
            raise V2Error(cfg, "caller state contains duplicate used key IDs")
        used.add(key_id)
    if current_id not in used:
        raise V2Error(cfg, "caller used-key history does not contain the current key")
    if stmt.new_key_id in used:
        raise V2Error(V2ErrorClass.ROTATION_KEY_REUSED, "rotation replacement key was already used by this authority")
    if (type(now_unix) is not int or type(future_skew) is not int or future_skew < 0
            or not (-MAX_SAFE_INTEGER <= now_unix <= MAX_SAFE_INTEGER) or future_skew > MAX_SAFE_INTEGER):
        raise V2Error(cfg, "rotation verification clock inputs are outside safe bounds")
    if now_unix > MAX_SAFE_INTEGER - future_skew:
        future_skew = MAX_SAFE_INTEGER - now_unix
    if (
        not equal_public_keys(stmt.old_key, state.current_key) or stmt.authority_id != state.authority_id
        or stmt.recovery_epoch != state.recovery_epoch or stmt.role != state.role
        or stmt.sequence != state.sequence + 1 or bytes(stmt.previous_statement_hash) != bytes(state.head_hash)
    ):
        raise V2Error(V2ErrorClass.ROTATION_STATE_MISMATCH,
                      "rotation statement does not extend the caller-authenticated authority state")
    if stmt.issued_at > now_unix + future_skew or stmt.not_before > now_unix + future_skew:
        raise V2Error(V2ErrorClass.ROTATION_FUTURE_DATED, "rotation statement is future-dated")
    signable = key_rotation_signable_bytes_v2(stmt)
    verify_v2_statement(KEY_ROTATION_AUTHORIZATION, signable, stmt.old_signature, state.current_key)
    verify_v2_statement(KEY_ROTATION_PROOF_OF_POSSESSION, signable, stmt.new_signature, stmt.new_key)


def new_key_rotation_v2_journal(authority_id: str, recovery_epoch: int, role: str, genesis_key: HybridPublicKey) -> KeyRotationV2Journal:
    cfg = V2ErrorClass.CONFIGURATION_INVALID
    try:
        genesis_id = key_id_v2(genesis_key)
    except ValueError as exc:
        raise V2Error(cfg, f"rotation genesis key: {exc}") from exc
    if len(authority_id) != 32 or not lower_hex_string(authority_id) or not (0 < recovery_epoch <= MAX_SAFE_INTEGER):
        raise V2Error(cfg, "rotation authority or recovery epoch is invalid")
    if role not in ROTATION_ROLES:
        raise V2Error(cfg, "rotation role is invalid")
    return KeyRotationV2Journal(state=KeyRotationV2State(
        authority_id=authority_id, recovery_epoch=recovery_epoch, role=role, sequence=0,
        head_hash=ZERO_HASH, current_key=copy.deepcopy(genesis_key), used_key_ids=[genesis_id],
    ))


def accept_key_rotation_statement_v2(stmt: KeyRotationStatementV2, journal: KeyRotationV2Journal, now_unix: int,
                                     future_skew: int) -> tuple[KeyRotationV2Journal, WitnessEntryV2Result]:
    """AcceptRotation (SPEC-v2 §5.4). Returns (journal, APPENDED|REPLAY).

    A validly signed different body at an accepted sequence raises
    KeyRotationForkError whose ``journal`` attribute is the frozen journal
    the caller must persist; every other error leaves the journal unchanged.
    """
    _run(V2ErrorClass.MALFORMED, lambda: validate_key_rotation_statement_v2(stmt, True))
    if len(journal.accepted) != journal.state.sequence:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "rotation journal accepted history does not match its sequence")
    if journal.frozen:
        raise KeyRotationFrozenError(f"key rotation authority is frozen: authority {journal.state.authority_id} requires recovery")
    state = journal.state
    if stmt.authority_id != state.authority_id or stmt.recovery_epoch != state.recovery_epoch or stmt.role != state.role:
        raise V2Error(V2ErrorClass.ROTATION_STATE_MISMATCH,
                      "rotation statement authority, recovery epoch, or role does not match caller state")
    if stmt.sequence <= state.sequence:
        accepted = journal.accepted[stmt.sequence - 1]
        if accepted.sequence != stmt.sequence or not equal_public_keys(stmt.old_key, accepted.old_key):
            raise V2Error(V2ErrorClass.ROTATION_STATE_MISMATCH,
                          f"rotation statement old key does not match the key accepted at sequence {stmt.sequence}")
        signable = _run(V2ErrorClass.MALFORMED, lambda: key_rotation_signable_bytes_v2(stmt))
        verify_v2_statement(KEY_ROTATION_AUTHORIZATION, signable, stmt.old_signature, accepted.old_key)
        verify_v2_statement(KEY_ROTATION_PROOF_OF_POSSESSION, signable, stmt.new_signature, stmt.new_key)
        digest = _run(V2ErrorClass.MALFORMED, lambda: statement_body_digest_v2(KEY_ROTATION_AUTHORIZATION, signable))
        if digest == accepted.body_digest:
            return journal, WitnessEntryV2Result.REPLAY
        frozen = copy.deepcopy(journal)
        frozen.frozen = True
        error = KeyRotationForkError(
            f"key rotation fork at sequence {stmt.sequence} for authority {state.authority_id}")
        error.journal = frozen
        raise error
    verify_key_rotation_statement_v2(stmt, state, now_unix, future_skew)
    digest = _run(V2ErrorClass.MALFORMED, lambda: key_rotation_statement_v2_digest(stmt))
    nxt = copy.deepcopy(journal)
    nxt.accepted.append(KeyRotationV2AcceptedEntry(stmt.sequence, digest, copy.deepcopy(stmt.old_key)))
    nxt.state.sequence = stmt.sequence
    nxt.state.head_hash = digest
    nxt.state.current_key = copy.deepcopy(stmt.new_key)
    nxt.state.used_key_ids.append(stmt.new_key_id)
    return nxt, WitnessEntryV2Result.APPENDED


def recover_key_rotation_v2(journal: KeyRotationV2Journal, new_recovery_epoch: int,
                            new_genesis_key: HybridPublicKey) -> KeyRotationV2Journal:
    invalid = V2ErrorClass.ROTATION_RECOVERY_INVALID
    try:
        new_id = key_id_v2(new_genesis_key)
    except ValueError as exc:
        raise V2Error(invalid, f"recovery genesis key: {exc}") from exc
    if new_recovery_epoch <= journal.state.recovery_epoch or new_recovery_epoch > MAX_SAFE_INTEGER:
        raise V2Error(invalid, "rotation recovery must increase the recovery epoch")
    if new_id in journal.state.used_key_ids:
        raise V2Error(invalid, "rotation recovery cannot anchor a previously used key")
    nxt = copy.deepcopy(journal)
    nxt.state.recovery_epoch = new_recovery_epoch
    nxt.state.sequence = 0
    nxt.state.head_hash = ZERO_HASH
    nxt.state.current_key = copy.deepcopy(new_genesis_key)
    nxt.state.used_key_ids.append(new_id)
    nxt.accepted = []
    nxt.frozen = False
    return nxt

