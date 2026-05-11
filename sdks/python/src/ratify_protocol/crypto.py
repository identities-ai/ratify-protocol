"""Ratify Protocol v1 — hybrid (Ed25519 + ML-DSA-65) crypto primitives.

Uses:
    cryptography (PyCA)    audited Ed25519 from the Python Cryptographic Authority
    pqcrypto               PQClean-based ML-DSA-65 (FIPS 204)

Every sign produces BOTH component signatures. Every verify checks BOTH;
either failure fails the whole signature.

Signature determinism note
--------------------------
pqcrypto's ML-DSA-65 sign is randomized by default (two calls produce
different bytes for the same input). This does NOT affect interop:

    - Python-produced signatures are valid and verify in Go / TS.
    - Go-produced deterministic signatures verify here.

Byte-identical reproduction of Go fixtures' signature bytes is NOT a
conformance requirement (see SDKS.md §4). The canonical SIGNABLE bytes
must match; the signature bytes produced by any implementation are
interchangeable in verification.
"""
from __future__ import annotations

import hmac as stdlib_hmac
import os
from hashlib import sha256
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from pqcrypto.sign import ml_dsa_65

from .canonical import canonical_json, hex_encode
from .types import (
    AgentIdentity,
    DelegationCert,
    HumanRoot,
    HybridPrivateKey,
    HybridPublicKey,
    HybridSignature,
    KeyRotationStatement,
    PolicyVerdict,
    ProofBundle,
    ReceiptPartySignature,
    RevocationList,
    RevocationPush,
    SessionToken,
    TransactionReceipt,
    VerificationReceipt,
    VerifierContext,
    VerifyResult,
    WitnessEntry,
)


# ----------------------------------------------------------------------
# ID derivation
# ----------------------------------------------------------------------

def derive_id(pub: HybridPublicKey) -> str:
    """hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])."""
    h = sha256()
    h.update(pub.ed25519)
    h.update(pub.ml_dsa_65)
    return hex_encode(h.digest()[:16])


# ----------------------------------------------------------------------
# Keypair generation
# ----------------------------------------------------------------------

def generate_hybrid_keypair() -> tuple[HybridPublicKey, HybridPrivateKey]:
    """Fresh hybrid keypair from OS randomness. Two independent 32-byte seeds."""
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
    ed_seed = ed_priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    ed_pub_bytes = ed_priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    ml_pub, ml_secret = ml_dsa_65.generate_keypair()

    return (
        HybridPublicKey(ed25519=ed_pub_bytes, ml_dsa_65=ml_pub),
        HybridPrivateKey(ed25519=ed_seed, ml_dsa_65=ml_secret),
    )


def hybrid_keypair_from_seeds(
    ed_seed: bytes,
    ml_seed: bytes,
) -> tuple[HybridPublicKey, HybridPrivateKey]:
    """Derive a hybrid keypair deterministically from two 32-byte seeds.

    NOTE: pqcrypto's ml_dsa_65 module does not expose seed-based keygen
    through its public API — it calls PQClean's crypto_sign_keypair which
    reads from the OS RNG. This function is therefore NOT truly deterministic
    on the ML-DSA side in Python. For test-vector regeneration use the Go
    reference; this SDK's responsibility is VERIFICATION of existing fixtures,
    not regeneration.
    """
    if len(ed_seed) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(ed_seed)}")
    if len(ml_seed) != 32:
        raise ValueError(f"ML-DSA-65 seed must be 32 bytes, got {len(ml_seed)}")

    ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ed_pub_bytes = ed_priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # pqcrypto does not expose seed-based ML-DSA keygen; fall back to
    # OS-randomness keygen. The result will differ between invocations.
    ml_pub, ml_secret = ml_dsa_65.generate_keypair()

    return (
        HybridPublicKey(ed25519=ed_pub_bytes, ml_dsa_65=ml_pub),
        HybridPrivateKey(ed25519=ed_seed, ml_dsa_65=ml_secret),
    )


def generate_human_root() -> tuple[HumanRoot, HybridPrivateKey]:
    """Fresh HumanRoot identity."""
    import time
    pub, priv = generate_hybrid_keypair()
    return HumanRoot(
        id=derive_id(pub),
        public_key=pub,
        created_at=int(time.time()),
    ), priv


def generate_agent(name: str, agent_type: str) -> tuple[AgentIdentity, HybridPrivateKey]:
    """Fresh AgentIdentity."""
    import time
    pub, priv = generate_hybrid_keypair()
    return AgentIdentity(
        id=derive_id(pub),
        public_key=pub,
        name=name,
        agent_type=agent_type,
        created_at=int(time.time()),
    ), priv


# ----------------------------------------------------------------------
# Canonical signing bytes — MUST match Go reference byte-for-byte.
# ----------------------------------------------------------------------

def delegation_sign_bytes(cert: DelegationCert) -> bytes:
    """Canonical bytes signed to produce DelegationCert.signature."""
    # Signable subset = all cert fields except `signature`. canonical_json
    # sorts keys lex-order; we construct the dict for clarity.
    # Constraints are serialized as [] when empty — never absent — so bytes
    # are deterministic across issuers. Each Constraint is flattened via
    # to_canonical_dict() to match Go's omitempty semantics.
    constraints = cert.constraints or []
    signable = {
        "cert_id": cert.cert_id,
        "constraints": [c.to_canonical_dict() for c in constraints],
        "expires_at": cert.expires_at,
        "issued_at": cert.issued_at,
        "issuer_id": cert.issuer_id,
        "issuer_pub_key": cert.issuer_pub_key,
        "scope": cert.scope,
        "subject_id": cert.subject_id,
        "subject_pub_key": cert.subject_pub_key,
        "version": cert.version,
    }
    return canonical_json(signable)


def challenge_sign_bytes(
    challenge: bytes,
    ts: int,
    session_context: bytes = b"",
    stream_id: bytes = b"",
    stream_seq: int = 0,
) -> bytes:
    """Canonical bytes signed to produce ProofBundle.challenge_sig.

    NOT JSON. Raw binary:

        challenge || big-endian uint64(ts)
          || [optional 32-byte session_context]
          || [optional 32-byte stream_id || big-endian int64(stream_seq)]

    Order matches the Go reference so the signable bytes are well-defined
    across the four allowed length combinations (40 / 72 / 80 / 112 bytes for
    a 32-byte challenge).
    """
    out = challenge + ts.to_bytes(8, byteorder="big", signed=False) + session_context
    if stream_id:
        out += stream_id + stream_seq.to_bytes(8, byteorder="big", signed=False)
    return out


def revocation_sign_bytes(lst: RevocationList) -> bytes:
    """Canonical bytes signed to produce RevocationList.signature."""
    signable = {
        "issuer_id": lst.issuer_id,
        "revoked_certs": lst.revoked_certs,
        "updated_at": lst.updated_at,
    }
    return canonical_json(signable)


def key_rotation_sign_bytes(stmt: KeyRotationStatement) -> bytes:
    """Canonical bytes signed by both old and new keys in KeyRotationStatement."""
    signable = {
        "new_id": stmt.new_id,
        "new_pub_key": stmt.new_pub_key,
        "old_id": stmt.old_id,
        "old_pub_key": stmt.old_pub_key,
        "reason": stmt.reason,
        "rotated_at": stmt.rotated_at,
        "version": stmt.version,
    }
    return canonical_json(signable)


# ----------------------------------------------------------------------
# Hybrid sign / verify
# ----------------------------------------------------------------------

def sign_both(msg: bytes, priv: HybridPrivateKey) -> HybridSignature:
    """Produce a hybrid signature over `msg` with both component private keys."""
    ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv.ed25519)
    ed_sig = ed_priv.sign(msg)

    # pqcrypto's ml_dsa_65.sign is randomized by default. Output verifies
    # cross-implementation regardless.
    ml_sig = ml_dsa_65.sign(priv.ml_dsa_65, msg)

    return HybridSignature(ed25519=ed_sig, ml_dsa_65=ml_sig)


def verify_both(
    msg: bytes,
    sig: HybridSignature,
    pub: HybridPublicKey,
) -> Optional[str]:
    """Verify both components. Returns None on success, error string on failure.

    Error strings match the Go reference for cross-language compatibility.
    """
    if len(pub.ed25519) != 32:
        return f"Ed25519 public key wrong length: {len(pub.ed25519)}"
    if len(pub.ml_dsa_65) != 1952:
        return f"ML-DSA-65 public key wrong length: {len(pub.ml_dsa_65)}"
    if len(sig.ed25519) != 64:
        return f"Ed25519 signature wrong length: {len(sig.ed25519)}"
    if len(sig.ml_dsa_65) != 3309:
        return f"ML-DSA-65 signature wrong length: {len(sig.ml_dsa_65)}"

    try:
        ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(pub.ed25519)
        ed_pub.verify(sig.ed25519, msg)
    except Exception:
        return "Ed25519 signature invalid"

    try:
        ok = ml_dsa_65.verify(pub.ml_dsa_65, msg, sig.ml_dsa_65)
    except Exception:
        return "ML-DSA-65 signature invalid"
    if not ok:
        return "ML-DSA-65 signature invalid"

    return None


# ----------------------------------------------------------------------
# High-level sign/verify helpers
# ----------------------------------------------------------------------

def issue_delegation(cert: DelegationCert, issuer_priv: HybridPrivateKey) -> None:
    """Populate cert.signature with a hybrid signature over the canonical bytes."""
    cert.signature = sign_both(delegation_sign_bytes(cert), issuer_priv)


def verify_delegation_signature(cert: DelegationCert) -> bool:
    """True iff both components of cert.signature verify against issuer pubkey."""
    return verify_delegation_signature_e(cert) is None


def verify_delegation_signature_e(cert: DelegationCert) -> Optional[str]:
    """Return None on success or a Go-compatible diagnostic string on failure."""
    return verify_both(delegation_sign_bytes(cert), cert.signature, cert.issuer_pub_key)


def sign_challenge(
    challenge: bytes,
    ts: int,
    agent_priv: HybridPrivateKey,
    session_context: bytes = b"",
    stream_id: bytes = b"",
    stream_seq: int = 0,
) -> HybridSignature:
    if session_context and len(session_context) != 32:
        raise ValueError(f"session_context must be 32 bytes, got {len(session_context)}")
    if stream_id and len(stream_id) != 32:
        raise ValueError(f"stream_id must be 32 bytes, got {len(stream_id)}")
    if stream_id and stream_seq < 1:
        raise ValueError(f"stream_seq must be >=1, got {stream_seq}")
    return sign_both(
        challenge_sign_bytes(challenge, ts, session_context, stream_id, stream_seq),
        agent_priv,
    )


def verify_challenge_signature(
    challenge: bytes,
    ts: int,
    sig: HybridSignature,
    agent_pub: HybridPublicKey,
    session_context: bytes = b"",
    stream_id: bytes = b"",
    stream_seq: int = 0,
) -> bool:
    return verify_challenge_signature_e(
        challenge, ts, sig, agent_pub, session_context, stream_id, stream_seq
    ) is None


def verify_challenge_signature_e(
    challenge: bytes,
    ts: int,
    sig: HybridSignature,
    agent_pub: HybridPublicKey,
    session_context: bytes = b"",
    stream_id: bytes = b"",
    stream_seq: int = 0,
) -> Optional[str]:
    if session_context and len(session_context) != 32:
        return f"session_context must be 32 bytes, got {len(session_context)}"
    if stream_id and len(stream_id) != 32:
        return f"stream_id must be 32 bytes, got {len(stream_id)}"
    if stream_id and stream_seq < 1:
        return f"stream_seq must be >=1, got {stream_seq}"
    return verify_both(
        challenge_sign_bytes(challenge, ts, session_context, stream_id, stream_seq),
        sig,
        agent_pub,
    )


def issue_revocation_list(lst: RevocationList, issuer_priv: HybridPrivateKey) -> None:
    lst.signature = sign_both(revocation_sign_bytes(lst), issuer_priv)


def verify_revocation_list(lst: RevocationList, issuer_pub: HybridPublicKey) -> bool:
    return verify_both(revocation_sign_bytes(lst), lst.signature, issuer_pub) is None


def revocation_push_sign_bytes(push: RevocationPush) -> bytes:
    """Canonical bytes signed to produce RevocationPush.signature."""
    signable = {
        "entries": push.entries or [],
        "issuer_id": push.issuer_id,
        "pushed_at": push.pushed_at,
        "seq_no": push.seq_no,
    }
    return canonical_json(signable)


def issue_revocation_push(push: RevocationPush, issuer_priv: HybridPrivateKey) -> None:
    """Populate push.signature with a hybrid signature over the canonical bytes."""
    push.signature = sign_both(revocation_push_sign_bytes(push), issuer_priv)


def verify_revocation_push(push: RevocationPush, issuer_pub: HybridPublicKey) -> bool:
    """True iff both components of push.signature verify against issuer pubkey."""
    return verify_both(revocation_push_sign_bytes(push), push.signature, issuer_pub) is None


def witness_entry_sign_bytes(entry: WitnessEntry) -> bytes:
    """Canonical bytes signed to produce WitnessEntry.signature."""
    signable = {
        "entry_data": entry.entry_data,
        "prev_hash": entry.prev_hash,
        "timestamp": entry.timestamp,
        "witness_id": entry.witness_id,
    }
    return canonical_json(signable)


def issue_witness_entry(entry: WitnessEntry, witness_priv: HybridPrivateKey) -> None:
    """Populate entry.signature with a hybrid signature over the canonical bytes."""
    entry.signature = sign_both(witness_entry_sign_bytes(entry), witness_priv)


def verify_witness_entry(entry: WitnessEntry, witness_pub: HybridPublicKey) -> bool:
    """True iff both components of entry.signature verify against witness pubkey."""
    return verify_both(witness_entry_sign_bytes(entry), entry.signature, witness_pub) is None


def issue_key_rotation_statement(
    stmt: KeyRotationStatement,
    old_priv: HybridPrivateKey,
    new_priv: HybridPrivateKey,
) -> None:
    bytes_to_sign = key_rotation_sign_bytes(stmt)
    stmt.signature_old = sign_both(bytes_to_sign, old_priv)
    stmt.signature_new = sign_both(bytes_to_sign, new_priv)


def verify_key_rotation_statement(stmt: KeyRotationStatement) -> bool:
    return verify_key_rotation_statement_e(stmt) is None


def verify_key_rotation_statement_e(stmt: KeyRotationStatement) -> Optional[str]:
    if stmt.version != 1:
        return f"version_mismatch: unsupported version {stmt.version}"
    if stmt.old_id != derive_id(stmt.old_pub_key):
        return "old_id does not match old_pub_key"
    if stmt.new_id != derive_id(stmt.new_pub_key):
        return "new_id does not match new_pub_key"
    if stmt.old_id == stmt.new_id:
        return "old_id and new_id must differ"
    if stmt.reason not in {"routine", "compromise_suspected", "device_lost", "recovery", "other"}:
        return f"unknown key rotation reason: {stmt.reason}"
    bytes_to_verify = key_rotation_sign_bytes(stmt)
    old_err = verify_both(bytes_to_verify, stmt.signature_old, stmt.old_pub_key)
    if old_err is not None:
        return f"old signature invalid: {old_err}"
    new_err = verify_both(bytes_to_verify, stmt.signature_new, stmt.new_pub_key)
    if new_err is not None:
        return f"new signature invalid: {new_err}"
    return None


def generate_challenge() -> bytes:
    """32 cryptographically random bytes."""
    return os.urandom(32)


# ----------------------------------------------------------------------
# v1.1 transaction receipt
# ----------------------------------------------------------------------

def transaction_receipt_sign_bytes(receipt: TransactionReceipt) -> bytes:
    """Canonical bytes that every party signs to bind the receipt.

    Parties are sorted lex by party_id. Each party entry includes only
    {agent_id, agent_pub_key, party_id, role} — proof_bundle is excluded
    (verified independently). party_signatures are also excluded (signatures
    cannot cover themselves).
    """
    parties_sorted = sorted(receipt.parties, key=lambda p: p.party_id)
    parties_signable = [
        {
            "agent_id": p.agent_id,
            "agent_pub_key": p.agent_pub_key,
            "party_id": p.party_id,
            "role": p.role,
        }
        for p in parties_sorted
    ]
    signable = {
        "created_at": receipt.created_at,
        "parties": parties_signable,
        "terms_canonical_json": receipt.terms_canonical_json,
        "terms_schema_uri": receipt.terms_schema_uri,
        "transaction_id": receipt.transaction_id,
        "version": receipt.version,
    }
    return canonical_json(signable)


def sign_transaction_receipt_party(
    receipt: TransactionReceipt,
    party_id: str,
    agent_priv: HybridPrivateKey,
) -> ReceiptPartySignature:
    """Produce a party's hybrid signature over the receipt's canonical signable."""
    data = transaction_receipt_sign_bytes(receipt)
    sig = sign_both(data, agent_priv)
    return ReceiptPartySignature(party_id=party_id, signature=sig)


# ----------------------------------------------------------------------
# v1.1 session cert cache (ROADMAP 2.3)
# ----------------------------------------------------------------------

def chain_hash(chain: list[DelegationCert]) -> bytes:
    """32-byte SHA-256 of the concatenated delegation_sign_bytes of each cert.

    Used as the stable chain identity inside SessionToken — a cert rotation
    changes chain_hash, invalidating every token issued against the old chain.
    """
    h = sha256()
    for cert in chain:
        h.update(delegation_sign_bytes(cert))
    return h.digest()


def session_token_sign_bytes(token: SessionToken) -> bytes:
    """Canonical MAC-input bytes for a SessionToken. The MAC itself is
    excluded from the signable (a MAC cannot cover itself)."""
    signable = {
        "agent_id": token.agent_id,
        "agent_pub_key": token.agent_pub_key,
        "chain_hash": token.chain_hash,
        "granted_scope": sorted(token.granted_scope),
        "human_id": token.human_id,
        "issued_at": token.issued_at,
        "session_id": token.session_id,
        "valid_until": token.valid_until,
        "version": token.version,
    }
    return canonical_json(signable)


def issue_session_token(
    bundle: ProofBundle,
    result: VerifyResult,
    session_id: str,
    issued_at: int,
    valid_until: int,
    session_secret: bytes,
) -> SessionToken:
    """Issue a SessionToken from a previously verified bundle's result.

    Callers MUST only invoke this after verify_bundle(bundle, opts) returned
    valid=True. session_secret MUST be a cryptographically random secret
    known only to the verifier.
    """
    if not session_secret:
        raise ValueError("session_secret must not be empty")
    if not session_id:
        raise ValueError("session_id must not be empty")
    if valid_until <= issued_at:
        raise ValueError("valid_until must be strictly after issued_at")
    token = SessionToken(
        version=1,
        session_id=session_id,
        agent_id=result.agent_id,
        agent_pub_key=bundle.agent_pub_key,
        human_id=result.human_id,
        granted_scope=sorted(result.granted_scope or []),
        issued_at=issued_at,
        valid_until=valid_until,
        chain_hash=chain_hash(bundle.delegations),
        mac=b"",
    )
    token.mac = stdlib_hmac.new(
        session_secret, session_token_sign_bytes(token), sha256
    ).digest()
    return token


def verify_session_token_e(
    token: SessionToken,
    session_secret: bytes,
    now: int,
) -> Optional[str]:
    """Check a SessionToken's HMAC against session_secret and its validity
    window against now (unix seconds). Returns None on success, an error
    string on failure."""
    if not session_secret:
        return "session_secret must not be empty"
    if token.version != 1:
        return f"version_mismatch: unsupported version {token.version}"
    if len(token.chain_hash) != 32:
        return f"chain_hash must be 32 bytes, got {len(token.chain_hash)}"
    if len(token.mac) != 32:
        return f"mac must be 32 bytes, got {len(token.mac)}"
    want = stdlib_hmac.new(
        session_secret, session_token_sign_bytes(token), sha256
    ).digest()
    if not stdlib_hmac.compare_digest(want, token.mac):
        return "session_token MAC invalid"
    if now < token.issued_at:
        return "session_token not yet valid"
    if now > token.valid_until:
        return "session_token expired"
    return None


def verify_session_token(
    token: SessionToken, session_secret: bytes, now: int
) -> bool:
    return verify_session_token_e(token, session_secret, now) is None


# ----------------------------------------------------------------------
# SPEC §17.5 — VerificationReceipt
# ----------------------------------------------------------------------

def bundle_hash(bundle: ProofBundle) -> bytes:
    """SHA-256 of a fixed-shape canonical form of a ProofBundle (SPEC §17.5).

    Cross-SDK byte equivalence requires every field to be present (no
    omitempty), keys alphabetical at every level, and empty bytes / empty
    lists / zero ints serialized as ``""`` / ``[]`` / ``0``. Every reference
    SDK (Go, TypeScript, Python, Rust) produces the same 32-byte digest for
    the same logical bundle. Verified against
    ``testvectors/v1/cross_sdk_vectors.json``.
    """
    delegations = []
    for d in bundle.delegations:
        delegations.append({
            "cert_id": d.cert_id,
            "constraints": d.constraints or [],
            "expires_at": d.expires_at,
            "issued_at": d.issued_at,
            "issuer_id": d.issuer_id,
            "issuer_pub_key": {
                "ed25519": d.issuer_pub_key.ed25519,
                "ml_dsa_65": d.issuer_pub_key.ml_dsa_65,
            },
            "scope": d.scope,
            "signature": {
                "ed25519": d.signature.ed25519,
                "ml_dsa_65": d.signature.ml_dsa_65,
            },
            "subject_id": d.subject_id,
            "subject_pub_key": {
                "ed25519": d.subject_pub_key.ed25519,
                "ml_dsa_65": d.subject_pub_key.ml_dsa_65,
            },
            "version": d.version,
        })
    signable = {
        "agent_id": bundle.agent_id,
        "agent_pub_key": {
            "ed25519": bundle.agent_pub_key.ed25519,
            "ml_dsa_65": bundle.agent_pub_key.ml_dsa_65,
        },
        "challenge": bundle.challenge or b"",
        "challenge_at": bundle.challenge_at,
        "challenge_sig": {
            "ed25519": bundle.challenge_sig.ed25519,
            "ml_dsa_65": bundle.challenge_sig.ml_dsa_65,
        },
        "delegations": delegations,
        "session_context": bundle.session_context or b"",
        "stream_id": bundle.stream_id or b"",
        "stream_seq": bundle.stream_seq or 0,
    }
    return sha256(canonical_json(signable)).digest()


def verification_receipt_sign_bytes(r: VerificationReceipt) -> bytes:
    """Canonical bytes signed to produce VerificationReceipt.signature."""
    scope = sorted(r.granted_scope) if r.granted_scope else []
    signable: dict = {
        "bundle_hash": r.bundle_hash,
        "decision": r.decision,
        "prev_hash": r.prev_hash,
        "verified_at": r.verified_at,
        "verifier_id": r.verifier_id,
        "verifier_pub": {
            "ed25519": r.verifier_pub.ed25519,
            "ml_dsa_65": r.verifier_pub.ml_dsa_65,
        },
        "version": r.version,
    }
    if r.agent_id:
        signable["agent_id"] = r.agent_id
    if r.error_reason:
        signable["error_reason"] = r.error_reason
    if scope:
        signable["granted_scope"] = scope
    if r.human_id:
        signable["human_id"] = r.human_id
    return canonical_json(signable)


def issue_verification_receipt(
    bundle: ProofBundle,
    result: VerifyResult,
    verifier_id: str,
    verifier_pub: HybridPublicKey,
    verifier_priv: HybridPrivateKey,
    prev_hash: Optional[bytes],
    verified_at: int,
) -> VerificationReceipt:
    """Construct and hybrid-sign a VerificationReceipt over a (bundle,
    result, prev) triple (SPEC §17.5). ``prev_hash`` is 32 zero bytes for
    genesis.
    """
    prev = prev_hash if prev_hash is not None else b"\x00" * 32
    if len(prev) != 32:
        raise ValueError(f"prev_hash must be 32 bytes, got {len(prev)}")
    r = VerificationReceipt(
        version=1,
        verifier_id=verifier_id,
        verifier_pub=verifier_pub,
        bundle_hash=bundle_hash(bundle),
        decision=result.identity_status,
        human_id=result.human_id,
        agent_id=result.agent_id,
        granted_scope=list(result.granted_scope),
        error_reason=result.error_reason,
        verified_at=verified_at,
        prev_hash=prev,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    r.signature = sign_both(verification_receipt_sign_bytes(r), verifier_priv)
    return r


def verify_verification_receipt(r: VerificationReceipt) -> Optional[str]:
    """Verify the hybrid signature on a VerificationReceipt. Returns None
    iff both component signatures verify; otherwise an error string.
    """
    if r.version != 1:
        return f"unsupported version {r.version}"
    if len(r.bundle_hash) != 32:
        return f"bundle_hash must be 32 bytes, got {len(r.bundle_hash)}"
    if len(r.prev_hash) != 32:
        return f"prev_hash must be 32 bytes, got {len(r.prev_hash)}"
    return verify_both(
        verification_receipt_sign_bytes(r), r.signature, r.verifier_pub
    )


def receipt_hash(r: VerificationReceipt) -> bytes:
    """SHA-256 of a receipt's canonical signable bytes. Use as ``prev_hash``
    for the next receipt in the chain.
    """
    return sha256(verification_receipt_sign_bytes(r)).digest()


# ----------------------------------------------------------------------
# SPEC §17.6 — PolicyVerdict
# ----------------------------------------------------------------------

def verifier_context_hash(ctx: Optional[VerifierContext]) -> bytes:
    """SHA-256 of the canonical-byte representation of the policy-relevant
    subset of a VerifierContext (SPEC §17.6). The ``invocations_in_window``
    callback is excluded — closures don't serialize.
    """
    c = ctx if ctx is not None else VerifierContext()
    # has_* booleans derived from field presence so the canonical hash matches
    # the Go reference's explicit Has* fields.
    signable = {
        "current_alt_m": c.current_alt_m if c.current_alt_m is not None else 0.0,
        "current_lat": c.current_lat if c.current_lat is not None else 0.0,
        "current_lon": c.current_lon if c.current_lon is not None else 0.0,
        "current_speed_mps": (
            c.current_speed_mps if c.current_speed_mps is not None else 0.0
        ),
        "has_amount": c.requested_amount is not None,
        "has_location": c.current_lat is not None and c.current_lon is not None,
        "has_speed": c.current_speed_mps is not None,
        "requested_amount": (
            c.requested_amount if c.requested_amount is not None else 0.0
        ),
        "requested_currency": c.requested_currency or "",
    }
    return sha256(canonical_json(signable)).digest()


def policy_verdict_sign_bytes(v: PolicyVerdict) -> bytes:
    """Canonical bytes over which a PolicyVerdict's MAC is computed."""
    signable = {
        "agent_id": v.agent_id,
        "allow": v.allow,
        "context_hash": v.context_hash,
        "issued_at": v.issued_at,
        "scope": v.scope,
        "valid_until": v.valid_until,
        "verdict_id": v.verdict_id,
        "version": v.version,
    }
    return canonical_json(signable)


def issue_policy_verdict(
    verdict_id: str,
    agent_id: str,
    scope: str,
    allow: bool,
    context_hash: bytes,
    issued_at: int,
    valid_until: int,
    policy_secret: bytes,
) -> PolicyVerdict:
    """Construct and HMAC-bind a PolicyVerdict (SPEC §17.6)."""
    if not policy_secret:
        raise ValueError("policy_secret must not be empty")
    if not verdict_id:
        raise ValueError("verdict_id must not be empty")
    if not agent_id:
        raise ValueError("agent_id must not be empty")
    if not scope:
        raise ValueError("scope must not be empty")
    if len(context_hash) != 32:
        raise ValueError(f"context_hash must be 32 bytes, got {len(context_hash)}")
    if valid_until <= issued_at:
        raise ValueError("valid_until must be strictly after issued_at")
    v = PolicyVerdict(
        version=1,
        verdict_id=verdict_id,
        agent_id=agent_id,
        scope=scope,
        allow=allow,
        context_hash=context_hash,
        issued_at=issued_at,
        valid_until=valid_until,
        mac=b"",
    )
    v.mac = stdlib_hmac.new(
        policy_secret, policy_verdict_sign_bytes(v), sha256
    ).digest()
    return v


def verify_policy_verdict_e(
    v: PolicyVerdict,
    policy_secret: bytes,
    expected_agent_id: str,
    expected_scope: str,
    expected_context_hash: bytes,
    now: int,
) -> Optional[str]:
    """Check a PolicyVerdict's HMAC and validity. Returns None on success
    (cached allow); returns ``"policy_verdict_denied: ..."`` on cached
    deny; any other return value indicates the verdict is unusable.
    """
    if not policy_secret:
        return "policy_secret must not be empty"
    if v.version != 1:
        return f"unsupported version {v.version}"
    if len(v.context_hash) != 32:
        return f"context_hash must be 32 bytes, got {len(v.context_hash)}"
    if len(v.mac) != 32:
        return f"mac must be 32 bytes, got {len(v.mac)}"
    want = stdlib_hmac.new(
        policy_secret, policy_verdict_sign_bytes(v), sha256
    ).digest()
    if not stdlib_hmac.compare_digest(want, v.mac):
        return "policy_verdict MAC invalid"
    if now < v.issued_at:
        return "policy_verdict not yet valid"
    if now > v.valid_until:
        return "policy_verdict expired"
    if v.agent_id != expected_agent_id:
        return "policy_verdict agent_id mismatch"
    if v.scope != expected_scope:
        return "policy_verdict scope mismatch"
    if not stdlib_hmac.compare_digest(v.context_hash, expected_context_hash):
        return "policy_verdict context_hash mismatch"
    if not v.allow:
        return f'policy_verdict_denied: cached deny for scope "{v.scope}"'
    return None
