"""Verify — the core verifier. Mirrors the Go reference verify.go exactly.

v1 uses hybrid signatures (Ed25519 + ML-DSA-65); both component signatures
must verify for any signature check to pass.
"""
from __future__ import annotations

import time
from typing import Optional

from .constraints import evaluate_constraints
from .crypto import (
    transaction_receipt_sign_bytes,
    verify_both,
    verify_challenge_signature_e,
    verify_delegation_signature_e,
    verify_session_token_e,
)
from .scope import SCOPE_IDENTITY_DELEGATE, intersect_scopes
from .types import (
    CHALLENGE_WINDOW_SECONDS,
    ED25519_PUBLIC_KEY_SIZE,
    MAX_DELEGATION_CHAIN_DEPTH,
    MLDSA65_PUBLIC_KEY_SIZE,
    PROTOCOL_VERSION,
    HybridPublicKey,
    HybridSignature,
    ProofBundle,
    SessionToken,
    TransactionReceipt,
    TransactionReceiptResult,
    VerifyOptions,
    VerifyResult,
)


def verify_bundle(bundle: ProofBundle, opts: VerifyOptions = None) -> VerifyResult:
    """Validate a ProofBundle against the Ratify Protocol.

    Check sequence (abridged; see SPEC.md §10 for the authoritative list):
      1. Structural (non-empty chain, depth bound, challenge present, pubkey lens).
      2. Agent binding (bundle's agent_pub_key / agent_id == leaf cert's subject).
      3. Per-cert: version, temporal validity, revocation, hybrid signature, linkage.
      4. Challenge freshness + hybrid signature.
      5. Effective scope (intersection across chain) contains required_scope.
      6. Optional advanced policy (SPEC §17.2) — fail-closed.

    Fail-closed: any single-component signature failure fails the whole check.
    Audit hook (SPEC §17.3) is invoked at the end on every call (success
    AND failure). Provider errors from audit are intentionally swallowed.
    """
    if opts is None:
        opts = VerifyOptions()
    res = _verify_bundle_inner(bundle, opts)
    if opts.audit is not None:
        try:
            opts.audit.log_verification(res, bundle)
        except Exception:
            # Audit MUST NOT alter the verdict. SPEC §17.3.
            pass
    return res


def _verify_bundle_inner(bundle: ProofBundle, opts: VerifyOptions) -> VerifyResult:
    now = opts.now if opts.now is not None else int(time.time())

    # --- Basic structure ---
    if not bundle.delegations:
        return _invalid("no_delegations", "proof bundle contains no delegation certificates")
    if len(bundle.delegations) > MAX_DELEGATION_CHAIN_DEPTH:
        return _invalid("chain_too_deep", "delegation chain exceeds maximum depth")
    if not bundle.challenge:
        return _invalid("no_challenge", "proof bundle contains no challenge")
    if bundle.session_context and len(bundle.session_context) != 32:
        return _invalid(
            "invalid_session_context",
            f"session_context must be 32 bytes, got {len(bundle.session_context)}",
        )
    if opts.session_context and len(opts.session_context) != 32:
        return _invalid(
            "invalid_session_context",
            f"verify option session_context must be 32 bytes, got {len(opts.session_context)}",
        )
    if opts.session_context:
        if not bundle.session_context:
            return _invalid(
                "missing_session_context",
                "verifier requires a session-bound challenge but bundle has no session_context",
            )
        if bundle.session_context != opts.session_context:
            return _invalid(
                "session_context_mismatch",
                "bundle session_context does not match verifier context",
            )
    elif bundle.session_context:
        return _invalid(
            "session_context_unverifiable",
            "bundle has session_context but verifier did not provide one",
        )

    # --- v1.1 stream binding checks (SPEC §5.8, §6.4.2) ---
    if bundle.stream_id and len(bundle.stream_id) != 32:
        return _invalid(
            "invalid_stream_id",
            f"stream_id must be 32 bytes, got {len(bundle.stream_id)}",
        )
    if not bundle.stream_id and bundle.stream_seq != 0:
        return _invalid("invalid_stream_seq", "stream_seq set without stream_id")
    if bundle.stream_id and bundle.stream_seq < 1:
        return _invalid(
            "invalid_stream_seq",
            f"stream_seq must be >=1, got {bundle.stream_seq}",
        )
    if opts.stream is not None:
        if len(opts.stream.stream_id) != 32:
            return _invalid(
                "invalid_stream_id",
                f"verify option stream_id must be 32 bytes, got {len(opts.stream.stream_id)}",
            )
        if not bundle.stream_id:
            return _invalid(
                "missing_stream_context",
                "verifier requires a stream-bound challenge but bundle has no stream_id",
            )
        if bundle.stream_id != opts.stream.stream_id:
            return _invalid(
                "stream_id_mismatch",
                "bundle stream_id does not match verifier stream context",
            )
        expected = opts.stream.last_seen_seq + 1
        if bundle.stream_seq <= opts.stream.last_seen_seq:
            return _invalid(
                "stream_seq_replay",
                f"stream_seq {bundle.stream_seq} already seen "
                f"(last={opts.stream.last_seen_seq})",
            )
        if bundle.stream_seq != expected:
            return _invalid(
                "stream_seq_skip",
                f"stream_seq {bundle.stream_seq} skips expected {expected}",
            )
    elif bundle.stream_id:
        return _invalid(
            "stream_context_unverifiable",
            "bundle has stream_id but verifier did not provide a stream context",
        )

    key_err = _validate_hybrid_pubkey_lens(bundle.agent_pub_key, "agent")
    if key_err:
        return _invalid("invalid_agent_key", key_err)

    first_cert = bundle.delegations[0]
    # Human root = last cert's issuer. Reported on both success and failure
    # paths for audit consistency.
    human_id = bundle.delegations[-1].issuer_id

    if not _hybrid_pub_key_equal(bundle.agent_pub_key, first_cert.subject_pub_key):
        return _invalid("key_mismatch", "agent public key does not match delegation subject")
    if bundle.agent_id != first_cert.subject_id:
        return _invalid("id_mismatch", "agent ID does not match delegation subject ID")

    if opts.force_revocation_check and opts.is_revoked is None and opts.revocation is None:
        return _invalid(
            "force_revocation_no_callback",
            "force_revocation_check is true but neither is_revoked nor revocation provider is set",
        )

    # --- Per-cert checks ---
    for i, cert in enumerate(bundle.delegations):
        if cert.version != PROTOCOL_VERSION:
            return _invalid("version_mismatch", f"cert {i} has unsupported version {cert.version}")
        if now > cert.expires_at:
            return _expired(human_id, bundle.agent_id)
        if now < cert.issued_at:
            return _invalid("not_yet_valid", f"cert {i} is not yet valid")
        # Revocation: provider (SPEC §17.1) takes precedence over legacy closure.
        if opts.revocation is not None:
            rev, rev_err = opts.revocation.is_revoked(cert.cert_id)
            if rev_err is not None:
                return _invalid(
                    "revocation_error",
                    f"cert {i}: revocation lookup failed: {rev_err}",
                )
            if rev:
                return _revoked(human_id, bundle.agent_id)
        elif opts.is_revoked is not None and opts.is_revoked(cert.cert_id):
            return _revoked(human_id, bundle.agent_id)
        sig_err = verify_delegation_signature_e(cert)
        if sig_err is not None:
            return _invalid("bad_signature", f"cert {i}: {sig_err}")
        # Constraint evaluation — each cert's first-class constraints must all
        # pass against the caller-supplied VerifierContext. Fail-closed.
        constraint_err = evaluate_constraints(
            cert, opts.context, now, opts.constraint_evaluators
        )
        if constraint_err is not None:
            status = "constraint_denied"
            if "constraint_unverifiable" in constraint_err:
                status = "constraint_unverifiable"
            elif "constraint_unknown" in constraint_err:
                status = "constraint_unknown"
            return _fail_with_status(status, f"cert {i}: {constraint_err}")
        # Chain linkage
        if i + 1 < len(bundle.delegations):
            nxt = bundle.delegations[i + 1]
            if cert.issuer_id != nxt.subject_id:
                return _invalid(
                    "broken_chain",
                    f"cert {i} issuer does not match cert {i + 1} subject",
                )
            if not _hybrid_pub_key_equal(cert.issuer_pub_key, nxt.subject_pub_key):
                return _invalid(
                    "broken_chain_keys",
                    f"cert {i} issuer key does not match cert {i + 1} subject key",
                )
            # Sub-delegation gate: parent cert must have explicitly granted
            # identity:delegate — sensitive, never from wildcard expansion.
            if SCOPE_IDENTITY_DELEGATE not in nxt.scope:
                return _fail_with_status(
                    "delegation_not_authorized",
                    f"cert {i} issued by a subject whose parent cert {i + 1} "
                    f'did not grant "{SCOPE_IDENTITY_DELEGATE}"',
                )

    # --- Liveness ---
    challenge_age = now - bundle.challenge_at
    if challenge_age < 0 or challenge_age > CHALLENGE_WINDOW_SECONDS:
        return _invalid(
            "stale_challenge",
            f"challenge is {challenge_age} seconds old (max {CHALLENGE_WINDOW_SECONDS})",
        )
    ch_err = verify_challenge_signature_e(
        bundle.challenge,
        bundle.challenge_at,
        bundle.challenge_sig,
        bundle.agent_pub_key,
        bundle.session_context,
        bundle.stream_id,
        bundle.stream_seq,
    )
    if ch_err is not None:
        return _invalid("bad_challenge_sig", f"challenge signature verification failed: {ch_err}")

    # --- Effective scope ---
    scope_lists = [cert.scope for cert in bundle.delegations]
    effective = intersect_scopes(*scope_lists)

    if opts.required_scope:
        if opts.required_scope not in effective:
            return _fail_with_status(
                "scope_denied",
                f'required scope "{opts.required_scope}" not in effective delegation scope',
            )

    result = VerifyResult(
        valid=True,
        identity_status="authorized_agent",
        human_id=human_id,
        agent_id=bundle.agent_id,
        granted_scope=effective,
    )

    # --- Anchor resolution (SPEC §17.8) ---
    if opts.anchor_resolver is not None:
        try:
            anchor = opts.anchor_resolver.resolve_anchor(human_id)
        except Exception:  # noqa: BLE001
            anchor = None  # non-fatal
        if anchor is not None:
            result.anchor = anchor

    # --- Advanced Policy Gating (SPEC §17.2 / §17.6) ---
    if (
        opts.policy_verdict is not None
        and opts.required_scope
        and opts.policy_secret is not None
    ):
        from .crypto import verifier_context_hash, verify_policy_verdict_e
        try:
            ctx_hash = verifier_context_hash(opts.context)
            verdict_err = verify_policy_verdict_e(
                opts.policy_verdict,
                opts.policy_secret,
                bundle.agent_id,
                opts.required_scope,
                ctx_hash,
                now,
            )
        except Exception as e:  # noqa: BLE001
            return _invalid("policy_error", f"verifier context hash failed: {e}")
        if verdict_err is None:
            return result  # cached allow — skip live policy
        if verdict_err.startswith("policy_verdict_denied"):
            return _fail_with_status(
                "scope_denied",
                "policy verdict (cached) denied access",
            )
        # else: stale verdict — fall through to live policy

    if opts.policy is not None:
        try:
            allow, pol_err = opts.policy.evaluate_policy(bundle, opts.context)
        except Exception as e:
            return _invalid("policy_error", f"advanced policy evaluation failed: {e}")
        if pol_err is not None:
            return _invalid("policy_error", f"advanced policy evaluation failed: {pol_err}")
        if not allow:
            return _fail_with_status(
                "scope_denied",
                "advanced policy evaluation denied access",
            )

    return result


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _hybrid_pub_key_equal(a: HybridPublicKey, b: HybridPublicKey) -> bool:
    return a.ed25519 == b.ed25519 and a.ml_dsa_65 == b.ml_dsa_65


def _validate_hybrid_pubkey_lens(pub: HybridPublicKey, label: str) -> str | None:
    if len(pub.ed25519) != ED25519_PUBLIC_KEY_SIZE:
        return f"{label} Ed25519 public key has wrong length: {len(pub.ed25519)}"
    if len(pub.ml_dsa_65) != MLDSA65_PUBLIC_KEY_SIZE:
        return f"{label} ML-DSA-65 public key has wrong length: {len(pub.ml_dsa_65)}"
    return None


def _invalid(reason: str, msg: str) -> VerifyResult:
    return VerifyResult(
        valid=False,
        identity_status="invalid",
        error_reason=f"{reason}: {msg}",
    )


def _fail_with_status(status, msg: str) -> VerifyResult:
    """Constructor for failures with their own identity_status (scope_denied,
    constraint_denied, etc). Mirrors Go's failWithStatus."""
    return VerifyResult(
        valid=False,
        identity_status=status,
        error_reason=f"{status}: {msg}",
    )


def _expired(human_id: str, agent_id: str) -> VerifyResult:
    return VerifyResult(
        valid=False,
        identity_status="expired",
        human_id=human_id,
        agent_id=agent_id,
        error_reason="delegation certificate has expired",
    )


def _revoked(human_id: str, agent_id: str) -> VerifyResult:
    return VerifyResult(
        valid=False,
        identity_status="revoked",
        human_id=human_id,
        agent_id=agent_id,
        error_reason="delegation certificate has been revoked",
    )


# ----------------------------------------------------------------------
# v1.1 transaction receipt verification
# ----------------------------------------------------------------------

def verify_transaction_receipt(
    receipt: TransactionReceipt,
    now: Optional[int] = None,
) -> TransactionReceiptResult:
    """Verify a TransactionReceipt's envelope per SPEC section 5.14.

    Checks version, non-empty fields, party_id uniqueness, signature
    coverage, proof_bundle validity, agent_id/pubkey binding, and party
    signature verification over the canonical signable. Atomic: any single
    failure fails the whole receipt.
    """
    if now is None:
        now = int(time.time())

    # --- Structural ---
    if receipt.version != PROTOCOL_VERSION:
        return TransactionReceiptResult(
            valid=False,
            error_reason=f"version_mismatch: unsupported version {receipt.version}",
        )
    if not receipt.transaction_id:
        return TransactionReceiptResult(
            valid=False,
            error_reason="missing_transaction_id: transaction_id must not be empty",
        )
    if not receipt.terms_schema_uri:
        return TransactionReceiptResult(
            valid=False,
            error_reason="missing_terms_schema_uri: terms_schema_uri must not be empty",
        )
    if not receipt.terms_canonical_json:
        return TransactionReceiptResult(
            valid=False,
            error_reason="missing_terms_canonical_json: terms_canonical_json must not be empty",
        )
    if not receipt.parties:
        return TransactionReceiptResult(
            valid=False,
            error_reason="no_parties: receipt must list at least one party",
        )

    # Party ID uniqueness
    party_idx: dict[str, int] = {}
    for i, p in enumerate(receipt.parties):
        if not p.party_id:
            return TransactionReceiptResult(
                valid=False,
                error_reason=f"empty_party_id: party {i} has no party_id",
            )
        if p.party_id in party_idx:
            return TransactionReceiptResult(
                valid=False,
                error_reason=f'duplicate_party_id: "{p.party_id}" listed more than once',
            )
        party_idx[p.party_id] = i

    # Signature coverage: each sig must reference a known party, no dups,
    # every party must have exactly one sig.
    sig_by_party: dict[str, int] = {}
    for i, s in enumerate(receipt.party_signatures):
        if s.party_id not in party_idx:
            return TransactionReceiptResult(
                valid=False,
                error_reason=f'unknown_party_signature: signature {i} references unknown party_id "{s.party_id}"',
            )
        if s.party_id in sig_by_party:
            return TransactionReceiptResult(
                valid=False,
                error_reason=f'duplicate_party_signature: party "{s.party_id}" has multiple signatures',
            )
        sig_by_party[s.party_id] = i
    for p in receipt.parties:
        if p.party_id not in sig_by_party:
            return TransactionReceiptResult(
                valid=False,
                error_reason=f'missing_party_signature: party "{p.party_id}" has no signature',
            )

    # Canonical signable bytes
    signable = transaction_receipt_sign_bytes(receipt)

    party_results: list[VerifyResult] = []
    for p in receipt.parties:
        # Proof bundle binding: agent_id and agent_pub_key must match.
        if p.proof_bundle.agent_id != p.agent_id:
            return TransactionReceiptResult(
                valid=False,
                error_reason=(
                    f'party_agent_id_mismatch: party "{p.party_id}" '
                    f'proof_bundle.agent_id="{p.proof_bundle.agent_id}" '
                    f'!= party.agent_id="{p.agent_id}"'
                ),
            )
        if not _hybrid_pub_key_equal(p.proof_bundle.agent_pub_key, p.agent_pub_key):
            return TransactionReceiptResult(
                valid=False,
                error_reason=(
                    f'party_agent_key_mismatch: party "{p.party_id}" '
                    f"proof_bundle.agent_pub_key != party.agent_pub_key"
                ),
            )

        # Verify party's proof bundle
        bundle_opts = VerifyOptions(now=now)
        r = verify_bundle(p.proof_bundle, bundle_opts)
        party_results.append(r)
        if not r.valid:
            return TransactionReceiptResult(
                valid=False,
                error_reason=(
                    f'party_bundle_invalid: party "{p.party_id}" '
                    f"status={r.identity_status} reason={r.error_reason}"
                ),
                party_results=party_results,
            )

        # Verify party signature over the canonical signable
        sig = receipt.party_signatures[sig_by_party[p.party_id]].signature
        sig_err = verify_both(signable, sig, p.agent_pub_key)
        if sig_err is not None:
            return TransactionReceiptResult(
                valid=False,
                error_reason=f'party_signature_invalid: party "{p.party_id}": {sig_err}',
                party_results=party_results,
            )

    return TransactionReceiptResult(valid=True, party_results=party_results)


# ----------------------------------------------------------------------
# v1.1 session cert cache (ROADMAP 2.3) streamed-turn verification
# ----------------------------------------------------------------------

def verify_streamed_turn(
    token: SessionToken,
    session_secret: bytes,
    challenge: bytes,
    challenge_at: int,
    challenge_sig: HybridSignature,
    session_context: bytes = b"",
    stream_id: bytes = b"",
    stream_seq: int = 0,
    now: Optional[int] = None,
) -> VerifyResult:
    """Fast-path verifier for streamed turns that present a SessionToken in
    place of the full cert chain. Checks HMAC, validity window, challenge
    freshness, and hybrid challenge signature against token.agent_pub_key.
    The chain is NOT re-verified — that's the point of the token.
    """
    import time

    if now is None:
        now = int(time.time())
    if token is None:
        return _invalid("nil_session_token", "session_token must not be nil")
    mac_err = verify_session_token_e(token, session_secret, now)
    if mac_err is not None:
        return _invalid("session_token_invalid", mac_err)
    if not challenge:
        return _invalid("no_challenge", "streamed turn contains no challenge")
    if session_context and len(session_context) != 32:
        return _invalid(
            "invalid_session_context",
            f"session_context must be 32 bytes, got {len(session_context)}",
        )
    if stream_id and len(stream_id) != 32:
        return _invalid(
            "invalid_stream_id",
            f"stream_id must be 32 bytes, got {len(stream_id)}",
        )
    if stream_id and stream_seq < 1:
        return _invalid(
            "invalid_stream_seq",
            f"stream_seq must be >=1, got {stream_seq}",
        )
    challenge_age = now - challenge_at
    if challenge_age < 0 or challenge_age > CHALLENGE_WINDOW_SECONDS:
        return _invalid(
            "stale_challenge",
            f"challenge is {challenge_age} seconds old (max {CHALLENGE_WINDOW_SECONDS})",
        )
    sig_err = verify_challenge_signature_e(
        challenge,
        challenge_at,
        challenge_sig,
        token.agent_pub_key,
        session_context,
        stream_id,
        stream_seq,
    )
    if sig_err is not None:
        return _invalid(
            "bad_challenge_sig",
            f"challenge signature verification failed: {sig_err}",
        )
    return VerifyResult(
        valid=True,
        identity_status="authorized_agent",
        human_id=token.human_id,
        agent_id=token.agent_id,
        granted_scope=list(token.granted_scope),
    )
