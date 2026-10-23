//! Strict decode and canonical re-encode, signable projections, the signing
//! transcript, every SPEC-v2 §4 digest, canonical JSON, scope and context
//! validation, and the two standard constraint evaluator profiles.

use std::os::raw::c_char;

use ratify_protocol::v2::*;
use ratify_protocol::HybridSignature;
use serde_json::Value;
use sha2::{Digest, Sha384};

use super::marshal::{constraint_context, operation_context, session_inputs, to_bytes, Obj};
use super::{
    bad_arg, bytes, clear_buffer, cstr, json_bytes, null_arg, run, write_buffer, write_opt_buffer,
    write_string, write_val, AbiResult, Failure, RatifyV2Buffer, RatifyV2Code, RatifyV2PublicKey,
    RatifyV2Slice,
};

pub(crate) fn object_type(code: u32) -> AbiResult<V2ObjectType> {
    u16::try_from(code)
        .ok()
        .and_then(V2ObjectType::from_code)
        .ok_or_else(|| {
            V2Error::new(
                V2ErrorClass::UnsupportedObjectType,
                format!("object type code {code:#06x} is outside the SPEC-v2 §4 registry"),
            )
            .into()
        })
}

fn unsupported_kind(kind: i32) -> Failure {
    V2Error::new(
        V2ErrorClass::UnsupportedObjectType,
        format!("object kind {kind} is not supported by this function"),
    )
    .into()
}

/// Strictly decode `wire` as `kind` and return its canonical encoding.
pub(crate) fn canonicalize(kind: i32, wire: &[u8]) -> AbiResult<Vec<u8>> {
    Ok(match kind {
        1 => encode_delegation_cert_v2(&decode_delegation_cert_v2(wire)?)?,
        2 => encode_proof_bundle_v2(&decode_proof_bundle_v2(wire)?)?,
        3 => encode_revocation_list_v2(&decode_revocation_list_v2(wire)?)?,
        4 | 9 => encode_key_rotation_statement_v2(&decode_key_rotation_statement_v2(wire)?)?,
        5 => encode_revocation_push_v2(&decode_revocation_push_v2(wire)?)?,
        6 => encode_witness_entry_v2(&decode_witness_entry_v2(wire)?)?,
        7 => encode_transaction_receipt_v2(&decode_transaction_receipt_v2(wire)?)?,
        8 => encode_verification_receipt_v2(&decode_verification_receipt_v2(wire)?)?,
        100 => verification_receipt_v2_body(&decode_verification_receipt_body_v2(wire)?)?,
        101 => status_batch_envelope(&decode_v2_status_evidence_batch(wire)?),
        102 => encode_v2_checkpoint_acknowledgement(&decode_v2_checkpoint_acknowledgement(wire)?)?,
        other => return Err(unsupported_kind(other)),
    })
}

/// A status evidence batch in its envelope form: entry members in canonical
/// order, each object's received bytes unchanged. SPEC-v2 §6.5 step 3 decodes
/// only the envelope; each object is decoded strictly when it is
/// authenticated, so the batch decode must not decode or re-encode it.
fn status_batch_envelope(batch: &V2StatusEvidenceBatch) -> Vec<u8> {
    let mut buf = vec![b'['];
    for (i, object) in batch.objects.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        buf.extend_from_slice(br#"{"object":"#);
        buf.extend_from_slice(&object.wire);
        buf.extend_from_slice(br#","object_type_code":"#);
        buf.extend_from_slice(object.object_type.to_string().as_bytes());
        buf.push(b'}');
    }
    buf.push(b']');
    buf
}

/// The exact signable projection of `wire` for signature code `code`.
pub(crate) fn signable(code: u32, wire: &[u8]) -> AbiResult<Vec<u8>> {
    Ok(match object_type(code)? {
        V2ObjectType::DelegationCertificate => {
            delegation_cert_v2_signable_bytes(&decode_delegation_cert_v2(wire)?)?
        }
        V2ObjectType::ChallengePresentation => {
            presentation_v2_signable_bytes(&decode_proof_bundle_v2(wire)?)?
        }
        V2ObjectType::RevocationList => {
            revocation_list_v2_signable_bytes(&decode_revocation_list_v2(wire)?)?
        }
        V2ObjectType::KeyRotationAuthorization | V2ObjectType::KeyRotationProofOfPossession => {
            key_rotation_statement_v2_signable_bytes(&decode_key_rotation_statement_v2(wire)?)?
        }
        V2ObjectType::RevocationPush => {
            revocation_push_v2_signable_bytes(&decode_revocation_push_v2(wire)?)?
        }
        V2ObjectType::WitnessEntry => {
            witness_entry_v2_signable_bytes(&decode_witness_entry_v2(wire)?)?
        }
        V2ObjectType::TransactionPartyStatement => {
            transaction_receipt_v2_sign_bytes(&decode_transaction_receipt_v2(wire)?)?
        }
        V2ObjectType::VerificationReceipt => {
            verification_receipt_v2_signable_bytes(&decode_verification_receipt_v2(wire)?)?
        }
    })
}

/// Strictly decode `wire` as `kind` (a `RatifyV2ObjectKind`), applying the
/// object's byte limit before parsing. When `canonical_out` is non-NULL the
/// canonical re-encoding is written there (it equals `wire` for every
/// conforming object). Signed objects 1..=8 are decoded with all their
/// structural checks; a transaction receipt also verifies its signatures.
/// A status evidence batch (101) is decoded at the envelope only (SPEC-v2
/// §6.5 step 3): its nested objects are not decoded, and `canonical_out`
/// carries each object's received bytes unchanged, with the entry members in
/// canonical order.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_object_decode(
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    canonical_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(canonical_out),
        || {
            let encoded = canonicalize(kind, bytes(wire, wire_len, "wire")?)?;
            write_opt_buffer(canonical_out, encoded)
        },
    )
}

/// The exact signable projection (SPEC-v2 §5) of `wire` under signature code
/// `object_type_code` (0x0001..=0x0009): the certificate body, the challenge
/// presentation of a proof bundle, the status object body, the rotation
/// statement body (both 0x0004 and 0x0009), the witness entry, the shared
/// transaction statement, or the receipt body. The object is strictly
/// decoded first.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_signable_bytes(
    object_type_code: u32,
    wire: *const u8,
    wire_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            write_buffer(
                out,
                signable(object_type_code, bytes(wire, wire_len, "wire")?)?,
            )
        },
    )
}

/// The 77-byte signing transcript `M` (SPEC-v2 §3.1) for `signable` under
/// `object_type_code`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_signing_message(
    object_type_code: u32,
    signable: *const u8,
    signable_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let ty = object_type(object_type_code)?;
            write_buffer(
                out,
                v2_signing_message(ty, bytes(signable, signable_len, "signable")?),
            )
        },
    )
}

/// The 22-byte FIPS 204 ML-DSA-65 context of `object_type_code`
/// (`ratify-protocol/2/` + lowercase 4-hex code).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mldsa_context(
    object_type_code: u32,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || write_buffer(out, v2_mldsa_context(object_type(object_type_code)?)),
    )
}

/// The 64-byte external μ an external-μ provider signs (SPEC-v2 §3.1):
/// `SHAKE256(SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx || M, 64)` for the
/// registry context of `object_type_code` and the 77-byte transcript
/// `message`. Provided for adapter checks and conformance; signing computes
/// μ itself.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_external_mu(
    key: *const RatifyV2PublicKey,
    object_type_code: u32,
    message: *const u8,
    message_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let key = key.as_ref().ok_or_else(|| null_arg("key"))?;
            let context = v2_mldsa_context(object_type(object_type_code)?);
            write_buffer(
                out,
                external_mu_v2(
                    &key.ml_dsa_65,
                    &context,
                    bytes(message, message_len, "message")?,
                ),
            )
        },
    )
}

/// Verify both components of a hybrid signature over `signable` under
/// `object_type_code` and a complete public key with the ordinary verifier.
/// A code outside the registry is `unsupported_object_type`; a failing
/// component is `invalid_signature`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verify_statement(
    object_type_code: u32,
    signable: *const u8,
    signable_len: usize,
    signature_ed25519: RatifyV2Slice,
    signature_ml_dsa_65: RatifyV2Slice,
    key: *const RatifyV2PublicKey,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let key = key.as_ref().ok_or_else(|| null_arg("key"))?;
            let code = u16::try_from(object_type_code).map_err(|_| {
                Failure::from(V2Error::new(
                    V2ErrorClass::UnsupportedObjectType,
                    "object type code exceeds 16 bits",
                ))
            })?;
            let sig = HybridSignature {
                ed25519: signature_ed25519.bytes("signature_ed25519")?.to_vec(),
                ml_dsa_65: signature_ml_dsa_65.bytes("signature_ml_dsa_65")?.to_vec(),
            };
            verify_v2_statement_code(
                code,
                bytes(signable, signable_len, "signable")?,
                &sig,
                &key.as_hybrid(),
            )?;
            Ok(())
        },
    )
}

// ---------------------------------------------------------------------------
// Digests (SPEC-v2 §4)

/// `delegation_digest` (48 bytes) recomputed over the delegations of a
/// strictly decoded proof bundle.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_delegation_digest(
    bundle: *const u8,
    bundle_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let b = decode_proof_bundle_v2(bytes(bundle, bundle_len, "bundle")?)?;
            write_buffer(out, delegation_digest_v2(&b.delegations)?)
        },
    )
}

/// `BundleHashV2` (`"sha384:" + 96 hex`) of a strictly decoded proof bundle.
/// Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_bundle_hash(
    bundle: *const u8,
    bundle_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let b = decode_proof_bundle_v2(bytes(bundle, bundle_len, "bundle")?)?;
            write_string(out, &bundle_hash_v2(&b)?)
        },
    )
}

/// `ChallengeClaimDigest` (48 bytes) of exactly 32 challenge bytes.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_challenge_claim_digest(
    challenge: *const u8,
    challenge_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            write_buffer(
                out,
                challenge_claim_digest_v2(bytes(challenge, challenge_len, "challenge")?)?,
            )
        },
    )
}

unsafe fn namespace<'a>(ptr: *const u8, len: usize) -> AbiResult<&'a str> {
    std::str::from_utf8(bytes(ptr, len, "namespace")?).map_err(|_| {
        V2Error::new(
            V2ErrorClass::ConfigurationInvalid,
            "verifier namespace is not valid UTF-8",
        )
        .into()
    })
}

/// The stable claim ID (64 lowercase hex) for a UTF-8 verifier namespace
/// (length-delimited; may contain NUL), replay epoch (0..2^53-1), and 32
/// challenge bytes. Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_claim_id(
    namespace_ptr: *const u8,
    namespace_len: usize,
    replay_epoch: i64,
    challenge: *const u8,
    challenge_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let ns = namespace(namespace_ptr, namespace_len)?;
            write_string(
                out,
                &protocol_claim_id_v2(
                    ns,
                    replay_epoch,
                    bytes(challenge, challenge_len, "challenge")?,
                )?,
            )
        },
    )
}

/// The claim ID from a precomputed 48-byte `ChallengeClaimDigest`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_claim_id_from_digest(
    namespace_ptr: *const u8,
    namespace_len: usize,
    replay_epoch: i64,
    claim_digest: *const u8,
    claim_digest_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let ns = namespace(namespace_ptr, namespace_len)?;
            write_string(
                out,
                &protocol_claim_id_from_digest_v2(
                    ns,
                    replay_epoch,
                    bytes(claim_digest, claim_digest_len, "claim_digest")?,
                )?,
            )
        },
    )
}

/// `StatusEvidenceDigest` (48 bytes) of a strictly decoded revocation list
/// (`kind` 3) or revocation push (`kind` 5), over the complete signed object.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_evidence_digest(
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let wire = bytes(wire, wire_len, "wire")?;
            let digest = match kind {
                3 => status_evidence_digest_list_v2(&decode_revocation_list_v2(wire)?)?,
                5 => status_evidence_digest_push_v2(&decode_revocation_push_v2(wire)?)?,
                other => return Err(unsupported_kind(other)),
            };
            write_buffer(out, digest)
        },
    )
}

/// `StatementBodyDigest(code, body)` (48 bytes) over an exact canonical
/// signable body, defined for codes 0x0003, 0x0004, 0x0005, 0x0006 and
/// 0x0008; any other code is `unsupported_object_type`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_statement_body_digest(
    object_type_code: u32,
    body: *const u8,
    body_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let code = object_type(object_type_code)?.code();
            write_buffer(
                out,
                statement_body_digest_v2(code, bytes(body, body_len, "body")?)?,
            )
        },
    )
}

/// `StatementBodyDigest` (48 bytes) of a strictly decoded signed object:
/// the chain digest of a rotation statement (`kind` 4), witness entry (6),
/// or verification receipt (8), and the digest of the signable projection
/// of a revocation list (3) or push (5). Kinds 1, 2 and 7 are
/// `unsupported_object_type` (SPEC-v2 §4). It is independent of signature
/// bytes, so hedged re-signatures share it.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_object_body_digest(
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let wire = bytes(wire, wire_len, "wire")?;
            let digest = match kind {
                4 => key_rotation_statement_v2_digest(&decode_key_rotation_statement_v2(wire)?)?,
                6 => witness_entry_v2_digest(&decode_witness_entry_v2(wire)?)?,
                8 => verification_receipt_v2_digest(&decode_verification_receipt_v2(wire)?)?,
                1 | 2 | 3 | 5 | 7 => {
                    let code = kind as u32;
                    statement_body_digest_v2(code as u16, &signable(code, wire)?)?
                }
                other => return Err(unsupported_kind(other)),
            };
            write_buffer(out, digest)
        },
    )
}

/// `RevokedSetDigest` (48 bytes) of a JSON array of revoked `cert_id`
/// strings: deduplicated, sorted by UTF-8 bytes, canonical JSON, SHA-384
/// under the `ratify-protocol-revoked-set-v2` tag.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_revoked_set_digest(
    cert_ids_json: *const u8,
    cert_ids_json_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let v = json_bytes(cert_ids_json, cert_ids_json_len, "cert_ids_json")?;
            let mut ids: Vec<String> = v
                .as_array()
                .ok_or_else(|| bad_arg("cert_ids_json must be an array of strings"))?
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| bad_arg("cert_ids_json entries must be strings"))
                })
                .collect::<AbiResult<_>>()?;
            ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            ids.dedup();
            let canonical = canonical_json_v2(&to_bytes(&Value::from(ids)))?;
            let mut h = Sha384::new();
            h.update(b"ratify-protocol-revoked-set-v2\0");
            h.update(&canonical);
            write_buffer(out, h.finalize().to_vec())
        },
    )
}

/// `ReceiptOutboxDigest` (`"sha384:" + 96 hex`) of an exact sealed outbox
/// body. Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_receipt_outbox_digest(
    body: *const u8,
    body_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            write_string(
                out,
                &receipt_outbox_digest_v2(bytes(body, body_len, "body")?),
            )
        },
    )
}

/// `SecurityJournalDigest` (`"sha384:" + 96 hex`) of a canonical
/// `SecurityJournalV2` snapshot. Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_security_journal_digest(
    snapshot: *const u8,
    snapshot_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            write_string(
                out,
                &security_journal_snapshot_digest_v2(bytes(snapshot, snapshot_len, "snapshot")?),
            )
        },
    )
}

/// The sealed receipt outbox body (SPEC-v2 §7.7) of a strictly decoded
/// signed verification receipt.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verification_receipt_body(
    receipt: *const u8,
    receipt_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let r = decode_verification_receipt_v2(bytes(receipt, receipt_len, "receipt")?)?;
            write_buffer(out, verification_receipt_v2_body(&r)?)
        },
    )
}

/// The 32-byte transaction context (SPEC-v2 §2.4) of a transaction ID, terms
/// schema URI, and exact canonical terms JSON. It needs no parties or
/// signatures, so it can be computed before any party signs.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_transaction_context_hash(
    transaction_id: *const c_char,
    terms_schema_uri: *const c_char,
    terms_canonical_json: *const u8,
    terms_canonical_json_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let r = TransactionReceiptV2 {
                version: 2,
                transaction_id: cstr(transaction_id, "transaction_id")?.to_string(),
                created_at: 0,
                terms_schema_uri: cstr(terms_schema_uri, "terms_schema_uri")?.to_string(),
                terms_canonical_json: bytes(
                    terms_canonical_json,
                    terms_canonical_json_len,
                    "terms_canonical_json",
                )?
                .to_vec(),
                parties: Vec::new(),
                party_signatures: Vec::new(),
            };
            write_buffer(out, transaction_context_hash_v2(&r))
        },
    )
}

/// The 32-byte per-party request hash (SPEC-v2 §2.4) of a transaction
/// context and the party's required scope.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_transaction_party_request_hash(
    transaction_context: *const u8,
    transaction_context_len: usize,
    required_scope: *const c_char,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            write_buffer(
                out,
                transaction_party_request_hash_v2(
                    bytes(
                        transaction_context,
                        transaction_context_len,
                        "transaction_context",
                    )?,
                    cstr(required_scope, "required_scope")?,
                ),
            )
        },
    )
}

/// The 32-byte operation `request_hash` (SPEC-v2 §2.4) of
/// `{"required_scope", "operation", "resource_id", "requested_path",
/// "payload_digest_b64"}` (payload digest empty or exactly 32 bytes).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_operation_context_hash(
    operation_json: *const u8,
    operation_json_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let ctx = operation_context(&json_bytes(
                operation_json,
                operation_json_len,
                "operation_json",
            )?)?;
            write_buffer(out, operation_context_v2_hash(&ctx)?)
        },
    )
}

/// The 32-byte `session_context` (SPEC-v2 §2.4) of `{"verifier_id",
/// "workspace_id", "agent_id", "session_id", "invocation_id",
/// "request_hash_b64"}`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_session_context(
    inputs_json: *const u8,
    inputs_json_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let inputs = session_inputs(&json_bytes(inputs_json, inputs_json_len, "inputs_json")?)?;
            write_buffer(out, build_session_context_v2(&inputs)?)
        },
    )
}

/// Decode the managed Verify API text form of a payload digest (§7.12).
/// NULL `encoded` means absent. `*present` is 1 when a 32-byte digest was
/// decoded into `out`, 0 when the input encodes "no digest".
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_payload_digest_decode(
    encoded: *const c_char,
    out: *mut RatifyV2Buffer,
    present: *mut i32,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            clear_buffer(out);
            crate::guard::clear_val(present);
        },
        || {
            let text = if encoded.is_null() {
                None
            } else {
                Some(cstr(encoded, "encoded")?)
            };
            let decoded = decode_payload_digest_v2(text)?;
            write_val(present, i32::from(decoded.is_some()))?;
            write_buffer(out, decoded.unwrap_or_default())
        },
    )
}

/// The context policy digest of `{"profile", "require_bound",
/// "required_fields", "expected_session_context_b64"}` (the expected session
/// context is excluded from the digest). Free `*out` with
/// `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_context_policy_digest(
    policy_json: *const u8,
    policy_json_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let policy = super::marshal::context_policy(&json_bytes(
                policy_json,
                policy_json_len,
                "policy_json",
            )?)??;
            write_string(out, policy.digest())
        },
    )
}

/// The extension evaluator profile digest (`"sha384:" + 96 hex`) of a
/// `{profile, type}` descriptor. Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_constraint_profile_digest(
    profile: *const c_char,
    constraint_type: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let d = ConstraintProfileDescriptorV2 {
                profile: cstr(profile, "profile")?.to_string(),
                kind: cstr(constraint_type, "constraint_type")?.to_string(),
            };
            write_string(out, &constraint_profile_digest_v2(&d)?)
        },
    )
}

/// RatifyCanonicalJSON (Annex A) of a strictly decoded JSON value.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_canonical_json(
    data: *const u8,
    data_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || write_buffer(out, canonical_json_v2(bytes(data, data_len, "data")?)?),
    )
}

/// Validate a JSON array of delegation scopes under the v2 scope rules.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_validate_scopes(
    scopes_json: *const u8,
    scopes_json_len: usize,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let v = json_bytes(scopes_json, scopes_json_len, "scopes_json")?;
            let scopes: Vec<String> = v
                .as_array()
                .ok_or_else(|| bad_arg("scopes_json must be an array"))?
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| bad_arg("scopes must be strings"))
                })
                .collect::<AbiResult<_>>()?;
            validate_scopes_v2(&scopes)?;
            Ok(())
        },
    )
}

/// Validate one request `required_scope` (SPEC-v2 §2.4):
/// `invalid_required_scope` unless it is one canonical non-wildcard scope or
/// one exact `custom:` scope.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_validate_required_scope(scope: *const c_char) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            validate_required_scope_v2(cstr(scope, "scope")?)?;
            Ok(())
        },
    )
}

/// Validate a request context JSON (the `"context"` member schema of the
/// verification request) against the extension-context bounds
/// (`configuration_invalid` when out of bounds).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_validate_request_context(
    context_json: *const u8,
    context_json_len: usize,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let c =
                constraint_context(&json_bytes(context_json, context_json_len, "context_json")?)?;
            validate_v2_request_context(&c)?;
            Ok(())
        },
    )
}

/// Evaluator outcomes (`ConstraintOutcomeV2`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2EvaluatorOutcome {
    RatifyV2OutcomePass = 1,
    RatifyV2OutcomeDenied = 2,
    RatifyV2OutcomeUnverifiable = 3,
    RatifyV2OutcomeInvalid = 4,
}

pub(crate) fn outcome_code(o: ConstraintOutcomeV2) -> i32 {
    (match o {
        ConstraintOutcomeV2::Pass => RatifyV2EvaluatorOutcome::RatifyV2OutcomePass,
        ConstraintOutcomeV2::Denied => RatifyV2EvaluatorOutcome::RatifyV2OutcomeDenied,
        ConstraintOutcomeV2::Unverifiable => RatifyV2EvaluatorOutcome::RatifyV2OutcomeUnverifiable,
        ConstraintOutcomeV2::Invalid => RatifyV2EvaluatorOutcome::RatifyV2OutcomeInvalid,
    }) as i32
}

/// Run one of the two built-in standard evaluator profiles
/// (`com.ratifyprotocol.max_count/v1`, `com.ratifyprotocol.allowed_values/v1`)
/// on an input `{"type", "params": <any JSON>, "delegation_index",
/// "constraint_index", "issuer_id", "cert_id", "context": <request context>,
/// "evaluation_time"}`; an absent `params` member means no params object.
/// Writes the outcome (`RatifyV2EvaluatorOutcome`), the pass horizon (0 =
/// none), and the diagnostic detail (free with `ratify_v2_string_free`;
/// `detail_out` may be NULL).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_evaluate_standard_profile(
    profile: *const c_char,
    input_json: *const u8,
    input_json_len: usize,
    outcome_out: *mut i32,
    valid_until_out: *mut i64,
    detail_out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            crate::guard::clear_val(outcome_out);
            crate::guard::clear_val(valid_until_out);
            crate::guard::clear_ptr(detail_out);
        },
        || {
            let profile = cstr(profile, "profile")?;
            let v = json_bytes(input_json, input_json_len, "input_json")?;
            let params = match v.as_object().and_then(|m| m.get("params")) {
                Some(p) => Some(canonical_json_v2(&to_bytes(p))?),
                None => None,
            };
            let o = Obj::new(
                &v,
                "evaluation input",
                &[
                    "type",
                    "params",
                    "delegation_index",
                    "constraint_index",
                    "issuer_id",
                    "cert_id",
                    "context",
                    "evaluation_time",
                ],
            )?;
            let context = match o.object("context") {
                Some(c) => constraint_context(c)?,
                None => ConstraintContextV2::default(),
            };
            let input = ConstraintEvaluationInputV2 {
                kind: o.str("type")?,
                params_json: params,
                delegation_index: o.u64("delegation_index")? as usize,
                constraint_index: o.u64("constraint_index")? as usize,
                issuer_id: o.str("issuer_id")?,
                cert_id: o.str("cert_id")?,
                context,
                evaluation_time: o.i64("evaluation_time")?,
            };
            let result = match profile {
                PROFILE_MAX_COUNT_V2 => evaluate_max_count_v2(&input),
                PROFILE_ALLOWED_VALUES_V2 => evaluate_allowed_values_v2(&input),
                other => {
                    return Err(Failure::new(
                        RatifyV2Code::RatifyV2ConfigurationInvalid,
                        format!("{other:?} is not a built-in standard evaluator profile"),
                    ))
                }
            };
            write_val(outcome_out, outcome_code(result.outcome))?;
            write_val(valid_until_out, result.valid_until)?;
            super::write_opt_string(detail_out, &result.detail)
        },
    )
}

/// Whether an authoritative time `now` is inside a claim's sealed challenge
/// bounds with exclusive deadlines (`issued_at <= now + skew`, `now <
/// expires_at`, `now < issued_at + max_age`). Returns 1 or 0; 0 on any
/// failure, including a timestamp outside 0..=253402300799, `max_age_seconds`
/// outside 1..=300 or `clock_skew_seconds` outside 0..=300 (the SPEC-v2 §2.5
/// bounds every sealed claim satisfies). For claim stores implementing the
/// freshness recheck.
#[no_mangle]
pub extern "C" fn ratify_v2_challenge_time_current(
    issued_at: i64,
    expires_at: i64,
    max_age_seconds: i64,
    clock_skew_seconds: i64,
    now: i64,
) -> i32 {
    crate::guard::ffi_guard(
        || 0,
        || {
            if !(1..=V2_MAX_CHALLENGE_AGE_SECONDS).contains(&max_age_seconds)
                || !(0..=V2_MAX_FUTURE_SKEW_SECONDS).contains(&clock_skew_seconds)
            {
                return 0;
            }
            let claim = V2ChallengeClaim {
                issued_at,
                expires_at,
                max_age_seconds,
                clock_skew_seconds,
                ..Default::default()
            };
            i32::from(challenge_claim_time_current_v2(&claim, now))
        },
    )
}

/// The stream-sequence rule of SPEC-v2 §7.4 for a claim store: `has_last`
/// says whether the stream has an accepted sequence `last`; `seq` is the
/// presented sequence. Returns 0 to accept or `stream_sequence_mismatch` /
/// `malformed`.
#[no_mangle]
pub extern "C" fn ratify_v2_check_stream_sequence(has_last: i32, last: i64, seq: i64) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            check_v2_stream_sequence(has_last != 0, last, seq)?;
            Ok(())
        },
    )
}

/// The finalization binding of SPEC-v2 §7.5 for a claim store's `finalize`
/// (Go `ValidateV2FinalizationPayload`). `claim_record` is the claim's
/// `RatifyV2ClaimView.record` as the store persisted it. Returns 0 when the
/// receipt body decodes strictly as a canonical receipt outbox body whose
/// `verifier_id`, `agent_id`, `bundle_hash`, `issuer_ids` (the sorted,
/// distinct sealed issuer IDs), `required_scope` and `constraint_evaluators`
/// equal the sealed claim's, whose `context_policy_digest` equals the sealed
/// claim's (null for a policy-less claim) unless `context_assessment` is
/// `not_evaluated`, when it is null, and the terminal result is a JSON
/// object whose `decision` and `decision_reason` equal the body's. Otherwise
/// `malformed` (the body does not decode) or `configuration_invalid` (any
/// difference); a store commits nothing in either case. A `claim_record` that is not a claim record is
/// `bad_argument`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_validate_finalization_payload(
    claim_record: *const u8,
    claim_record_len: usize,
    terminal_result: *const u8,
    terminal_result_len: usize,
    receipt_body: *const u8,
    receipt_body_len: usize,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let claim = super::marshal::claim_from_json(bytes(claim_record, claim_record_len, "claim_record")?)?;
            let terminal = bytes(terminal_result, terminal_result_len, "terminal_result")?;
            let body = bytes(receipt_body, receipt_body_len, "receipt_body")?;
            validate_v2_finalization_payload(&claim, terminal, body)?;
            Ok(())
        },
    )
}

/// Whether `outcome` (a `RatifyV2ReleaseStatus`) and `reason` form a release
/// record (SPEC-v2 §6.9; Go `ValidV2ReleaseRecordOutcome`): released with
/// the reason "" (or NULL), or withheld with "clock_regressed",
/// "challenge_expired" or "allow_horizon_passed". Returns 1 or 0. For claim
/// stores implementing `record_release`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_valid_release_record_outcome(outcome: i32, reason: *const c_char) -> i32 {
    crate::guard::ffi_guard(
        || 0,
        || {
            let reason = super::callbacks::owned(reason);
            i32::from(valid_v2_release_record_outcome(
                super::verifier::release_status_from_c(outcome),
                &reason,
            ))
        },
    )
}

/// Verify one cross-SDK fixture file (`testvectors/v2/cross-sdk/<sdk>.json`)
/// with the README procedure: strict decode, `sdk == expected_sdk`, key
/// derivation from seeds, byte-identical re-encoding, every signature
/// transcript and signature, and the required kinds and coverage.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_cross_sdk_fixture_verify(
    fixture: *const u8,
    fixture_len: usize,
    expected_sdk: *const c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            verify_cross_sdk_fixture_v2(
                bytes(fixture, fixture_len, "fixture")?,
                cstr(expected_sdk, "expected_sdk")?,
            )?;
            Ok(())
        },
    )
}
