//! Transaction receipts (party statements, object code 0x0007).
//! Mirrors Go `transaction_receipt_v2.go`.

use super::context::V2Context;
use super::crypto::{
    equal_keys, key_id_v2, lp, sha256, sha384, valid_prefixed_digest, valid_v2_id, verify_v2_statement, V2ObjectType,
};
use super::errors::{V2Error, V2SignError, V2SignResult};
use super::limits::{check_v2_wire_size, valid_v2_timestamp, MAX_TRANSACTION_RECEIPT_BYTES_V2};
use super::signer::{sign_v2_statement_with_signer, signer_public_key_v2, LocalSignerV2, SignerV2};
use super::errors::{err, plain, Classify, V2ErrorClass, V2Result};
use super::json::{canonical, node_to_cj, obj, parse_json, parse_wire, JNode, CJ, JV};
use super::wire::{
    bundle_hash_of_bytes, bundle_hash_v2, decode_proof_bundle_v2, encode_proof_bundle_v2,
    required_scope_v2, verify_proof_bundle_v2_signatures, ProofBundleV2,
};
use super::operation_context::{build_session_context_v2, SessionContextV2Inputs};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature};

/// Bound on the complete encoded receipt including embedded bundles.
pub const MAX_TRANSACTION_RECEIPT_BYTES: usize = MAX_TRANSACTION_RECEIPT_BYTES_V2;
/// Bound on the number of parties.
pub const MAX_TRANSACTION_PARTIES: usize = super::limits::MAX_TRANSACTION_PARTIES_V2;

/// Canonical application terms bound to one signed v2 proof per party.
#[derive(Debug, Clone)]
pub struct TransactionReceiptV2 {
    pub version: i64,
    pub transaction_id: String,
    pub created_at: i64,
    pub terms_schema_uri: String,
    pub terms_canonical_json: Vec<u8>,
    pub parties: Vec<TransactionReceiptPartyV2>,
    pub party_signatures: Vec<TransactionReceiptSignatureV2>,
}

#[derive(Debug, Clone)]
pub struct TransactionReceiptPartyV2 {
    pub party_id: String,
    pub role: String,
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub verifier_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub invocation_id: String,
    pub required_scope: String,
    pub proof_bundle_hash: String,
    pub proof_bundle: Option<ProofBundleV2>,
}

#[derive(Debug, Clone)]
pub struct TransactionReceiptSignatureV2 {
    pub party_id: String,
    pub signature: HybridSignature,
}

const TOP: &[&str] = &[
    "version",
    "transaction_id",
    "created_at",
    "terms_schema_uri",
    "terms_canonical_json",
    "parties",
    "party_signatures",
];
const PARTY: &[&str] = &[
    "agent_id",
    "agent_pub_key",
    "invocation_id",
    "party_id",
    "proof_bundle",
    "proof_bundle_hash",
    "required_scope",
    "role",
    "session_id",
    "verifier_id",
    "workspace_id",
];

/// SHA-256 transaction context over (transaction_id, terms_schema_uri, SHA-384(terms)).
pub fn transaction_context_hash_v2(r: &TransactionReceiptV2) -> Vec<u8> {
    let terms = sha384(&[&r.terms_canonical_json]);
    sha256(&[
        b"ratify/transaction-context/v2",
        &lp(r.transaction_id.as_bytes()),
        &lp(r.terms_schema_uri.as_bytes()),
        &terms,
    ])
}

/// Per-party request hash bound into that party's session context.
pub fn transaction_party_request_hash_v2(transaction_hash: &[u8], required_scope: &str) -> Vec<u8> {
    sha256(&[
        b"ratify/transaction-party-request/v2",
        &lp(transaction_hash),
        &lp(required_scope.as_bytes()),
    ])
}

/// Exact object-type 0x0007 bytes signed by each party.
pub fn transaction_receipt_v2_sign_bytes(r: &TransactionReceiptV2) -> V2Result<Vec<u8>> {
    if r.parties.is_empty() {
        return plain("v2 transaction receipt and parties are required");
    }
    if r.parties.len() > MAX_TRANSACTION_PARTIES {
        return plain("v2 transaction receipt exceeds MAX_TRANSACTION_PARTIES");
    }
    let mut parties: Vec<&TransactionReceiptPartyV2> = r.parties.iter().collect();
    parties.sort_by(|a, b| a.party_id.as_bytes().cmp(b.party_id.as_bytes()));
    let parties = parties
        .into_iter()
        .map(|p| {
            CJ::obj(vec![
                ("agent_id", CJ::s(&p.agent_id)),
                ("agent_pub_key", CJ::key(&p.agent_pub_key)),
                ("invocation_id", CJ::s(&p.invocation_id)),
                ("party_id", CJ::s(&p.party_id)),
                ("proof_bundle_hash", CJ::s(&p.proof_bundle_hash)),
                ("required_scope", CJ::s(&p.required_scope)),
                ("role", CJ::s(&p.role)),
                ("session_id", CJ::s(&p.session_id)),
                ("verifier_id", CJ::s(&p.verifier_id)),
                ("workspace_id", CJ::s(&p.workspace_id)),
            ])
        })
        .collect();
    canonical(&CJ::obj(vec![
        ("created_at", CJ::Int(r.created_at)),
        ("parties", CJ::Arr(parties)),
        (
            "terms_canonical_json",
            CJ::Bytes(r.terms_canonical_json.clone()),
        ),
        ("terms_schema_uri", CJ::s(&r.terms_schema_uri)),
        ("transaction_id", CJ::s(&r.transaction_id)),
        ("version", CJ::Int(r.version)),
    ]))
}

fn valid_workspace(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

fn integer_only(node: &JNode) -> bool {
    match &node.v {
        JV::Num(t) => !t.contains(['.', 'e', 'E']),
        JV::Arr(items) => items.iter().all(integer_only),
        JV::Obj(fields) => fields.iter().all(|(_, v)| integer_only(v)),
        _ => true,
    }
}

fn validate_terms(data: &[u8]) -> V2Result<()> {
    let root = parse_json(data)?;
    if !matches!(root.v, JV::Obj(_)) {
        return plain("terms must be a JSON object");
    }
    if !integer_only(&root) {
        return plain("non-integer JSON numbers are not permitted");
    }
    if canonical(&node_to_cj(&root))? != data {
        return plain("terms bytes differ from RatifyCanonicalJSON");
    }
    Ok(())
}

fn validate(r: &TransactionReceiptV2, require_signatures: bool) -> V2Result<()> {
    use V2ErrorClass::*;
    if r.version != 2
        || r.transaction_id.is_empty()
        || !valid_v2_timestamp(r.created_at)
        || r.terms_schema_uri.is_empty()
        || r.terms_canonical_json.is_empty()
        || r.parties.is_empty()
    {
        return plain("wire v2: transaction receipt header or terms are invalid");
    }
    if r.parties.len() > MAX_TRANSACTION_PARTIES {
        return plain("wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES");
    }
    validate_terms(&r.terms_canonical_json)
        .map_err(|e| e.context("wire v2: transaction terms are not canonical Ratify JSON"))?;
    let tx_hash = transaction_context_hash_v2(r);
    for (i, p) in r.parties.iter().enumerate() {
        if p.party_id.is_empty()
            || p.role.is_empty()
            || p.session_id.is_empty()
            || p.invocation_id.is_empty()
            || !valid_v2_id(&p.verifier_id)
            || !valid_workspace(&p.workspace_id)
            || !valid_v2_id(&p.agent_id)
        {
            return plain(format!(
                "wire v2: transaction party {i} has invalid identity or context fields"
            ));
        }
        if i > 0 && r.parties[i - 1].party_id.as_bytes() >= p.party_id.as_bytes() {
            return plain("wire v2: transaction parties must be sorted by unique party_id");
        }
        if r.parties[..i].iter().any(|q| q.agent_id == p.agent_id) {
            return plain(format!(
                "wire v2: agent {:?} cannot represent multiple transaction parties",
                p.agent_id
            ));
        }
        required_scope_v2(&p.required_scope)
            .map_err(|e| e.context(format!("wire v2: party {:?} required_scope", p.party_id)))?;
        let Some(bundle) = &p.proof_bundle else {
            return plain(format!(
                "wire v2: party {:?} proof_bundle is required",
                p.party_id
            ));
        };
        if key_id_v2(&p.agent_pub_key).ok().as_deref() != Some(p.agent_id.as_str()) {
            return err(
                KeyIdMismatch,
                format!(
                    "wire v2: party {:?} agent ID does not match its complete public key",
                    p.party_id
                ),
            );
        }
        if !valid_prefixed_digest(&p.proof_bundle_hash) {
            return err(
                Malformed,
                format!(
                    "wire v2: party {:?} proof_bundle_hash is not sha384: followed by 96 lowercase hex characters",
                    p.party_id
                ),
            );
        }
        if bundle_hash_v2(bundle).ok().as_deref() != Some(p.proof_bundle_hash.as_str()) {
            return err(
                BundleHashMismatch,
                format!(
                    "wire v2: party {:?} proof_bundle_hash does not match its bundle",
                    p.party_id
                ),
            );
        }
        verify_proof_bundle_v2_signatures(bundle).map_err(|e| {
            e.context(format!(
                "wire v2: party {:?} proof bundle signature",
                p.party_id
            ))
        })?;
        if bundle.delegations.is_empty() {
            // SPEC-v2 §5.7: a transaction party must present delegated
            // authority; an empty chain is rejected, never evaluated.
            return err(
                TransactionPartyMismatch,
                format!(
                    "wire v2: party {:?} proof bundle has no delegation certificates",
                    p.party_id
                ),
            );
        }
        if bundle.agent_id != p.agent_id
            || !equal_keys(&bundle.agent_pub_key, &p.agent_pub_key)
            || bundle.verifier_id != p.verifier_id
            || bundle.delegations.first().map(|c| c.subject_id.as_str())
                != Some(p.agent_id.as_str())
        {
            return err(
                TransactionPartyMismatch,
                format!(
                    "wire v2: party {:?} proof bundle identity does not match its signed party",
                    p.party_id
                ),
            );
        }
        let expected = build_session_context_v2(&SessionContextV2Inputs {
            verifier_id: p.verifier_id.clone(),
            workspace_id: p.workspace_id.clone(),
            agent_id: p.agent_id.clone(),
            session_id: p.session_id.clone(),
            invocation_id: p.invocation_id.clone(),
            request_hash: transaction_party_request_hash_v2(&tx_hash, &p.required_scope),
        });
        let bound = matches!((expected, &bundle.session_context), (Ok(e), Some(s)) if e == *s);
        if !bound {
            return err(
                TransactionContextMismatch,
                format!(
                    "wire v2: party {:?} proof bundle session context does not bind this transaction and scope",
                    p.party_id
                ),
            );
        }
    }
    if require_signatures {
        if r.party_signatures.len() != r.parties.len() {
            return err(
                TransactionSignatureSetInvalid,
                "wire v2: transaction receipt must have one signature per party",
            );
        }
        for (i, s) in r.party_signatures.iter().enumerate() {
            if !r.parties.iter().any(|p| p.party_id == s.party_id)
                || r.party_signatures[..i]
                    .iter()
                    .any(|q| q.party_id == s.party_id)
            {
                return err(
                    TransactionSignatureSetInvalid,
                    format!(
                        "wire v2: unknown or duplicate transaction party signature {:?}",
                        s.party_id
                    ),
                );
            }
        }
    }
    transaction_receipt_v2_sign_bytes(r).map(|_| ())
}

/// Check party signatures, bundle hashes and signatures, party-key bindings,
/// and transaction-derived session contexts. Trust and status are not evaluated.
pub fn verify_transaction_receipt_v2_signatures(r: &TransactionReceiptV2) -> V2Result<()> {
    use V2ErrorClass::*;
    validate(r, true).classify(Malformed)?;
    let signable = transaction_receipt_v2_sign_bytes(r).classify(Malformed)?;
    for (i, s) in r.party_signatures.iter().enumerate() {
        if r.party_signatures[..i]
            .iter()
            .any(|q| q.party_id == s.party_id)
        {
            return err(
                TransactionSignatureSetInvalid,
                "v2 transaction receipt has duplicate party signature",
            );
        }
    }
    if r.party_signatures.len() != r.parties.len() {
        return err(
            TransactionSignatureSetInvalid,
            "v2 transaction receipt must contain exactly one signature per party",
        );
    }
    for p in &r.parties {
        let Some(s) = r.party_signatures.iter().find(|s| s.party_id == p.party_id) else {
            return err(
                TransactionSignatureSetInvalid,
                format!(
                    "v2 transaction receipt is missing signature for party {:?}",
                    p.party_id
                ),
            );
        };
        verify_v2_statement(
            V2ObjectType::TransactionPartyStatement,
            &signable,
            &s.signature,
            &p.agent_pub_key,
        )
        .map_err(|e| {
            e.context(format!(
                "v2 transaction receipt signature for party {:?}",
                p.party_id
            ))
        })?;
    }
    Ok(())
}

/// Sign the shared transaction statement with one party's key.
pub fn sign_transaction_receipt_party_v2(
    r: &TransactionReceiptV2,
    party_id: &str,
    key: &HybridPrivateKey,
) -> V2SignResult<TransactionReceiptSignatureV2> {
    sign_transaction_receipt_party_v2_with_signer(&V2Context::background(), r, party_id, &LocalSignerV2::new(key)?)
}

/// [`sign_transaction_receipt_party_v2`] with an external signer whose
/// complete key must equal the party agent key.
pub fn sign_transaction_receipt_party_v2_with_signer(
    ctx: &V2Context,
    r: &TransactionReceiptV2,
    party_id: &str,
    signer: &dyn SignerV2,
) -> V2SignResult<TransactionReceiptSignatureV2> {
    let Some(party) = r.parties.iter().find(|p| p.party_id == party_id) else {
        return Err(V2SignError::InvalidObject(V2Error::new(
            V2ErrorClass::TransactionPartyMismatch,
            format!("party {party_id:?} is not listed in the transaction receipt"),
        )));
    };
    let party_public = signer_public_key_v2(signer)?;
    if !equal_keys(&party_public, &party.agent_pub_key) {
        return Err(V2SignError::KeyBinding(format!(
            "signing key does not match party {party_id:?} agent public key"
        )));
    }
    validate(r, false)
        .map_err(|e| e.context("cannot sign invalid transaction receipt"))
        .classify(V2ErrorClass::Malformed)?;
    let signable = transaction_receipt_v2_sign_bytes(r).classify(V2ErrorClass::Malformed)?;
    Ok(TransactionReceiptSignatureV2 {
        party_id: party_id.to_string(),
        signature: sign_v2_statement_with_signer(
            ctx,
            V2ObjectType::TransactionPartyStatement,
            &signable,
            signer,
            &party_public,
        )?,
    })
}

fn encode_canonical(r: &TransactionReceiptV2) -> V2Result<Vec<u8>> {
    let mut parties = Vec::new();
    for p in &r.parties {
        let bundle = p
            .proof_bundle
            .as_ref()
            .ok_or_else(|| super::errors::V2Error::plain("proof_bundle is required"))?;
        let raw =
            String::from_utf8(encode_proof_bundle_v2(bundle)?).expect("canonical JSON is UTF-8");
        parties.push(CJ::obj(vec![
            ("agent_id", CJ::s(&p.agent_id)),
            ("agent_pub_key", CJ::key(&p.agent_pub_key)),
            ("invocation_id", CJ::s(&p.invocation_id)),
            ("party_id", CJ::s(&p.party_id)),
            ("proof_bundle", CJ::Raw(raw)),
            ("proof_bundle_hash", CJ::s(&p.proof_bundle_hash)),
            ("required_scope", CJ::s(&p.required_scope)),
            ("role", CJ::s(&p.role)),
            ("session_id", CJ::s(&p.session_id)),
            ("verifier_id", CJ::s(&p.verifier_id)),
            ("workspace_id", CJ::s(&p.workspace_id)),
        ]));
    }
    let mut sigs: Vec<&TransactionReceiptSignatureV2> = r.party_signatures.iter().collect();
    sigs.sort_by(|a, b| a.party_id.as_bytes().cmp(b.party_id.as_bytes()));
    let encoded = canonical(&CJ::obj(vec![
        ("created_at", CJ::Int(r.created_at)),
        ("parties", CJ::Arr(parties)),
        (
            "party_signatures",
            CJ::Arr(
                sigs.into_iter()
                    .map(|s| {
                        CJ::obj(vec![
                            ("party_id", CJ::s(&s.party_id)),
                            ("signature", CJ::sig(&s.signature)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "terms_canonical_json",
            CJ::Bytes(r.terms_canonical_json.clone()),
        ),
        ("terms_schema_uri", CJ::s(&r.terms_schema_uri)),
        ("transaction_id", CJ::s(&r.transaction_id)),
        ("version", CJ::Int(r.version)),
    ]))?;
    if encoded.len() > MAX_TRANSACTION_RECEIPT_BYTES_V2 {
        return plain("wire v2: transaction receipt exceeds MAX_TRANSACTION_RECEIPT_BYTES_V2");
    }
    Ok(encoded)
}

/// Canonical wire JSON after verifying all party and embedded signatures.
pub fn encode_transaction_receipt_v2(r: &TransactionReceiptV2) -> V2Result<Vec<u8>> {
    verify_transaction_receipt_v2_signatures(r)?;
    encode_canonical(r)
}

/// Strictly decode and verify a transaction receipt (party signatures,
/// embedded bundle identity, hashes, and context bindings).
pub fn decode_transaction_receipt_v2(data: &[u8]) -> V2Result<TransactionReceiptV2> {
    (|| {
        check_v2_wire_size(
            data,
            "transaction receipt",
            "MAX_TRANSACTION_RECEIPT_BYTES_V2",
            MAX_TRANSACTION_RECEIPT_BYTES_V2,
        )?;
        let root = parse_wire(data, &["terms_canonical_json"], &[])?;
        let o = obj(&root)?;
        o.require(TOP, &[])?;
        if o.array("parties")?.len() > MAX_TRANSACTION_PARTIES {
            return plain("wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES");
        }
        o.only(TOP)?;
        let mut raw_bundles = Vec::new();
        let mut parties = Vec::new();
        for n in o.array("parties")? {
            let p = obj(n)?;
            p.only(PARTY)?;
            p.require(PARTY, &[])?;
            raw_bundles.push(p.get("proof_bundle").map(|b| &data[b.start..b.end]).unwrap_or(&[]));
            parties.push(TransactionReceiptPartyV2 {
                party_id: p.str("party_id")?,
                role: p.str("role")?,
                agent_id: p.str("agent_id")?,
                agent_pub_key: p.pub_key("agent_pub_key")?,
                verifier_id: p.str("verifier_id")?,
                workspace_id: p.str("workspace_id")?,
                session_id: p.str("session_id")?,
                invocation_id: p.str("invocation_id")?,
                required_scope: p.str("required_scope")?,
                proof_bundle_hash: p.str("proof_bundle_hash")?,
                proof_bundle: None,
            });
        }
        let mut party_signatures = Vec::new();
        for n in o.array("party_signatures")? {
            let s = obj(n)?;
            s.only(&["party_id", "signature"])?;
            s.require(&["party_id", "signature"], &[])?;
            party_signatures.push(TransactionReceiptSignatureV2 {
                party_id: s.str("party_id")?,
                signature: s.sig("signature")?,
            });
        }
        let mut r = TransactionReceiptV2 {
            version: o.i64("version")?,
            transaction_id: o.str("transaction_id")?,
            created_at: o.i64("created_at")?,
            terms_schema_uri: o.str("terms_schema_uri")?,
            terms_canonical_json: o.bytes("terms_canonical_json")?,
            parties,
            party_signatures,
        };
        for (p, raw) in r.parties.iter_mut().zip(raw_bundles) {
            if !raw.starts_with(b"{") {
                return plain("wire v2: party proof_bundle must be a JSON object");
            }
            // The nested bundle is decoded strictly, and must be in canonical
            // form like the whole receipt, before its hash is compared, so a
            // malformed bundle is malformed rather than bundle_hash_mismatch.
            let bundle =
                decode_proof_bundle_v2(raw).map_err(|e| e.context(format!("wire v2: party {:?} proof bundle", p.party_id)))?;
            if !encode_proof_bundle_v2(&bundle).is_ok_and(|canonical| canonical == raw) {
                return plain(format!("wire v2: party {:?} proof bundle is not canonical JSON", p.party_id));
            }
            // The hash field's shape is checked before it is compared (SPEC-v2
            // §5.7, §2.7): a misshapen value is malformed, not a mismatch.
            if !valid_prefixed_digest(&p.proof_bundle_hash) {
                return err(
                    V2ErrorClass::Malformed,
                    format!(
                        "wire v2: party {:?} proof_bundle_hash is not sha384: followed by 96 lowercase hex characters",
                        p.party_id
                    ),
                );
            }
            if p.proof_bundle_hash != bundle_hash_of_bytes(raw) {
                return err(
                    V2ErrorClass::BundleHashMismatch,
                    format!("wire v2: party {:?} proof_bundle_hash does not match its canonical bundle bytes", p.party_id),
                );
            }
            p.proof_bundle = Some(bundle);
        }
        verify_transaction_receipt_v2_signatures(&r)?;
        if encode_canonical(&r)? != data {
            return plain("wire v2: transaction receipt is not canonical JSON");
        }
        Ok(r)
    })()
    .classify(V2ErrorClass::Malformed)
}
