//! Status evidence batch wire form (SPEC-v2 §6.5 step 3). Mirrors Go
//! `status_batch_v2.go`.
//!
//! A status provider that crosses a process or language boundary returns
//! this JSON array:
//!
//! ```text
//! [{"object":<complete signed RevocationList or RevocationPush>,"object_type_code":3|5}, ...]
//! ```
//!
//! with at most [`MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2`] entries and at most
//! [`MAX_STATUS_EVIDENCE_BATCH_BYTES_V2`] encoded bytes. Each entry has
//! exactly these two members. The batch may be empty. The canonical encoding
//! sorts each entry's members and re-encodes each object canonically; a
//! decoder accepts any strict JSON spelling and keeps each object's exact
//! received bytes, which the verifier then decodes and authenticates under
//! the object's own limits.

use super::errors::{err, plain, Classify, V2ErrorClass, V2Result};
use super::json::{obj, parse_wire_envelope, JV};
use super::limits::{
    check_v2_wire_size, MAX_STATUS_EVIDENCE_BATCH_BYTES_V2, MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2,
};
use super::status::{LIST, PUSH};
use super::status_provenance::{V2StatusEvidenceBatch, V2StatusEvidenceObject};
use super::wire::{
    decode_revocation_list_v2, decode_revocation_push_v2, encode_revocation_list_v2,
    encode_revocation_push_v2,
};

/// The canonical JSON encoding of `batch` (class `malformed` on any
/// failure). Every object must decode strictly under its code.
pub fn encode_v2_status_evidence_batch(batch: &V2StatusEvidenceBatch) -> V2Result<Vec<u8>> {
    if batch.objects.len() > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 {
        return err(
            V2ErrorClass::Malformed,
            format!("v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects"),
        );
    }
    let mut buf: Vec<u8> = vec![b'['];
    for (i, object) in batch.objects.iter().enumerate() {
        let canonical =
            match object.object_type {
                LIST => decode_revocation_list_v2(&object.wire)
                    .and_then(|l| encode_revocation_list_v2(&l)),
                PUSH => decode_revocation_push_v2(&object.wire)
                    .and_then(|p| encode_revocation_push_v2(&p)),
                other => plain(format!(
                    "v2 status batch object type 0x{other:04x} is not 3 or 5"
                )),
            }
            .classify(V2ErrorClass::Malformed)?;
        if i > 0 {
            buf.push(b',');
        }
        buf.extend_from_slice(br#"{"object":"#);
        buf.extend_from_slice(&canonical);
        buf.extend_from_slice(br#","object_type_code":"#);
        buf.extend_from_slice(object.object_type.to_string().as_bytes());
        buf.push(b'}');
    }
    buf.push(b']');
    if buf.len() > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2 {
        return err(
            V2ErrorClass::Malformed,
            format!("v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_BYTES_V2} bytes"),
        );
    }
    Ok(buf)
}

/// Strictly decode a status evidence batch. The byte limit is checked before
/// parsing; any violation is `malformed`. It checks the envelope only
/// (SPEC-v2 §6.5 step 3): a JSON array of at most 64 entries, each with
/// exactly `object` and `object_type_code`, the code 3 or 5, and each
/// `object` a JSON object, kept as received. It does not inspect or
/// authenticate the objects.
pub fn decode_v2_status_evidence_batch(data: &[u8]) -> V2Result<V2StatusEvidenceBatch> {
    (|| {
        check_v2_wire_size(
            data,
            "status evidence batch",
            "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2",
            MAX_STATUS_EVIDENCE_BATCH_BYTES_V2,
        )?;
        let root = parse_wire_envelope(data)?;
        let JV::Arr(entries) = &root.v else {
            return plain("wire v2: status evidence batch must be a JSON array of objects");
        };
        // Go decodes into []map[string]json.RawMessage: a null entry is a nil
        // map and fails the exact-members check below; any other non-object
        // fails to decode. Both are malformed.
        let mut views = Vec::with_capacity(entries.len());
        for entry in entries {
            match obj(entry) {
                Ok(o) => views.push(o),
                Err(_) => return plain("wire v2: status evidence batch must be a JSON array of objects"),
            }
        }
        if views.len() > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 {
            return plain(format!(
                "wire v2: status evidence batch exceeds {MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects"
            ));
        }
        let mut batch = V2StatusEvidenceBatch {
            objects: Vec::with_capacity(views.len()),
        };
        for entry in views {
            let (Some(code), Some(object)) = (entry.get("object_type_code"), entry.get("object")) else {
                return plain("wire v2: status evidence entry must have exactly object and object_type_code");
            };
            if entry.fields.len() != 2 {
                return plain("wire v2: status evidence entry must have exactly object and object_type_code");
            }
            let object_type = match &code.v {
                JV::Num(t) if t == "3" => LIST,
                JV::Num(t) if t == "5" => PUSH,
                _ => return plain("wire v2: status evidence object_type_code must be 3 or 5"),
            };
            if !matches!(object.v, JV::Obj(_)) {
                return plain("wire v2: status evidence object must be a JSON object");
            }
            let wire = data
                .get(object.start..object.end)
                .ok_or_else(|| super::errors::V2Error::plain("wire v2: status evidence object span"))?;
            batch.objects.push(V2StatusEvidenceObject {
                object_type,
                wire: wire.to_vec(),
            });
        }
        Ok(batch)
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Go `v2StatusEvidenceBatchEncodedLength`: the length of the batch wire
/// form carrying each object's bytes exactly as received, which is what the
/// byte limit bounds for a batch handed over as native values.
pub(crate) fn v2_status_evidence_batch_encoded_length(batch: &V2StatusEvidenceBatch) -> usize {
    let mut total: usize = 2; // [ ]
    for (i, object) in batch.objects.iter().enumerate() {
        if i > 0 {
            total = total.saturating_add(1);
        }
        total = total
            .saturating_add(r#"{"object":"#.len())
            .saturating_add(object.wire.len())
            .saturating_add(r#","object_type_code":"#.len())
            .saturating_add(object.object_type.to_string().len())
            .saturating_add(1);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid_keypair_from_seeds;
    use crate::types::HybridSignature;
    use crate::v2::crypto::key_id_v2;
    use crate::v2::wire::{sign_revocation_list_v2, RevocationListV2, RevokedCertV2};

    fn signed_list(revoked: usize, sequence: i64) -> (Vec<u8>, RevocationListV2) {
        let (public_key, private_key) = hybrid_keypair_from_seeds(&[3u8; 32], &[4u8; 32]);
        let issuer_id = key_id_v2(&public_key).expect("key id");
        let list = RevocationListV2 {
            version: 2,
            issuer_id: issuer_id.clone(),
            updated_at: 1_800_000_000,
            next_update: 1_800_000_600,
            sequence,
            revoked: (0..revoked)
                .map(|i| RevokedCertV2 {
                    cert_id: format!("c{i}"),
                })
                .collect(),
            signature: HybridSignature {
                ed25519: vec![],
                ml_dsa_65: vec![],
            },
        };
        let signed =
            sign_revocation_list_v2(&list, &issuer_id, &public_key, &private_key).expect("sign");
        (encode_revocation_list_v2(&signed).expect("encode"), signed)
    }

    #[test]
    fn round_trip_keeps_received_bytes_and_canonical_encoding() {
        let (wire, _) = signed_list(2, 1);
        let batch = V2StatusEvidenceBatch {
            objects: vec![V2StatusEvidenceObject {
                object_type: 3,
                wire: wire.clone(),
            }],
        };
        let encoded = encode_v2_status_evidence_batch(&batch).expect("encode");
        assert_eq!(
            decode_v2_status_evidence_batch(&encoded).expect("decode"),
            batch
        );
        assert_eq!(
            encoded.len(),
            v2_status_evidence_batch_encoded_length(&batch)
        );
        // Any strict spelling decodes and keeps the object's exact bytes.
        let spaced = format!(
            "[ {{ \"object_type_code\" : 3 , \"object\" : {} }} ]",
            String::from_utf8(wire.clone()).expect("utf8")
        );
        let decoded = decode_v2_status_evidence_batch(spaced.as_bytes()).expect("decode spaced");
        assert_eq!(decoded.objects[0].wire, wire);
        assert_eq!(
            decode_v2_status_evidence_batch(b"[]")
                .expect("empty")
                .objects
                .len(),
            0
        );
        for bad in [
            &b"null"[..],
            b"{}",
            b"[1]",
            b"[{\"object\":{},\"object_type_code\":4}]",
            b"[{\"object\":{},\"object_type_code\":3.0}]",
            b"[{\"object\":[],\"object_type_code\":3}]",
            b"[{\"object\":{},\"object_type_code\":3,\"x\":1}]",
            b"[{\"object_type_code\":3}]",
        ] {
            let e = decode_v2_status_evidence_batch(bad).expect_err("must reject");
            assert_eq!(
                e.class,
                V2ErrorClass::Malformed,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn object_count_limit_is_64() {
        let (wire, _) = signed_list(0, 1);
        let object = V2StatusEvidenceObject {
            object_type: 3,
            wire,
        };
        let at_limit = V2StatusEvidenceBatch {
            objects: vec![object.clone(); MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2],
        };
        let encoded = encode_v2_status_evidence_batch(&at_limit).expect("64 objects encode");
        assert_eq!(
            decode_v2_status_evidence_batch(&encoded)
                .expect("64 decode")
                .objects
                .len(),
            64
        );
        let over = V2StatusEvidenceBatch {
            objects: vec![object; MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 + 1],
        };
        assert_eq!(
            encode_v2_status_evidence_batch(&over)
                .expect_err("65")
                .class,
            V2ErrorClass::Malformed
        );
        // Build the 65-entry wire form by hand: the decoder rejects it too.
        let wire65 = {
            let single = encode_v2_status_evidence_batch(&V2StatusEvidenceBatch {
                objects: vec![at_limit.objects[0].clone()],
            })
            .expect("single");
            let inner = &single[1..single.len() - 1];
            let mut out = vec![b'['];
            for i in 0..65 {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(inner);
            }
            out.push(b']');
            out
        };
        assert_eq!(
            decode_v2_status_evidence_batch(&wire65)
                .expect_err("65 decode")
                .class,
            V2ErrorClass::Malformed
        );
    }

    #[test]
    fn byte_limit_is_checked_before_parsing() {
        let mut at_limit = vec![b' '; MAX_STATUS_EVIDENCE_BATCH_BYTES_V2];
        at_limit[0] = b'[';
        at_limit[1] = b']';
        assert!(decode_v2_status_evidence_batch(&at_limit)
            .expect("limit decodes")
            .objects
            .is_empty());
        let mut over = at_limit.clone();
        over.push(b' ');
        let e = decode_v2_status_evidence_batch(&over).expect_err("limit+1");
        assert_eq!(e.class, V2ErrorClass::Malformed);
        assert!(
            e.message.contains("MAX_STATUS_EVIDENCE_BATCH_BYTES_V2"),
            "{}",
            e.message
        );
        // Native batches are bounded by the length of the received-bytes form.
        let wire = vec![b'x'; MAX_STATUS_EVIDENCE_BATCH_BYTES_V2];
        let native = V2StatusEvidenceBatch {
            objects: vec![V2StatusEvidenceObject {
                object_type: 3,
                wire,
            }],
        };
        assert!(
            v2_status_evidence_batch_encoded_length(&native) > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2
        );
    }
}
