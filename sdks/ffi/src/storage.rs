//! The documented, implementation-neutral key storage record (build plan
//! §4.3; published in sdks/swift/KEY_STORAGE.md and sdks/kotlin/KEY_STORAGE.md):
//!
//! ```text
//! record = "RFYK" || version u8 (= 1) || record_type u8
//!          || key_id_len u16 (big-endian) || key_id (ASCII, 64 lowercase hex)
//!          || field_count u8 || field*
//! field  = tag u8 || len u16 (big-endian) || bytes[len]
//! ```
//!
//! The header is everything before `field_count`; Android binds it as the
//! AES-GCM associated data. Record types and their fields (each exactly once):
//!
//! | type | meaning           | fields                                                     |
//! |------|-------------------|------------------------------------------------------------|
//! | 0x01 | software key      | 0x01 ed25519_seed[32], 0x02 mldsa65_seed[32]               |
//! | 0x02 | Apple SE hybrid   | 0x01 ed25519_seed[32], 0x03 mldsa65_public[1952], 0x04 se_data_representation[1..] |
//! | 0x03 | Android split     | 0x02 mldsa65_seed[32], 0x05 ed25519_public[32], 0x06 keystore_alias[1..] |
//!
//! Anything else is refused as `malformed`: an unknown version, type or tag,
//! a missing or duplicate tag, a wrong length, or trailing bytes. A record
//! whose fields derive a key ID other than the recorded one is refused as
//! `key_id_mismatch`. Future versions are read-old/write-new.

use std::sync::Arc;

use ratify_protocol::v2::{valid_v2_id, V2ErrorClass};
use zeroize::Zeroizing;

use crate::error::{protocol, FfiError, FfiResult};
use crate::guard::{call, call_on};
use crate::keys::FfiSoftwareKey;

pub const MAGIC: &[u8; 4] = b"RFYK";
pub const VERSION: u8 = 1;
pub const TYPE_SOFTWARE: u8 = 0x01;
pub const TYPE_SECURE_ENCLAVE: u8 = 0x02;
pub const TYPE_ANDROID_SPLIT: u8 = 0x03;

pub const TAG_ED25519_SEED: u8 = 0x01;
pub const TAG_MLDSA65_SEED: u8 = 0x02;
pub const TAG_MLDSA65_PUBLIC: u8 = 0x03;
pub const TAG_SE_DATA: u8 = 0x04;
pub const TAG_ED25519_PUBLIC: u8 = 0x05;
pub const TAG_KEYSTORE_ALIAS: u8 = 0x06;

/// Each record type's fields, in canonical order, with a fixed length or
/// `None` for variable (1..=u16::MAX bytes).
fn schema(record_type: u8) -> Option<&'static [(u8, Option<usize>)]> {
    match record_type {
        TYPE_SOFTWARE => Some(&[(TAG_ED25519_SEED, Some(32)), (TAG_MLDSA65_SEED, Some(32))]),
        TYPE_SECURE_ENCLAVE => Some(&[
            (TAG_ED25519_SEED, Some(32)),
            (TAG_MLDSA65_PUBLIC, Some(1952)),
            (TAG_SE_DATA, None),
        ]),
        TYPE_ANDROID_SPLIT => Some(&[
            (TAG_MLDSA65_SEED, Some(32)),
            (TAG_ED25519_PUBLIC, Some(32)),
            (TAG_KEYSTORE_ALIAS, None),
        ]),
        _ => None,
    }
}

fn malformed(m: impl Into<String>) -> FfiError {
    protocol(
        V2ErrorClass::Malformed,
        format!("key storage record: {}", m.into()),
    )
}

/// One record field. Seed values are key material; the caller wipes them.
#[derive(uniffi::Record, Clone)]
pub struct FfiStorageField {
    pub tag: u8,
    pub value: Vec<u8>,
}

impl std::fmt::Debug for FfiStorageField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FfiStorageField(tag {:#04x}, {} bytes)",
            self.tag,
            self.value.len()
        )
    }
}

/// A parsed, validated storage record.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStorageRecord {
    pub record_type: u8,
    pub key_id: String,
    /// Fields in canonical order for the record type.
    pub fields: Vec<FfiStorageField>,
    /// The cleartext header bytes (the Android AES-GCM associated data).
    pub header: Vec<u8>,
}

fn header(record_type: u8, key_id: &str) -> FfiResult<Vec<u8>> {
    if !valid_v2_id(key_id) {
        return Err(malformed("key ID is not 64 lowercase hex characters"));
    }
    let mut h = Vec::with_capacity(8 + key_id.len());
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.push(record_type);
    h.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    h.extend_from_slice(key_id.as_bytes());
    Ok(h)
}

/// Encode a record, validating it against its type's schema.
pub(crate) fn encode(
    record_type: u8,
    key_id: &str,
    fields: &[(u8, &[u8])],
) -> FfiResult<Zeroizing<Vec<u8>>> {
    let schema = schema(record_type)
        .ok_or_else(|| malformed(format!("unknown record type {record_type:#04x}")))?;
    if fields.len() != schema.len() {
        return Err(malformed("wrong number of fields for the record type"));
    }
    let mut out = Zeroizing::new(header(record_type, key_id)?);
    out.push(schema.len() as u8);
    for ((tag, value), (want_tag, want_len)) in fields.iter().zip(schema) {
        if tag != want_tag {
            return Err(malformed(format!(
                "field {tag:#04x} is not field {want_tag:#04x} of the record type"
            )));
        }
        let ok = match want_len {
            Some(n) => value.len() == *n,
            None => !value.is_empty() && value.len() <= u16::MAX as usize,
        };
        if !ok {
            return Err(malformed(format!(
                "field {tag:#04x} has the wrong length {}",
                value.len()
            )));
        }
        out.push(*tag);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// A parsed record whose field values are wiped when dropped (also on a
/// failed or partial parse). Loaders use this; only the explicit FFI parse
/// export copies values out.
pub(crate) struct SecretRecord {
    pub record_type: u8,
    pub key_id: String,
    pub header: Vec<u8>,
    pub fields: Vec<(u8, Zeroizing<Vec<u8>>)>,
}

impl SecretRecord {
    /// The value of a schema-validated field.
    pub(crate) fn field(&self, tag: u8) -> &[u8] {
        &self
            .fields
            .iter()
            .find(|(t, _)| *t == tag)
            .expect("schema-validated")
            .1
    }
}

/// Parse and validate a record (format only; key ID binding is checked by
/// the loader that derives the key).
pub(crate) fn parse_secret(data: &[u8]) -> FfiResult<SecretRecord> {
    let take = |at: &mut usize, n: usize| -> FfiResult<&[u8]> {
        let end = at
            .checked_add(n)
            .filter(|e| *e <= data.len())
            .ok_or_else(|| malformed("truncated"))?;
        let s = &data[*at..end];
        *at = end;
        Ok(s)
    };
    let mut at = 0;
    if take(&mut at, 4)? != MAGIC {
        return Err(malformed("bad magic"));
    }
    let version = take(&mut at, 1)?[0];
    if version != VERSION {
        return Err(malformed(format!("unknown version {version}")));
    }
    let record_type = take(&mut at, 1)?[0];
    let schema = schema(record_type)
        .ok_or_else(|| malformed(format!("unknown record type {record_type:#04x}")))?;
    let id_len = u16::from_be_bytes(take(&mut at, 2)?.try_into().unwrap()) as usize;
    let id = std::str::from_utf8(take(&mut at, id_len)?)
        .map_err(|_| malformed("key ID is not ASCII"))?
        .to_string();
    if !valid_v2_id(&id) {
        return Err(malformed("key ID is not 64 lowercase hex characters"));
    }
    let header = data[..at].to_vec();
    let count = take(&mut at, 1)?[0] as usize;
    if count != schema.len() {
        return Err(malformed("wrong number of fields for the record type"));
    }
    let mut fields: Vec<(u8, Zeroizing<Vec<u8>>)> = Vec::with_capacity(count);
    for (want_tag, want_len) in schema {
        let tag = take(&mut at, 1)?[0];
        if fields.iter().any(|(t, _)| *t == tag) {
            return Err(malformed(format!("duplicate field {tag:#04x}")));
        }
        if tag != *want_tag {
            return Err(malformed(format!("unexpected field {tag:#04x}")));
        }
        let len = u16::from_be_bytes(take(&mut at, 2)?.try_into().unwrap()) as usize;
        let ok = match want_len {
            Some(n) => len == *n,
            None => len > 0,
        };
        if !ok {
            return Err(malformed(format!(
                "field {tag:#04x} has the wrong length {len}"
            )));
        }
        fields.push((tag, Zeroizing::new(take(&mut at, len)?.to_vec())));
    }
    if at != data.len() {
        return Err(malformed("trailing bytes"));
    }
    Ok(SecretRecord {
        record_type,
        key_id: id,
        header,
        fields,
    })
}

/// The FFI form of a parsed record (field values copied out for the caller,
/// which wipes them).
pub(crate) fn parse(data: &[u8]) -> FfiResult<FfiStorageRecord> {
    let r = parse_secret(data)?;
    Ok(FfiStorageRecord {
        record_type: r.record_type,
        key_id: r.key_id.clone(),
        header: r.header.clone(),
        fields: r
            .fields
            .iter()
            .map(|(tag, v)| FfiStorageField {
                tag: *tag,
                value: v.to_vec(),
            })
            .collect(),
    })
}

/// Parse and validate any record type.
#[uniffi::export]
pub fn ffi_parse_storage_record(data: Vec<u8>) -> FfiResult<FfiStorageRecord> {
    call(|| {
        let data = Zeroizing::new(data);
        parse(&data)
    })
}

/// A record's header facts, without its fields (no key material crosses).
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStorageHeader {
    pub record_type: u8,
    pub key_id: String,
    /// The cleartext header bytes (the Android AES-GCM associated data).
    pub header: Vec<u8>,
}

/// Parse and validate a record, returning only its header facts.
#[uniffi::export]
pub fn ffi_parse_storage_header(data: Vec<u8>) -> FfiResult<FfiStorageHeader> {
    call(|| {
        let data = Zeroizing::new(data);
        let r = parse_secret(&data)?;
        Ok(FfiStorageHeader {
            record_type: r.record_type,
            key_id: r.key_id.clone(),
            header: r.header.clone(),
        })
    })
}

/// The Keystore alias a type 0x03 record names, or None for other types.
#[uniffi::export]
pub fn ffi_storage_record_keystore_alias(data: Vec<u8>) -> FfiResult<Option<String>> {
    call(|| {
        let data = Zeroizing::new(data);
        let r = parse_secret(&data)?;
        if r.record_type != TYPE_ANDROID_SPLIT {
            return Ok(None);
        }
        let alias = std::str::from_utf8(r.field(TAG_KEYSTORE_ALIAS))
            .map_err(|_| malformed("keystore alias is not ASCII"))?
            .to_string();
        Ok(Some(alias))
    })
}

/// Encode a record of any type, validating it against its schema.
#[uniffi::export]
pub fn ffi_encode_storage_record(
    record_type: u8,
    key_id: String,
    fields: Vec<FfiStorageField>,
) -> FfiResult<Vec<u8>> {
    call(move || {
        // The field values (seeds) are wiped when this call ends, on every path.
        let fields: Vec<(u8, Zeroizing<Vec<u8>>)> = fields
            .into_iter()
            .map(|f| (f.tag, Zeroizing::new(f.value)))
            .collect();
        let refs: Vec<(u8, &[u8])> = fields.iter().map(|(t, v)| (*t, v.as_slice())).collect();
        Ok(encode(record_type, &key_id, &refs)?.to_vec())
    })
}

#[uniffi::export]
impl FfiSoftwareKey {
    /// This key's type 0x01 storage record (its two seeds).
    pub fn storage_record(&self) -> FfiResult<Vec<u8>> {
        call_on(&self.poison, || {
            Ok(encode(
                TYPE_SOFTWARE,
                &self.key_id_str(),
                &[
                    (TAG_ED25519_SEED, &self.ed_seed[..]),
                    (TAG_MLDSA65_SEED, &self.ml_seed[..]),
                ],
            )?
            .to_vec())
        })
    }

    /// Load a software key from its type 0x01 storage record. The key is
    /// re-derived from the seeds and must match the recorded key ID.
    #[uniffi::constructor]
    pub fn from_storage_record(data: Vec<u8>) -> FfiResult<Arc<Self>> {
        call(|| {
            let data = Zeroizing::new(data);
            let r = parse_secret(&data)?;
            if r.record_type != TYPE_SOFTWARE {
                return Err(malformed(format!(
                    "record type {:#04x} is not a software key",
                    r.record_type
                )));
            }
            let key = FfiSoftwareKey::from_seed_slices(
                r.field(TAG_ED25519_SEED),
                r.field(TAG_MLDSA65_SEED),
            )?;
            if key.key_id_str() != r.key_id {
                return Err(protocol(
                    V2ErrorClass::KeyIdMismatch,
                    "key storage record: the seeds derive a key other than the recorded key ID",
                ));
            }
            Ok(key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Arc<FfiSoftwareKey> {
        FfiSoftwareKey::from_seeds(vec![0x41; 32], vec![0xc1; 32]).unwrap()
    }

    fn class(r: FfiResult<impl Sized>) -> String {
        match r {
            Err(FfiError::Protocol { class, .. }) => class,
            Err(e) => format!("{e}"),
            Ok(_) => "ok".into(),
        }
    }

    #[test]
    fn round_trip_and_layout() {
        let k = key();
        let rec = k.storage_record().unwrap();
        assert_eq!(&rec[..6], b"RFYK\x01\x01");
        assert_eq!(&rec[6..8], &[0, 64]);
        assert_eq!(rec.len(), 4 + 1 + 1 + 2 + 64 + 1 + 2 * (1 + 2 + 32));
        let again = FfiSoftwareKey::from_storage_record(rec.clone()).unwrap();
        assert_eq!(again.key_id().unwrap(), k.key_id().unwrap());
        let p = parse(&rec).unwrap();
        assert_eq!(p.header, rec[..72].to_vec());
    }

    #[test]
    fn every_malformation_is_refused() {
        let rec = key().storage_record().unwrap();
        let m = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut r = rec.clone();
            f(&mut r);
            class(FfiSoftwareKey::from_storage_record(r))
        };
        assert_eq!(m(&|r| r[0] = b'X'), "malformed", "magic");
        assert_eq!(m(&|r| r[4] = 2), "malformed", "unknown version");
        assert_eq!(m(&|r| r[5] = 9), "malformed", "unknown type");
        assert_eq!(m(&|r| r.truncate(r.len() - 1)), "malformed", "truncated");
        assert_eq!(m(&|r| r.push(0)), "malformed", "trailing bytes");
        assert_eq!(m(&|r| r[72] = 3), "malformed", "field count");
        assert_eq!(m(&|r| r[73] = 7), "malformed", "unknown tag");
        assert_eq!(m(&|r| r[73 + 3 + 32] = 1), "malformed", "duplicate tag");
        assert_eq!(m(&|r| r[75] = 31), "malformed", "wrong length");
        assert_eq!(m(&|r| r[8] = b'A'), "malformed", "uppercase key ID");
        // A record whose seeds derive another key.
        assert_eq!(m(&|r| r[76] ^= 1), "key_id_mismatch", "swapped seed");
        let other = FfiSoftwareKey::from_seeds(vec![1; 32], vec![2; 32]).unwrap();
        let mut swapped = rec.clone();
        swapped[8..72].copy_from_slice(other.key_id().unwrap().as_bytes());
        assert_eq!(
            class(FfiSoftwareKey::from_storage_record(swapped)),
            "key_id_mismatch",
            "swapped key ID"
        );
    }

    #[test]
    fn platform_record_types_validate_their_schema() {
        let id = key().key_id().unwrap();
        let se = encode(
            TYPE_SECURE_ENCLAVE,
            &id,
            &[(1, &[0; 32]), (3, &[0; 1952]), (4, b"opaque")],
        )
        .unwrap();
        assert_eq!(parse(&se).unwrap().record_type, TYPE_SECURE_ENCLAVE);
        let android = encode(
            TYPE_ANDROID_SPLIT,
            &id,
            &[(2, &[0; 32]), (5, &[0; 32]), (6, b"ratify.v2.ed25519.x")],
        )
        .unwrap();
        assert_eq!(
            parse(&android).unwrap().fields[2].value,
            b"ratify.v2.ed25519.x"
        );
        assert!(
            encode(
                TYPE_SECURE_ENCLAVE,
                &id,
                &[(1, &[0; 32]), (3, &[0; 1952]), (4, b"")]
            )
            .is_err(),
            "empty variable field"
        );
        assert_eq!(
            class(FfiSoftwareKey::from_storage_record(android.to_vec())),
            "malformed",
            "not a software record"
        );
    }
}
