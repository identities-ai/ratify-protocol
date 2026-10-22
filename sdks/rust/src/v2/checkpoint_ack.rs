//! Independent checkpoint acknowledgement wire form (SPEC-v2 §7.8). Mirrors
//! Go `checkpoint_ack_v2.go`; the struct itself is declared in Go
//! `release_v2.go`.

use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::crypto::lower_hex;
use super::errors::{plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, obj, parse_wire, CJ};
use super::limits::{
    check_v2_wire_size, valid_v2_timestamp, MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2,
};
use super::wire::MAX_SAFE;

/// An independent checkpoint's acknowledgement of one receipt-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2CheckpointAcknowledgement {
    pub log_id: String,
    pub sequence: i64,
    pub entry_hash: Vec<u8>,
    pub timestamp: i64,
}

const CHECKPOINT_ACKNOWLEDGEMENT_V2_FIELDS: &[&str] =
    &["entry_hash", "log_id", "sequence", "timestamp"];

fn validate_v2_checkpoint_acknowledgement(ack: &V2CheckpointAcknowledgement) -> V2Result<()> {
    if ack.log_id.len() != 32
        || !lower_hex(&ack.log_id)
        || ack.sequence < 1
        || ack.sequence > MAX_SAFE
        || ack.entry_hash.len() != 48
        || !valid_v2_timestamp(ack.timestamp)
    {
        return plain(
            "wire v2: checkpoint acknowledgement log_id, sequence, entry_hash, or timestamp is invalid",
        );
    }
    Ok(())
}

/// The canonical JSON wire form of an independent checkpoint
/// acknowledgement: `{"entry_hash":<base64 of 48 bytes>,"log_id":<32
/// lowercase hex>,"sequence":<integer>,"timestamp":<integer>}` (class
/// `malformed` on failure).
pub fn encode_v2_checkpoint_acknowledgement(
    ack: &V2CheckpointAcknowledgement,
) -> V2Result<Vec<u8>> {
    validate_v2_checkpoint_acknowledgement(ack).classify(V2ErrorClass::Malformed)?;
    canonical(&CJ::obj(vec![
        ("entry_hash", CJ::Str(STANDARD.encode(&ack.entry_hash))),
        ("log_id", CJ::s(&ack.log_id)),
        ("sequence", CJ::Int(ack.sequence)),
        ("timestamp", CJ::Int(ack.timestamp)),
    ]))
    .classify(V2ErrorClass::Malformed)
}

/// Strictly decode the acknowledgement wire form; only the canonical
/// encoding is accepted (class `malformed` on failure).
pub fn decode_v2_checkpoint_acknowledgement(data: &[u8]) -> V2Result<V2CheckpointAcknowledgement> {
    (|| {
        check_v2_wire_size(
            data,
            "checkpoint acknowledgement",
            "MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2",
            MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2,
        )?;
        let root = parse_wire(data, &["entry_hash"], &[])?;
        let o = obj(&root)?;
        o.require(CHECKPOINT_ACKNOWLEDGEMENT_V2_FIELDS, &[])?;
        o.only(CHECKPOINT_ACKNOWLEDGEMENT_V2_FIELDS)?;
        let entry_hash_text = o.str("entry_hash")?;
        let log_id = o.str("log_id")?;
        let sequence = o.i64("sequence")?;
        let timestamp = o.i64("timestamp")?;
        let entry_hash = STANDARD
            .decode(&entry_hash_text)
            .ok()
            .filter(|h| STANDARD.encode(h) == entry_hash_text)
            .ok_or_else(|| {
                V2Error::plain(
                    "wire v2: checkpoint acknowledgement entry_hash is not canonical base64",
                )
            })?;
        let ack = V2CheckpointAcknowledgement {
            log_id,
            sequence,
            entry_hash,
            timestamp,
        };
        let canonical_bytes = encode_v2_checkpoint_acknowledgement(&ack)?;
        if canonical_bytes != data {
            return plain("wire v2: checkpoint acknowledgement is not canonically encoded");
        }
        Ok(ack)
    })()
    .classify(V2ErrorClass::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack() -> V2CheckpointAcknowledgement {
        V2CheckpointAcknowledgement {
            log_id: "0123456789abcdef0123456789abcdef".into(),
            sequence: 7,
            entry_hash: vec![0xab; 48],
            timestamp: 1_800_000_000,
        }
    }

    #[test]
    fn round_trip_is_canonical_only() {
        let wire = encode_v2_checkpoint_acknowledgement(&ack()).expect("encode");
        assert_eq!(
            String::from_utf8(wire.clone()).expect("utf8"),
            format!(
                "{{\"entry_hash\":\"{}\",\"log_id\":\"0123456789abcdef0123456789abcdef\",\"sequence\":7,\"timestamp\":1800000000}}",
                STANDARD.encode([0xab; 48])
            )
        );
        assert_eq!(
            decode_v2_checkpoint_acknowledgement(&wire).expect("decode"),
            ack()
        );
        let spaced = String::from_utf8(wire.clone())
            .expect("utf8")
            .replace(",", ", ");
        let reordered = String::from_utf8(wire).expect("utf8").replace(
            "\"sequence\":7,\"timestamp\":1800000000",
            "\"timestamp\":1800000000,\"sequence\":7",
        );
        for bad in [spaced, reordered, "{}".into(), "null".into()] {
            let e =
                decode_v2_checkpoint_acknowledgement(bad.as_bytes()).expect_err("non-canonical");
            assert_eq!(e.class, V2ErrorClass::Malformed);
        }
        for mutate in [
            |a: &mut V2CheckpointAcknowledgement| {
                a.log_id = "0123456789ABCDEF0123456789abcdef".into()
            },
            |a: &mut V2CheckpointAcknowledgement| a.sequence = 0,
            |a: &mut V2CheckpointAcknowledgement| a.entry_hash.pop().map(|_| ()).unwrap_or(()),
            |a: &mut V2CheckpointAcknowledgement| a.timestamp = -1,
        ] {
            let mut a = ack();
            mutate(&mut a);
            assert_eq!(
                encode_v2_checkpoint_acknowledgement(&a)
                    .expect_err("invalid")
                    .class,
                V2ErrorClass::Malformed
            );
        }
    }

    #[test]
    fn size_limit_is_checked_before_parsing() {
        let wire = encode_v2_checkpoint_acknowledgement(&ack()).expect("encode");
        // At the limit: the size gate passes and the canonical check rejects
        // the padding; at limit + 1 the size gate itself rejects.
        let mut at_limit = wire.clone();
        at_limit.resize(MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2, b' ');
        let e = decode_v2_checkpoint_acknowledgement(&at_limit).expect_err("padded");
        assert!(
            !e.message
                .contains("MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2"),
            "{}",
            e.message
        );
        let mut over = wire;
        over.resize(MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2 + 1, b' ');
        let e = decode_v2_checkpoint_acknowledgement(&over).expect_err("limit+1");
        assert_eq!(e.class, V2ErrorClass::Malformed);
        assert!(
            e.message
                .contains("MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2"),
            "{}",
            e.message
        );
    }
}
