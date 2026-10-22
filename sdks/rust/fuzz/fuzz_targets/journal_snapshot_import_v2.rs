#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::{
    export_security_journal_snapshot_v2, import_security_journal_snapshot_v2,
    security_journal_snapshot_digest_v2, SecurityJournalHeadV2,
};

// The importer decodes persisted, possibly corrupted bytes and must fail
// closed; an accepted snapshot must re-export byte for byte.
fuzz_target!(|data: &[u8]| {
    let head = SecurityJournalHeadV2 {
        generation: 0,
        digest: security_journal_snapshot_digest_v2(data),
    };
    if let Ok(journal) = import_security_journal_snapshot_v2(data, &head) {
        let again = export_security_journal_snapshot_v2(&journal).expect("imported snapshot re-exports");
        assert_eq!(again, data, "imported snapshot does not re-export identically");
    }
});
