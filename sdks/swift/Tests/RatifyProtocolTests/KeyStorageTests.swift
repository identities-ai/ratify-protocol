import Foundation
import XCTest
import RatifyProtocol

/// The documented storage record and the Keychain store (build plan §4.3).
final class KeyStorageTests: XCTestCase {
    func testRecordRoundTripsAndIsTheDocumentedLayout() throws {
        let key = try SoftwarePrivateKey(ed25519Seed: Data(repeating: 0x41, count: 32), mlDsa65Seed: Data(repeating: 0xc1, count: 32))
        let record = try key.storageRecord()
        // "RFYK" || version 1 || type 0x01 || key_id_len 64 || key_id || 2 fields of 32 bytes.
        XCTAssertEqual(record.prefix(8), Data("RFYK".utf8) + Data([1, 1, 0, 64]))
        XCTAssertEqual(record.count, 8 + 64 + 1 + 2 * (3 + 32))
        let parsed = try KeyStorageRecord(record)
        XCTAssertEqual(parsed.recordType, .software)
        XCTAssertEqual(parsed.keyId, key.keyId)
        XCTAssertEqual(parsed.header, record.prefix(72))
        XCTAssertEqual(try SoftwarePrivateKey(storageRecord: record).keyId, key.keyId)
    }

    func testCorruptedTruncatedAndSwappedRecordsAreRefused() throws {
        let key = try SoftwarePrivateKey.generate()
        let record = try key.storageRecord()
        func load(_ mutate: (inout Data) -> Void) -> String {
            var r = record
            mutate(&r)
            return classOf { _ = try SoftwarePrivateKey(storageRecord: r) }
        }
        XCTAssertEqual(load { $0.removeLast() }, "malformed")
        XCTAssertEqual(load { $0.append(0) }, "malformed")
        XCTAssertEqual(load { $0[4] = 2 }, "malformed", "unknown version")
        XCTAssertEqual(load { $0[0] = 0x58 }, "malformed", "bad magic")
        XCTAssertEqual(load { $0[76] ^= 1 }, "key_id_mismatch", "a seed that derives another key")
        let other = try SoftwarePrivateKey.generate()
        XCTAssertEqual(load { $0.replaceSubrange(8..<72, with: Data(other.keyId.utf8)) }, "key_id_mismatch", "swapped key ID")
    }

    #if os(macOS)
    /// An iOS package test bundle has no host app and so no Keychain
    /// entitlement (errSecMissingEntitlement); iOS Keychain runs in the
    /// host-app suite (build plan M5) and the device evidence run.
    func testKeychainStoresLoadsAndDeletes() throws {
        let store = KeychainKeyStore()
        let key = try SoftwarePrivateKey.generate()
        defer { try? store.delete(keyId: key.keyId) }
        XCTAssertNil(try store.load(keyId: key.keyId))
        try store.save(key)
        XCTAssertEqual(classOf { try store.save(key) }, "configuration_invalid", "a key is never silently replaced")
        let loaded = try XCTUnwrap(try store.load(keyId: key.keyId))
        XCTAssertEqual(loaded.keyId, key.keyId)
        XCTAssertEqual(loaded.publicKey, key.publicKey)
        try store.delete(keyId: key.keyId)
        XCTAssertNil(try store.load(keyId: key.keyId))
    }
    #endif
}

/// The published KEY_STORAGE.md vector is exactly what the SDK writes.
final class KeyStorageDocTests: XCTestCase {
    func testPublishedVectorMatchesTheSDK() throws {
        let doc = try String(contentsOf: Corpus.url("../../sdks/swift/KEY_STORAGE.md"), encoding: .utf8)
        let line = try XCTUnwrap(doc.components(separatedBy: "\n").first { $0.hasPrefix("5246594b") })
        let root = Fixture.shared.privateKey("root")
        XCTAssertEqual(try root.storageRecord().hex, line)
        XCTAssertTrue(doc.contains("has key ID `\(root.keyId)`"))
        let kotlin = try String(contentsOf: Corpus.url("../../sdks/kotlin/KEY_STORAGE.md"), encoding: .utf8)
        XCTAssertEqual(doc, kotlin, "the Swift and Kotlin copies are identical")
    }
}
