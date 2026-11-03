import Foundation
import Security

/// A parsed key storage record (sdks/swift/KEY_STORAGE.md): the documented,
/// implementation-neutral form a key is stored in.
public struct KeyStorageRecord: Sendable {
    public enum RecordType: UInt8, Sendable {
        /// An Ed25519 seed and an ML-DSA-65 seed held in software.
        case software = 0x01
        /// An Ed25519 seed and a Secure Enclave ML-DSA-65 key (device-bound).
        case secureEnclaveHybrid = 0x02
        /// An ML-DSA-65 seed and an Android Keystore Ed25519 key.
        case androidSplit = 0x03
    }

    public let recordType: RecordType
    public let keyId: String
    /// The cleartext header bytes (bound as associated data where encrypted).
    public let header: Data
    let fields: [UInt8: Data]

    /// Parse and validate a record. Throws `malformed` for any deviation
    /// from the documented format.
    public init(_ data: Data) throws(RatifyError) {
        let r = try ffi { try ffiParseStorageRecord(data: data) }
        guard let t = RecordType(rawValue: r.recordType) else { throw .protocol(.malformed, message: "unknown record type") }
        recordType = t
        keyId = r.keyId
        header = r.header
        fields = Dictionary(uniqueKeysWithValues: r.fields.map { ($0.tag, $0.value) })
    }
}

extension SoftwarePrivateKey {
    /// This key's storage record (type 0x01: its two seeds). The record is
    /// key material: store it only in protected storage and wipe your copy.
    public func storageRecord() throws(RatifyError) -> Data {
        try ffi { try handle.storageRecord() }
    }

    /// Load a key from its storage record. The key is re-derived from the
    /// seeds; a record whose seeds derive another key ID is refused with
    /// `keyIdMismatch`.
    public convenience init(storageRecord: Data) throws(RatifyError) {
        try self.init(handle: try ffi { try FfiSoftwareKey.fromStorageRecord(data: storageRecord) })
    }
}

/// Stores software keys in the Keychain (build plan §4.3): one
/// generic-password item per key, service `com.ratifyprotocol.v2.key`,
/// account = the key ID, data = the storage record, available only when the
/// device is unlocked, never synchronized, never leaves this device.
public struct KeychainKeyStore: Sendable {
    public static let service = "com.ratifyprotocol.v2.key"
    /// An optional Keychain access group, to share keys between your apps.
    public let accessGroup: String?

    public init(accessGroup: String? = nil) { self.accessGroup = accessGroup }

    private func query(_ keyId: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: keyId,
            kSecAttrSynchronizable as String: false,
        ]
        if let g = accessGroup { q[kSecAttrAccessGroup as String] = g }
        return q
    }

    /// Store a key. Fails with `configurationInvalid` if one with this ID exists.
    public func save(_ key: SoftwarePrivateKey) throws(RatifyError) {
        try saveRecord(try key.storageRecord(), keyId: key.keyId)
    }

    /// Store a Secure Enclave key's (device-bound) record.
    @available(iOS 26.0, macOS 26.0, *)
    public func save(_ key: SecureEnclaveKey) throws(RatifyError) {
        try saveRecord(try key.storageRecord(), keyId: key.keyId)
    }

    /// Load the Secure Enclave key with this ID, or nil if none is stored.
    @available(iOS 26.0, macOS 26.0, *)
    public func loadSecureEnclaveKey(keyId: String) throws(RatifyError) -> SecureEnclaveKey? {
        guard var record = try loadRecord(keyId) else { return nil }
        defer { record.resetBytes(in: 0..<record.count) }
        let key = try SecureEnclaveKey(storageRecord: record)
        guard key.keyId == keyId else { throw .protocol(.keyIdMismatch, message: "stored record names another key") }
        return key
    }

    private func saveRecord(_ data: Data, keyId: String) throws(RatifyError) {
        var record = data
        defer { record.resetBytes(in: 0..<record.count) }
        var q = query(keyId)
        q[kSecValueData as String] = record
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw .protocol(.configurationInvalid, message: "keychain refused to store the key (OSStatus \(status))")
        }
    }

    private func loadRecord(_ keyId: String) throws(RatifyError) -> Data? {
        var q = query(keyId)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let record = out as? Data else {
            throw .protocol(.configurationInvalid, message: "keychain refused to load the key (OSStatus \(status))")
        }
        return record
    }

    /// Load the software key with this ID, or nil if none is stored.
    public func load(keyId: String) throws(RatifyError) -> SoftwarePrivateKey? {
        guard var record = try loadRecord(keyId) else { return nil }
        defer { record.resetBytes(in: 0..<record.count) }
        let key = try SoftwarePrivateKey(storageRecord: record)
        guard key.keyId == keyId else {
            throw .protocol(.keyIdMismatch, message: "stored record names another key")
        }
        return key
    }

    /// Delete the key with this ID; deleting an absent key succeeds.
    public func delete(keyId: String) throws(RatifyError) {
        let status = SecItemDelete(query(keyId) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw .protocol(.configurationInvalid, message: "keychain refused to delete the key (OSStatus \(status))")
        }
    }
}
