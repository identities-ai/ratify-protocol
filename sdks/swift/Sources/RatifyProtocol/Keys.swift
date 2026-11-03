import Foundation

/// A complete hybrid public key: Ed25519 (32 bytes) and ML-DSA-65 (1952 bytes).
public struct HybridPublicKey: Sendable, Hashable {
    public var ed25519: Data
    public var mlDsa65: Data

    public init(ed25519: Data, mlDsa65: Data) {
        self.ed25519 = ed25519
        self.mlDsa65 = mlDsa65
    }

    init(_ k: FfiPublicKey) {
        self.init(ed25519: k.ed25519, mlDsa65: k.mlDsa65)
    }

    var ffi: FfiPublicKey { FfiPublicKey(ed25519: ed25519, mlDsa65: mlDsa65) }
}

/// A hybrid Ed25519 + ML-DSA-65 private key held in software.
///
/// It is kept as its two 32-byte seeds (an Ed25519 seed and a FIPS 204
/// ML-DSA-65 seed), the documented storage form. The private key never
/// leaves the SDK except through the storage record.
public final class SoftwarePrivateKey: Sendable {
    let handle: FfiSoftwareKey

    /// The public half.
    public let publicKey: HybridPublicKey
    /// `key_id_v2` of the public key (64 lowercase hex characters).
    public let keyId: String

    private init(_ handle: FfiSoftwareKey) throws(RatifyError) {
        self.handle = handle
        self.publicKey = HybridPublicKey(try ffi { try handle.publicKey() })
        self.keyId = try ffi { try handle.keyId() }
    }

    /// Derive the key from its two 32-byte seeds.
    public convenience init(ed25519Seed: Data, mlDsa65Seed: Data) throws(RatifyError) {
        let h = try ffi { try FfiSoftwareKey.fromSeeds(ed25519Seed: ed25519Seed, mlDsa65Seed: mlDsa65Seed) }
        try self.init(h)
    }

    /// Generate a fresh key from the operating-system random source. Throws
    /// `internal(.randomSource)` if that source fails.
    public static func generate() throws(RatifyError) -> SoftwarePrivateKey {
        try SoftwarePrivateKey(try ffi { try FfiSoftwareKey.generate() })
    }
}

extension Ratify {
    /// `key_id_v2` of a complete public key (SPEC-v2 §2.3).
    public static func keyId(_ key: HybridPublicKey) throws(RatifyError) -> String {
        try ffi { try ffiKeyId(key: key.ffi) }
    }

    /// Whether `id` is a well-formed v2 key ID: 64 lowercase hex characters.
    public static func validId(_ id: String) throws(RatifyError) -> Bool {
        try ffi { try ffiValidId(id: id) }
    }
}
