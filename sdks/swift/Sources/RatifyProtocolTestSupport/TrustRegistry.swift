@_spi(TestSupport) import RatifyProtocol

/// Rust candidate-record trust resolver for conformance tests.
public final class TrustRegistry: TrustProvider, Sendable {
    private let bridge: ReferenceTrustRegistryBridge

    public init(records: [HybridPublicKey]) throws(RatifyError) {
        bridge = try ReferenceTrustRegistryBridge(records: records)
    }

    public func resolve(chain: [DelegationCert]) async throws -> TrustResolution {
        try bridge.resolve(chain: chain)
    }
}
