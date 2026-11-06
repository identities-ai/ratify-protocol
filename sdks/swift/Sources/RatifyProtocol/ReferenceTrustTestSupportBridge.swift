import Foundation

/// Candidate-record resolver for conformance tests. Records must come from authenticated configuration.
@_spi(TestSupport) public final class ReferenceTrustRegistryBridge: Sendable {
    private let handle: FfiReferenceTrustRegistry

    public init(records: [HybridPublicKey]) throws(RatifyError) {
        handle = try ffi { try ffiReferenceTrustRegistry(records: records.map(\.ffi)) }
    }

    public func resolve(chain: [DelegationCert]) throws(RatifyError) -> TrustResolution {
        let answer = try ffi { try handle.resolve(chain: chain.map(\.ffi)) }
        guard let outcome = TrustOutcome(rawValue: answer.outcome) else {
            throw RatifyError.internal(.panic, message: "unknown reference trust outcome")
        }
        return TrustResolution(outcome: outcome, rootKey: HybridPublicKey(answer.rootKey))
    }
}
