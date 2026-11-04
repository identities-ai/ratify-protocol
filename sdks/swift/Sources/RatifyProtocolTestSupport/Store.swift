import Foundation
@_spi(TestSupport) import RatifyProtocol

/// Rust Part B reference store for conformance tests.
public final class Store: Sendable {
    private let bridge: ReferenceStoreBridge

    public init(now: Int64, leaseSeconds: Int64, logId: String, verifierKey: SoftwarePrivateKey) throws(RatifyError) {
        bridge = try ReferenceStoreBridge(now: now, leaseSeconds: leaseSeconds, logId: logId, verifierKey: verifierKey)
    }

    private init(_ bridge: ReferenceStoreBridge) { self.bridge = bridge }

    public func cloneStore() throws(RatifyError) -> Store { try Store(bridge.cloneStore()) }
    public func setTime(_ now: Int64) throws(RatifyError) { try bridge.setTime(now) }
    public func now() throws(RatifyError) -> Int64 { try bridge.now() }
    public func setSignerFailure(_ failing: Bool) throws(RatifyError) { try bridge.setSignerFailure(failing) }
    public func setAcknowledgementWithheld(_ withheld: Bool) throws(RatifyError) { try bridge.setAcknowledgementWithheld(withheld) }
    public func logLength() throws(RatifyError) -> UInt64 { try bridge.logLength() }
    public func plantReleaseTestOnly(claimId: String, ackTimestamp: Int64) throws(RatifyError) {
        try bridge.plantReleaseTestOnly(claimId: claimId, ackTimestamp: ackTimestamp)
    }
    public func abandonPendingReceipts() throws(RatifyError) -> [String] { try bridge.abandonPendingReceipts() }
}
