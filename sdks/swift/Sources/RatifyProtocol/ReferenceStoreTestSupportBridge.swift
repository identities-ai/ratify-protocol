import Foundation

/// Internal bridge for the separately packaged reference store.
@_spi(TestSupport) public final class ReferenceStoreBridge: Sendable {
    private let handle: FfiReferenceStore

    public init(now: Int64, leaseSeconds: Int64, logId: String, verifierKey: SoftwarePrivateKey) throws(RatifyError) {
        handle = try ffi { try FfiReferenceStore(now: now, leaseSeconds: leaseSeconds, logId: logId, verifierKey: verifierKey.handle) }
    }

    private init(_ handle: FfiReferenceStore) { self.handle = handle }

    public func cloneStore() throws(RatifyError) -> ReferenceStoreBridge {
        try ReferenceStoreBridge(ffi { try handle.cloneStore() })
    }

    public func setTime(_ now: Int64) throws(RatifyError) { try ffi { try handle.setTime(now: now) } }
    public func now() throws(RatifyError) -> Int64 { try ffi { try handle.now() } }
    public func setSignerFailure(_ failing: Bool) throws(RatifyError) { try ffi { try handle.setSignerFailure(failing: failing) } }
    public func setAcknowledgementWithheld(_ withheld: Bool) throws(RatifyError) { try ffi { try handle.setAcknowledgementWithheld(withheld: withheld) } }
    public func logLength() throws(RatifyError) -> UInt64 { try ffi { try handle.logLength() } }
    public func plantReleaseTestOnly(claimId: String, ackTimestamp: Int64) throws(RatifyError) {
        try ffi { try handle.plantReleaseTestOnly(claimId: claimId, ackTimestamp: ackTimestamp) }
    }
    public func abandonPendingReceipts() throws(RatifyError) -> [String] { try ffi { try handle.abandonPendingReceipts() } }
}
