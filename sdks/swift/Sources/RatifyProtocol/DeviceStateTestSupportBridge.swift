import Foundation

/// Internal bridge used by the separately packaged test support module.
@_spi(TestSupport) public struct DeviceStateProjectionBridge: Sendable {
    public let claims: Data
    public let streams: Data
    public let rateCounters: Data
    public let receiptLog: Data
    public let issuanceRecords: Data
    public let projection: Data
    public let completeStateDigest: Data

    init(_ value: FfiDeviceStateProjectionTestOnly) {
        claims = value.claims
        streams = value.streams
        rateCounters = value.rateCounters
        receiptLog = value.receiptLog
        issuanceRecords = value.issuanceRecords
        projection = value.projection
        completeStateDigest = value.completeStateDigest
    }
}

@_spi(TestSupport) extension Ratify {
    public static func deviceStateProjectionTestOnly(_ stateJSON: Data) throws(RatifyError) -> DeviceStateProjectionBridge {
        DeviceStateProjectionBridge(try ffi { try ffiDeviceStateProjectionTestOnly(stateJson: stateJSON) })
    }
}
