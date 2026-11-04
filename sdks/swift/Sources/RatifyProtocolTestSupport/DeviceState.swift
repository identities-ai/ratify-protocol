import Foundation
@_spi(TestSupport) import RatifyProtocol

/// §7.13 canonical projection members from a reference primary. Test fixtures only.
public struct DeviceStateProjection: Sendable {
    public let claims: Data
    public let streams: Data
    public let rateCounters: Data
    public let receiptLog: Data
    public let issuanceRecords: Data
    public let projection: Data
    public let completeStateDigest: Data

    public init(stateJSON: Data) throws(RatifyError) {
        let value = try Ratify.deviceStateProjectionTestOnly(stateJSON)
        claims = value.claims
        streams = value.streams
        rateCounters = value.rateCounters
        receiptLog = value.receiptLog
        issuanceRecords = value.issuanceRecords
        projection = value.projection
        completeStateDigest = value.completeStateDigest
    }
}
