import Foundation
@_spi(TestSupport) import RatifyProtocol

public struct DeviceReply: Sendable {
    public let acknowledged: [Int64]
    public let ackTime: Int64?
    public let failure: String?
    init(_ value: OfflineDeviceReplyBridge) {
        acknowledged = value.acknowledged
        ackTime = value.ackTime
        failure = value.failure
    }
}

/// Single-device reference checkpoint and outbox for conformance tests.
public final class OfflineDevice: ReceiptCheckpoint {
    private let bridge: OfflineDeviceBridge

    public init(store: Store, replayEpoch: Int64, seed: Data, capacity: UInt32) throws(RatifyError) {
        bridge = try OfflineDeviceBridge(store: store.bridge, replayEpoch: replayEpoch, seed: seed, capacity: capacity)
    }

    public func startup() throws(RatifyError) -> String { try bridge.startup().status ?? "" }
    public func setPowerLoss(_ mode: String) throws(RatifyError) { try bridge.setPowerLoss(mode) }
    public func submitPending() throws(RatifyError) -> DeviceReply { try DeviceReply(bridge.submitPending()) }
    public func resubmit(_ sequence: Int64) throws(RatifyError) -> DeviceReply { try DeviceReply(bridge.resubmit(sequence)) }
    public func upload() throws(RatifyError) -> [Int64] { try bridge.upload().uploaded }

    public func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                            entryHash: Data) async throws -> CheckpointAcknowledgement {
        try bridge.acknowledge(logId: logId, sequence: sequence, previousEntryHash: previousEntryHash,
            entryHash: entryHash).requiredAcknowledgement()
    }
    public func get(logId: String, sequence: Int64) async throws -> CheckpointAcknowledgement {
        try bridge.get(logId: logId, sequence: sequence).requiredAcknowledgement()
    }
}
