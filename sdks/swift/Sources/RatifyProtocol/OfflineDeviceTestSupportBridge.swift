import Foundation

@_spi(TestSupport) public struct OfflineDeviceReplyBridge: Sendable {
    public let acknowledged: [Int64]
    public let uploaded: [Int64]
    public let ackTime: Int64?
    public let status: String?
    public let failure: String?
    let acknowledgement: CheckpointAcknowledgement?
    private let storeFailure: FfiReferenceStoreFailure?

    init(_ value: FfiDeviceReply) {
        acknowledged = value.acknowledged
        uploaded = value.uploaded
        ackTime = value.ackTime
        status = value.status
        failure = value.failure
        acknowledgement = value.acknowledgement.map(CheckpointAcknowledgement.init)
        storeFailure = value.storeFailure
    }

    public func requiredAcknowledgement() throws -> CheckpointAcknowledgement {
        if let storeFailure { throw ReferenceStoreBridge.error(storeFailure) }
        if let failure { throw StoreError.unavailable(failure) }
        guard let acknowledgement else { throw RatifyError.internal(.panic, message: "device omitted acknowledgement") }
        return acknowledgement
    }
}

@_spi(TestSupport) public final class OfflineDeviceSnapshotBridge: Sendable {
    let handle: FfiDeviceSnapshot
    init(_ handle: FfiDeviceSnapshot) { self.handle = handle }
}

@_spi(TestSupport) public final class OfflineDeviceBridge: Sendable {
    private let handle: FfiOfflineDevice

    private init(_ handle: FfiOfflineDevice) { self.handle = handle }

    public init(store: ReferenceStoreBridge, replayEpoch: Int64, seed: Data, capacity: UInt32) throws(RatifyError) {
        handle = try ffi { try FfiOfflineDevice(store: store.handle, replayEpoch: replayEpoch,
            seed: seed, capacity: capacity) }
    }

    public func startup() throws(RatifyError) -> OfflineDeviceReplyBridge {
        OfflineDeviceReplyBridge(try ffi { try handle.startup() })
    }
    public func snapshot() throws(RatifyError) -> OfflineDeviceSnapshotBridge {
        try OfflineDeviceSnapshotBridge(ffi { try handle.snapshot() })
    }
    public func restore(_ snapshot: OfflineDeviceSnapshotBridge) throws(RatifyError) -> OfflineDeviceBridge {
        try OfflineDeviceBridge(ffi { try handle.restore(snapshot: snapshot.handle) })
    }
    public func primaryStore() throws(RatifyError) -> ReferenceStoreBridge {
        try ReferenceStoreBridge(ffi { try handle.primaryStore() })
    }
    public func setPowerLoss(_ mode: String) throws(RatifyError) {
        try ffi { try handle.setPowerLoss(mode: mode) }
    }
    public func submitPending() throws(RatifyError) -> OfflineDeviceReplyBridge {
        OfflineDeviceReplyBridge(try ffi { try handle.submitPending() })
    }
    public func resubmit(_ sequence: Int64) throws(RatifyError) -> OfflineDeviceReplyBridge {
        OfflineDeviceReplyBridge(try ffi { try handle.resubmit(sequence: sequence) })
    }
    public func upload() throws(RatifyError) -> OfflineDeviceReplyBridge {
        OfflineDeviceReplyBridge(try ffi { try handle.upload() })
    }
    public func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                            entryHash: Data) throws(RatifyError) -> OfflineDeviceReplyBridge {
        OfflineDeviceReplyBridge(try ffi { try handle.acknowledgeReceipt(logId: logId, sequence: sequence,
            previousEntryHash: previousEntryHash, entryHash: entryHash) })
    }
    public func get(logId: String, sequence: Int64) throws(RatifyError) -> OfflineDeviceReplyBridge {
        OfflineDeviceReplyBridge(try ffi { try handle.getAcknowledgement(logId: logId, sequence: sequence) })
    }
}
