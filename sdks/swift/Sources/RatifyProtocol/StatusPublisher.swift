import Foundation

/// Persist this state durably before publishing either signed object.
public struct StatusPublisherState: Sendable, Hashable {
    public let issuerId: String
    public let statusKeyId: String
    public let sequence: Int64
    public let updatedAt: Int64
    public let revoked: [String]

    public init(issuerId: String, statusKeyId: String, sequence: Int64, updatedAt: Int64, revoked: [String]) {
        self.issuerId = issuerId
        self.statusKeyId = statusKeyId
        self.sequence = sequence
        self.updatedAt = updatedAt
        self.revoked = revoked
    }

    init(_ f: FfiStatusPublisherState) {
        self.init(issuerId: f.issuerId, statusKeyId: f.statusKeyId, sequence: f.sequence,
                  updatedAt: f.updatedAt, revoked: f.revoked)
    }

    var ffi: FfiStatusPublisherState {
        FfiStatusPublisherState(issuerId: issuerId, statusKeyId: statusKeyId, sequence: sequence,
                                updatedAt: updatedAt, revoked: revoked)
    }
}

/// A transition's durable state and signed objects. Publish only after saving state.
public struct StatusPublication: Sendable, Hashable {
    public let state: StatusPublisherState
    public let list: RevocationList
    public let push: RevocationPush?

    init(_ f: FfiStatusPublication) {
        state = StatusPublisherState(f.state)
        list = RevocationList(f.list)
        push = f.push.map(RevocationPush.init)
    }
}

public final class StatusPublisher: @unchecked Sendable {
    private let handle: FfiStatusPublisher
    public let issuerId: String
    public let statusKey: HybridPublicKey

    init(_ handle: FfiStatusPublisher) throws(RatifyError) {
        self.handle = handle
        issuerId = try ffi { try handle.issuerId() }
        statusKey = HybridPublicKey(try ffi { try handle.statusKey() })
    }

    public func genesis(updatedAt: Int64, timeout: Duration? = nil) async throws(RatifyError) -> StatusPublication {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            StatusPublication(try ffi { try self.handle.genesis(token: token, updatedAt: updatedAt) })
        }
    }

    public func heartbeat(state: StatusPublisherState, updatedAt: Int64,
                          timeout: Duration? = nil) async throws(RatifyError) -> StatusPublication {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            StatusPublication(try ffi { try self.handle.heartbeat(token: token, state: state.ffi, updatedAt: updatedAt) })
        }
    }

    public func revoke(state: StatusPublisherState, certIds: [String], at: Int64,
                       timeout: Duration? = nil) async throws(RatifyError) -> StatusPublication {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            StatusPublication(try ffi { try self.handle.revoke(token: token, state: state.ffi, certIds: certIds, at: at) })
        }
    }
}

extension Ratify {
    /// Bind a separate status key to the authenticated issuer role. Lifetime
    /// must be 1...86400 seconds and within the verifier's list lifetime policy.
    /// Invalid role or key configuration throws `configuration_invalid`.
    public static func newStatusPublisher(store: any SecurityJournalStore, issuerKey: HybridPublicKey,
                                          statusKey: SoftwarePrivateKey, lifetimeSeconds: Int64,
                                          timeout: Duration? = nil) async throws(RatifyError) -> StatusPublisher {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try StatusPublisher(ffi { try ffiNewStatusPublisherWithKey(store: JournalStoreBridge(store), token: token,
                issuerKey: issuerKey.ffi, statusKey: statusKey.handle, lifetimeSeconds: lifetimeSeconds) })
        }
    }

    /// The external signer variant, with the same role and lifetime checks.
    public static func newStatusPublisher(store: any SecurityJournalStore, issuerKey: HybridPublicKey,
                                          statusSigner: any ExternalSigner, lifetimeSeconds: Int64,
                                          timeout: Duration? = nil) async throws(RatifyError) -> StatusPublisher {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try StatusPublisher(ffi { try ffiNewStatusPublisherWithSigner(store: JournalStoreBridge(store), token: token,
                issuerKey: issuerKey.ffi, statusSigner: SignerBridge(statusSigner), lifetimeSeconds: lifetimeSeconds) })
        }
    }
}
