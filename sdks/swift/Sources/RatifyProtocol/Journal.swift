import Foundation

/// The independently anchored security journal head. Persist it separately
/// from the snapshot so a rollback of both cannot be accepted as current.
public struct SecurityJournalHead: Sendable, Hashable {
    public let generation: UInt64
    public let digest: String

    public init(generation: UInt64, digest: String) {
        self.generation = generation
        self.digest = digest
    }

    var ffi: FfiJournalHead { FfiJournalHead(generation: generation, digest: digest) }
}

/// Canonical journal bytes with the head they were exported against.
public struct SecurityJournalSnapshot: Sendable, Hashable {
    public let snapshot: Data
    public let head: SecurityJournalHead

    public init(snapshot: Data, head: SecurityJournalHead) {
        self.snapshot = snapshot
        self.head = head
    }

    init(_ f: FfiJournalSnapshot) {
        snapshot = f.snapshot
        head = SecurityJournalHead(generation: f.head.generation, digest: f.head.digest)
    }

    var ffi: FfiJournalSnapshot { FfiJournalSnapshot(snapshot: snapshot, head: head.ffi) }
}

/// A durable store whose head is protected independently from the snapshot.
/// Compare-and-swap must advance both atomically. A regular file or database
/// row by itself does not meet that contract.
public protocol SecurityJournalStore: Sendable {
    func load() async throws -> SecurityJournalSnapshot
    func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) async throws
}

public enum SecurityJournalStoreError: Error, Sendable {
    case conflict
    case cancelled
}

final class JournalStoreBridge: FfiJournalStore, @unchecked Sendable {
    private let store: any SecurityJournalStore
    init(_ store: any SecurityJournalStore) { self.store = store }

    private func wait<T: Sendable>(context: FfiJournalContext,
                                   _ operation: @escaping @Sendable () async throws -> T) throws -> T {
        let box = ResultBox<T>()
        let done = DispatchSemaphore(value: 0)
        let task = Task.detached {
            do { box.set(.success(try await operation())) } catch { box.set(.failure(error)) }
            done.signal()
        }
        while done.wait(timeout: .now() + .milliseconds(5)) == .timedOut {
            if (try? context.isCancelled()) == true { task.cancel() }
        }
        switch box.value! {
        case let .success(value): return value
        case let .failure(error as SecurityJournalStoreError):
            switch error {
            case .conflict: throw FfiJournalStoreError.Conflict
            case .cancelled: throw FfiJournalStoreError.Cancelled
            }
        case let .failure(error) where error is CancellationError: throw FfiJournalStoreError.Cancelled
        case let .failure(error): throw FfiJournalStoreError.Failed(detail: "\(error)")
        }
    }

    func load(context: FfiJournalContext) throws -> FfiJournalSnapshot {
        let store = self.store
        return try wait(context: context) { try await store.load().ffi }
    }

    func compareAndSwap(expected: FfiJournalHead, next: FfiJournalSnapshot, context: FfiJournalContext) throws {
        let store = self.store
        let head = SecurityJournalHead(generation: expected.generation, digest: expected.digest)
        let snapshot = SecurityJournalSnapshot(next)
        try wait(context: context) { try await store.compareAndSwap(expected: head, next: snapshot) }
    }
}

extension Ratify {
    public static func emptySecurityJournalSnapshot() throws(RatifyError) -> SecurityJournalSnapshot {
        SecurityJournalSnapshot(try ffi { try ffiEmptySecurityJournalSnapshot() })
    }

    /// Rejects noncanonical bytes and a snapshot that does not match the
    /// independently stored head.
    public static func validateSecurityJournalSnapshot(_ snapshot: Data, head: SecurityJournalHead) throws(RatifyError) {
        try ffi { try ffiValidateSecurityJournalSnapshot(snapshot: snapshot, head: head.ffi) }
    }

    public static func securityJournalSnapshotDigest(_ snapshot: Data) throws(RatifyError) -> String {
        try ffi { try ffiSecurityJournalSnapshotDigest(snapshot: snapshot) }
    }

    public static func migrateSecurityJournalJSON(_ legacyJSON: Data) throws(RatifyError) -> SecurityJournalSnapshot {
        SecurityJournalSnapshot(try ffi { try ffiMigrateSecurityJournalJson(legacyJson: legacyJSON) })
    }

    public static func validateSecurityJournalTransition(current: SecurityJournalSnapshot,
                                                         next: SecurityJournalSnapshot) throws(RatifyError) {
        try ffi { try ffiValidateSecurityJournalTransition(current: current.ffi, next: next.ffi) }
    }

    public static func recordSecurityKeyRole(store: any SecurityJournalStore, role: String, key: HybridPublicKey,
                                             timeout: Duration? = nil) async throws(RatifyError) -> SecurityJournalSnapshot {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            SecurityJournalSnapshot(try ffi { try ffiRecordSecurityKeyRole(store: JournalStoreBridge(store), token: token,
                                                                           role: role, key: key.ffi) })
        }
    }

    public static func configureStatusKeyEpoch(store: any SecurityJournalStore, issuerId: String, epoch: UInt64,
                                                key: HybridPublicKey, timeout: Duration? = nil) async throws(RatifyError) -> SecurityJournalSnapshot {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            SecurityJournalSnapshot(try ffi { try ffiConfigureStatusKeyEpoch(store: JournalStoreBridge(store), token: token,
                                                                              issuerId: issuerId, epoch: epoch, key: key.ffi) })
        }
    }

    public static func applyRevocationListToJournal(store: any SecurityJournalStore, list: RevocationList,
                                                     issuerId: String, epoch: UInt64, key: HybridPublicKey,
                                                     policy: RevocationStatusPolicy, now: Int64,
                                                     timeout: Duration? = nil) async throws(RatifyError) -> SecurityJournalSnapshot {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            SecurityJournalSnapshot(try ffi { try ffiApplyRevocationListToJournal(store: JournalStoreBridge(store), token: token,
                list: list.ffi, issuerId: issuerId, epoch: epoch, key: key.ffi, policy: policy.ffi, now: now) })
        }
    }

    public static func applyRevocationPushToJournal(store: any SecurityJournalStore, push: RevocationPush,
                                                     issuerId: String, epoch: UInt64, key: HybridPublicKey,
                                                     policy: RevocationStatusPolicy, now: Int64,
                                                     timeout: Duration? = nil) async throws(RatifyError) -> SecurityJournalSnapshot {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            SecurityJournalSnapshot(try ffi { try ffiApplyRevocationPushToJournal(store: JournalStoreBridge(store), token: token,
                push: push.ffi, issuerId: issuerId, epoch: epoch, key: key.ffi, policy: policy.ffi, now: now) })
        }
    }

    public static func revocationStatusFromJournal(store: any SecurityJournalStore, issuerId: String, certId: String,
                                                    epoch: UInt64, key: HybridPublicKey, policy: RevocationStatusPolicy,
                                                    now: Int64, timeout: Duration? = nil) async throws(RatifyError) -> RevocationStatusResult {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            let r = try ffi { try ffiRevocationStatusFromJournal(store: JournalStoreBridge(store), token: token,
                issuerId: issuerId, certId: certId, epoch: epoch, key: key.ffi, policy: policy.ffi, now: now) }
            return RevocationStatusResult(status: r.status, reason: r.reason,
                                          evidence: r.evidence.map(StatusEvidenceEntry.init), freshUntil: r.freshUntil)
        }
    }
}
