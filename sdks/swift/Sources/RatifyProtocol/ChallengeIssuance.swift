import Foundation

/// One authenticated issuance context. Every expected binding comes from the verifier.
public struct ChallengeIssueRequest: Sendable {
    public let verifierNamespace: String
    public let replayEpoch: Int64
    public let verifierId: String
    public let lifetimeSeconds: Int64
    public let expectedAgentId: String
    public let expectedAgentPublicKey: HybridPublicKey?
    public let expectedReceiverId: String
    public let expectedSessionContext: Data?

    public init(verifierNamespace: String, replayEpoch: Int64, verifierId: String, lifetimeSeconds: Int64,
                expectedAgentId: String = "", expectedAgentPublicKey: HybridPublicKey? = nil,
                expectedReceiverId: String = "", expectedSessionContext: Data? = nil) {
        self.verifierNamespace = verifierNamespace
        self.replayEpoch = replayEpoch
        self.verifierId = verifierId
        self.lifetimeSeconds = lifetimeSeconds
        self.expectedAgentId = expectedAgentId
        self.expectedAgentPublicKey = expectedAgentPublicKey
        self.expectedReceiverId = expectedReceiverId
        self.expectedSessionContext = expectedSessionContext
    }

    var ffi: FfiChallengeIssueRequest {
        FfiChallengeIssueRequest(verifierNamespace: verifierNamespace, replayEpoch: replayEpoch,
            verifierId: verifierId, lifetimeSeconds: lifetimeSeconds, expectedAgentId: expectedAgentId,
            expectedAgentPublicKey: expectedAgentPublicKey?.ffi, expectedReceiverId: expectedReceiverId,
            expectedSessionContext: expectedSessionContext)
    }
}

/// The complete durable challenge record. Persist before exposing `value`.
public struct ExpectedChallenge: Sendable {
    public let value: Data
    public let issuedAt: Int64
    public let expiresAt: Int64
    public let verifierNamespace: String
    public let replayEpoch: Int64
    public let verifierId: String
    public let expectedAgentId: String
    public let expectedAgentPublicKey: HybridPublicKey?
    public let expectedReceiverId: String
    public let expectedSessionContext: Data?
    public let contextPolicy: ContextPolicy?

    public init(value: Data, issuedAt: Int64, expiresAt: Int64, verifierNamespace: String,
                replayEpoch: Int64, verifierId: String, expectedAgentId: String = "",
                expectedAgentPublicKey: HybridPublicKey? = nil, expectedReceiverId: String = "",
                expectedSessionContext: Data? = nil, contextPolicy: ContextPolicy? = nil) {
        self.value = value
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.verifierNamespace = verifierNamespace
        self.replayEpoch = replayEpoch
        self.verifierId = verifierId
        self.expectedAgentId = expectedAgentId
        self.expectedAgentPublicKey = expectedAgentPublicKey
        self.expectedReceiverId = expectedReceiverId
        self.expectedSessionContext = expectedSessionContext
        self.contextPolicy = contextPolicy
    }

    init(_ f: FfiExpectedChallenge) throws(RatifyError) {
        self.init(value: f.value, issuedAt: f.issuedAt, expiresAt: f.expiresAt,
            verifierNamespace: f.verifierNamespace, replayEpoch: f.replayEpoch, verifierId: f.verifierId,
            expectedAgentId: f.expectedAgentId, expectedAgentPublicKey: f.expectedAgentPublicKey.map(HybridPublicKey.init),
            expectedReceiverId: f.expectedReceiverId, expectedSessionContext: f.expectedSessionContext,
            contextPolicy: try f.contextPolicy.map(ContextPolicy.init))
    }

    var ffi: FfiExpectedChallenge {
        FfiExpectedChallenge(value: value, issuedAt: issuedAt, expiresAt: expiresAt,
            verifierNamespace: verifierNamespace, replayEpoch: replayEpoch, verifierId: verifierId,
            expectedAgentId: expectedAgentId, expectedAgentPublicKey: expectedAgentPublicKey?.ffi,
            expectedReceiverId: expectedReceiverId, expectedSessionContext: expectedSessionContext,
            contextPolicy: contextPolicy?.handle)
    }
}

/// Part B store failures. A store must return the precise conflict or missing-record case.
public enum StoreError: Error, Sendable {
    case classified(ErrorClass, detail: String)
    case unavailable(String)
    case claimProofConflict
    case rateLimitExceeded
    case releaseStateMismatch
    case acknowledgementNotFound
    case challengeIssuanceConflict
    case challengeIssuanceNotFound

    public var errorClass: ErrorClass? {
        switch self {
        case let .classified(c, _): c
        case .claimProofConflict: .claimReplay
        case .rateLimitExceeded: .claimStoreUnavailable
        default: nil
        }
    }

    var ffi: FfiStoreError {
        switch self {
        case let .classified(c, detail): .Classified(class: c.rawValue, detail: detail)
        case let .unavailable(detail): .Unavailable(detail: detail)
        case .claimProofConflict: .ClaimProofConflict
        case .rateLimitExceeded: .RateLimitExceeded
        case .releaseStateMismatch: .ReleaseStateMismatch
        case .acknowledgementNotFound: .AcknowledgementNotFound
        case .challengeIssuanceConflict: .ChallengeIssuanceConflict
        case .challengeIssuanceNotFound: .ChallengeIssuanceNotFound
        }
    }
}

public protocol AuthoritativeClock: Sendable {
    func authoritativeTime() async throws -> Int64
}

/// Persist inserts atomically and durably. Load looks up namespace, epoch and claim digest.
public protocol ChallengeIssuanceStore: Sendable {
    func persist(_ record: ExpectedChallenge) async throws
    func load(namespace: String, replayEpoch: Int64, claimDigest: Data) async throws -> ExpectedChallenge
}

/// A caller-controlled source of unpredictable bytes. The SDK requires exactly `count` bytes.
public protocol ChallengeRandomSource: Sendable {
    func fill(count: Int) async throws -> Data
}

func callbackWait<T: Sendable>(context: FfiStoreContext,
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
    return try box.value!.get()
}

final class ClockBridge: FfiAuthoritativeClock, @unchecked Sendable {
    private let clock: any AuthoritativeClock
    init(_ clock: any AuthoritativeClock) { self.clock = clock }
    func authoritativeTime(context: FfiStoreContext) throws -> Int64 {
        do { return try callbackWait(context: context) { try await self.clock.authoritativeTime() } }
        catch {
            if error is CancellationError, (try? context.isCancelled()) == true { throw FfiStoreError.Cancelled }
            throw (error as? StoreError)?.ffi ?? FfiStoreError.Unavailable(detail: "\(error)")
        }
    }
}

final class ChallengeStoreBridge: FfiChallengeIssuanceStore, @unchecked Sendable {
    private let store: any ChallengeIssuanceStore
    init(_ store: any ChallengeIssuanceStore) { self.store = store }

    func persist(record: FfiExpectedChallenge, context: FfiStoreContext) throws {
        do {
            let value = try ExpectedChallenge(record)
            try callbackWait(context: context) { try await self.store.persist(value) }
        } catch {
            if error is CancellationError, (try? context.isCancelled()) == true { throw FfiStoreError.Cancelled }
            throw (error as? StoreError)?.ffi ?? FfiStoreError.Unavailable(detail: "\(error)")
        }
    }

    func load(namespace: String, replayEpoch: Int64, claimDigest: Data,
              context: FfiStoreContext) throws -> FfiExpectedChallenge {
        do {
            return try callbackWait(context: context) {
                try await self.store.load(namespace: namespace, replayEpoch: replayEpoch, claimDigest: claimDigest).ffi
            }
        } catch {
            if error is CancellationError, (try? context.isCancelled()) == true { throw FfiStoreError.Cancelled }
            throw (error as? StoreError)?.ffi ?? FfiStoreError.Unavailable(detail: "\(error)")
        }
    }
}

final class RandomBridge: FfiRandomSource, @unchecked Sendable {
    private let source: any ChallengeRandomSource
    init(_ source: any ChallengeRandomSource) { self.source = source }
    func fill(count: UInt32, context: FfiStoreContext) throws -> Data {
        do { return try callbackWait(context: context) { try await self.source.fill(count: Int(count)) } }
        catch {
            if error is CancellationError, (try? context.isCancelled()) == true { throw FfiRandomError.Cancelled }
            throw FfiRandomError.Failed(detail: "\(error)")
        }
    }
}

extension Ratify {
    /// Returns only after the complete record is durable. A failure exposes no challenge.
    public static func issueChallenge(request: ChallengeIssueRequest, clock: any AuthoritativeClock,
                                      store: any ChallengeIssuanceStore, random: (any ChallengeRandomSource)? = nil,
                                      timeout: Duration? = nil) async throws(RatifyError) -> ExpectedChallenge {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try ExpectedChallenge(ffi { try ffiIssueChallenge(clock: ClockBridge(clock), store: ChallengeStoreBridge(store),
                random: random.map(RandomBridge.init), token: token, request: request.ffi) })
        }
    }

    /// Loads by the challenge claim digest. The caller still performs all pre-claim checks.
    public static func loadExpectedChallenge(store: any ChallengeIssuanceStore, namespace: String,
                                             replayEpoch: Int64, challenge: Data,
                                             timeout: Duration? = nil) async throws(RatifyError) -> ExpectedChallenge {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try ExpectedChallenge(ffi { try ffiLoadExpectedChallenge(store: ChallengeStoreBridge(store), token: token,
                namespace: namespace, replayEpoch: replayEpoch, challenge: challenge) })
        }
    }
}
