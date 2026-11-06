import Foundation

/// The relying party's freshness policy for status evidence.
public struct RevocationStatusPolicy: Sendable, Hashable {
    public var maxListLifetimeSeconds: Int64
    public var maxStatusAgeSeconds: Int64
    public var clockSkewSeconds: Int64

    public init(maxListLifetimeSeconds: Int64, maxStatusAgeSeconds: Int64, clockSkewSeconds: Int64) {
        self.maxListLifetimeSeconds = maxListLifetimeSeconds
        self.maxStatusAgeSeconds = maxStatusAgeSeconds
        self.clockSkewSeconds = clockSkewSeconds
    }

    var ffi: FfiStatusPolicy {
        FfiStatusPolicy(maxListLifetimeSeconds: maxListLifetimeSeconds, maxStatusAgeSeconds: maxStatusAgeSeconds,
                        clockSkewSeconds: clockSkewSeconds)
    }
}

/// One status object the reducer observed.
public struct RevocationObservation: Sendable, Hashable {
    public var objectType: UInt16
    public var statusKeyEpoch: UInt64
    public var statusKeyId: String
    public var sequence: Int64
    public var evidenceDigest: Data
    public var bodyDigest: Data
    public var revokedSetDigest: Data
    public var revokedCertIds: [String]
    public var futureDated: Bool
    public var fork: Bool
    public var gap: Bool
    public var accepted: Bool
}

/// Caller-persisted revocation status state for one issuer (SPEC-v2 §6.6).
/// Start from `Ratify.emptyRevocationStatusState()` and persist each result.
public struct RevocationStatusState: Sendable, Hashable {
    public var issuerId: String
    public var statusKeyEpoch: UInt64
    public var statusKeyId: String
    public var retiredStatusKeyIds: [String]
    public var hasFloor: Bool
    public var floor: Int64
    public var acceptedSnapshot: RevocationList?
    public var acceptedCertIds: [String]
    public var hasPrecedingCheckpoint: Bool
    public var precedingFloor: Int64
    public var precedingAcceptedCertIds: [String]
    public var denyUnionCertIds: [String]
    public var observations: [RevocationObservation]
    public var maxObservedSequence: Int64
    public var forkSequence: Int64
    public var reconciliationRequired: Bool
    public var futureDatedObjectObserved: Bool

    init(_ f: FfiStatusState) {
        issuerId = f.issuerId
        statusKeyEpoch = f.statusKeyEpoch
        statusKeyId = f.statusKeyId
        retiredStatusKeyIds = f.retiredStatusKeyIds
        hasFloor = f.hasFloor
        floor = f.floor
        acceptedSnapshot = f.acceptedSnapshot.map(RevocationList.init)
        acceptedCertIds = f.acceptedCertIds
        hasPrecedingCheckpoint = f.hasPrecedingCheckpoint
        precedingFloor = f.precedingFloor
        precedingAcceptedCertIds = f.precedingAcceptedCertIds
        denyUnionCertIds = f.denyUnionCertIds
        observations = f.observations.map {
            RevocationObservation(objectType: $0.objectType, statusKeyEpoch: $0.statusKeyEpoch, statusKeyId: $0.statusKeyId,
                                  sequence: $0.sequence, evidenceDigest: $0.evidenceDigest, bodyDigest: $0.bodyDigest,
                                  revokedSetDigest: $0.revokedSetDigest, revokedCertIds: $0.revokedCertIds,
                                  futureDated: $0.futureDated, fork: $0.fork, gap: $0.gap, accepted: $0.accepted)
        }
        maxObservedSequence = f.maxObservedSequence
        forkSequence = f.forkSequence
        reconciliationRequired = f.reconciliationRequired
        futureDatedObjectObserved = f.futureDatedObjectObserved
    }

    var ffi: FfiStatusState {
        FfiStatusState(
            issuerId: issuerId, statusKeyEpoch: statusKeyEpoch, statusKeyId: statusKeyId, retiredStatusKeyIds: retiredStatusKeyIds,
            hasFloor: hasFloor, floor: floor, acceptedSnapshot: acceptedSnapshot?.ffi, acceptedCertIds: acceptedCertIds,
            hasPrecedingCheckpoint: hasPrecedingCheckpoint, precedingFloor: precedingFloor,
            precedingAcceptedCertIds: precedingAcceptedCertIds, denyUnionCertIds: denyUnionCertIds,
            observations: observations.map {
                FfiStatusObservation(objectType: $0.objectType, statusKeyEpoch: $0.statusKeyEpoch, statusKeyId: $0.statusKeyId,
                                     sequence: $0.sequence, evidenceDigest: $0.evidenceDigest, bodyDigest: $0.bodyDigest,
                                     revokedSetDigest: $0.revokedSetDigest, revokedCertIds: $0.revokedCertIds,
                                     futureDated: $0.futureDated, fork: $0.fork, gap: $0.gap, accepted: $0.accepted)
            },
            maxObservedSequence: maxObservedSequence, forkSequence: forkSequence, reconciliationRequired: reconciliationRequired,
            futureDatedObjectObserved: futureDatedObjectObserved)
    }
}

/// A certificate's revocation status.
public struct RevocationStatusResult: Sendable, Hashable {
    /// "not_revoked", "revoked", or "indeterminate".
    public let status: String
    /// "" or, for indeterminate, "unavailable" / "stale".
    public let reason: String
    public let evidence: [StatusEvidenceEntry]
    public let freshUntil: Int64
}

extension Ratify {
    public static func emptyRevocationStatusState() throws(RatifyError) -> RevocationStatusState {
        RevocationStatusState(try ffi { try ffiEmptyStatusState() })
    }

    public static func applyRevocationList(_ state: RevocationStatusState, _ list: RevocationList, boundIssuerId: String,
                                           statusKeyEpoch: UInt64, statusKey: HybridPublicKey, policy: RevocationStatusPolicy,
                                           now: Int64) throws(RatifyError) -> RevocationStatusState {
        RevocationStatusState(try ffi {
            try ffiApplyRevocationList(state: state.ffi, list: list.ffi, boundIssuerId: boundIssuerId, statusKeyEpoch: statusKeyEpoch,
                                       statusKey: statusKey.ffi, policy: policy.ffi, now: now)
        })
    }

    public static func applyRevocationPush(_ state: RevocationStatusState, _ push: RevocationPush, boundIssuerId: String,
                                           statusKeyEpoch: UInt64, statusKey: HybridPublicKey, policy: RevocationStatusPolicy,
                                           now: Int64) throws(RatifyError) -> RevocationStatusState {
        RevocationStatusState(try ffi {
            try ffiApplyRevocationPush(state: state.ffi, push: push.ffi, boundIssuerId: boundIssuerId, statusKeyEpoch: statusKeyEpoch,
                                       statusKey: statusKey.ffi, policy: policy.ffi, now: now)
        })
    }

    public static func transitionRevocationStatusEpoch(_ state: RevocationStatusState, issuerId: String, nextEpoch: UInt64,
                                                       nextStatusKey: HybridPublicKey) throws(RatifyError) -> RevocationStatusState {
        RevocationStatusState(try ffi {
            try ffiTransitionRevocationStatusEpoch(state: state.ffi, issuerId: issuerId, nextEpoch: nextEpoch, nextStatusKey: nextStatusKey.ffi)
        })
    }

    public static func revocationStatusForCert(_ state: RevocationStatusState, issuerId: String, certId: String,
                                               statusKeyEpoch: UInt64, statusKey: HybridPublicKey, policy: RevocationStatusPolicy,
                                               now: Int64) throws(RatifyError) -> RevocationStatusResult {
        let r = try ffi {
            try ffiRevocationStatusForCert(state: state.ffi, issuerId: issuerId, certId: certId, statusKeyEpoch: statusKeyEpoch,
                                           statusKey: statusKey.ffi, policy: policy.ffi, now: now)
        }
        return RevocationStatusResult(status: r.status, reason: r.reason, evidence: r.evidence.map(StatusEvidenceEntry.init), freshUntil: r.freshUntil)
    }

    /// The claim ID from a precomputed challenge claim digest.
    public static func protocolClaimId(namespace: String, replayEpoch: Int64, digest: Data) throws(RatifyError) -> String {
        try ffi { try ffiProtocolClaimIdFromDigest(namespace: namespace, replayEpoch: replayEpoch, digest: digest) }
    }
}
