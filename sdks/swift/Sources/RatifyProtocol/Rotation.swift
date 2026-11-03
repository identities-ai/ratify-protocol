import Foundation

/// One accepted rotation, retained for replay and fork checks.
public struct RotationAcceptedEntry: Sendable, Hashable {
    public var sequence: Int64
    public var bodyDigest: Data
    public var oldKey: HybridPublicKey

    public init(sequence: Int64, bodyDigest: Data, oldKey: HybridPublicKey) {
        self.sequence = sequence
        self.bodyDigest = bodyDigest
        self.oldKey = oldKey
    }
}

/// Caller-persisted key-rotation continuity state for one authority
/// (SPEC-v2 §5.4). Persist it atomically after every accepted statement.
public struct RotationJournal: Sendable, Hashable {
    public var state: RotationState
    public var accepted: [RotationAcceptedEntry]
    public var frozen: Bool

    public init(state: RotationState, accepted: [RotationAcceptedEntry], frozen: Bool) {
        self.state = state
        self.accepted = accepted
        self.frozen = frozen
    }

    init(_ f: FfiRotationJournal) {
        state = RotationState(f.state)
        accepted = f.accepted.map { RotationAcceptedEntry(sequence: $0.sequence, bodyDigest: $0.bodyDigest, oldKey: HybridPublicKey($0.oldKey)) }
        frozen = f.frozen
    }

    var ffi: FfiRotationJournal {
        FfiRotationJournal(state: state.ffi,
                           accepted: accepted.map { FfiRotationAcceptedEntry(sequence: $0.sequence, bodyDigest: $0.bodyDigest, oldKey: $0.oldKey.ffi) },
                           frozen: frozen)
    }
}

extension RotationState {
    init(_ f: FfiRotationState) {
        self.init(authorityId: f.authorityId, recoveryEpoch: f.recoveryEpoch, role: f.role, sequence: f.sequence,
                  headHash: f.headHash, currentKey: HybridPublicKey(f.currentKey), usedKeyIds: f.usedKeyIds)
    }
}

extension Ratify {
    /// The initial journal from a caller-authenticated genesis key.
    public static func newKeyRotationJournal(authorityId: String, recoveryEpoch: Int64, role: String,
                                             genesisKey: HybridPublicKey) throws(RatifyError) -> RotationJournal {
        RotationJournal(try ffi {
            try ffiNewKeyRotationJournal(authorityId: authorityId, recoveryEpoch: recoveryEpoch, role: role, genesisKey: genesisKey.ffi)
        })
    }

    /// Accept one rotation statement. Returns the next journal, which can
    /// change even when the statement is refused (a fork freezes it), and
    /// what the statement did or why it was refused.
    public static func acceptKeyRotationStatement(_ statement: KeyRotationStatement, journal: RotationJournal, now: Int64,
                                                  futureSkew: Int64) throws(RatifyError) -> (journal: RotationJournal, result: Result<LogResult, RatifyError>) {
        let a = try ffi {
            try ffiAcceptKeyRotationStatement(statement: statement.ffi, journal: journal.ffi, now: now, futureSkew: futureSkew)
        }
        let result: Result<LogResult, RatifyError>
        if let r = a.result {
            result = .success(LogResult(r))
        } else {
            let e = a.error!
            result = .failure(.protocol(ErrorClass(spelling: e.class), message: e.detail))
        }
        return (RotationJournal(a.journal), result)
    }

    /// Start a new recovery epoch from a caller-authenticated genesis key.
    public static func recoverKeyRotation(_ journal: RotationJournal, newRecoveryEpoch: Int64,
                                          newGenesisKey: HybridPublicKey) throws(RatifyError) -> RotationJournal {
        RotationJournal(try ffi {
            try ffiRecoverKeyRotation(journal: journal.ffi, newRecoveryEpoch: newRecoveryEpoch, newGenesisKey: newGenesisKey.ffi)
        })
    }
}
