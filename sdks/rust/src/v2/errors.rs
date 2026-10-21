//! Language-neutral Protocol v2 failure classes (mirrors Go `errors_v2.go`).

use std::fmt;

/// A language-neutral failure class shared by the Protocol v2 conformance
/// corpus. Messages are diagnostic only; conformance compares classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V2ErrorClass {
    Unclassified,
    Malformed,
    UnsupportedObjectType,
    KeyIdMismatch,
    DelegationDigestMismatch,
    ChainLinkageMismatch,
    DuplicateCertificateRef,
    InvalidSignature,
    InvalidRequiredScope,
    ConfigurationInvalid,
    ExpectedChallengeUnavailable,
    NamespaceMismatch,
    StaleReplayEpoch,
    VerifierIdMismatch,
    ChallengeMismatch,
    ChallengeNotFresh,
    ExpectedAgentMismatch,
    SessionContextMismatch,
    ReceiverAudienceRequired,
    ReceiverAudienceMismatch,
    ReceiverBindingRejected,
    ClaimReplay,
    ClaimStoreUnavailable,
    StatusKeyBindingMismatch,
    ReceiptBundleMismatch,
    BundleHashMismatch,
    TransactionPartyMismatch,
    TransactionContextMismatch,
    TransactionSignatureSetInvalid,
    RotationStateMismatch,
    RotationKeyReused,
    RotationFutureDated,
    RotationFork,
    RotationFrozen,
    RotationRecoveryInvalid,
    LogStateMismatch,
    LogGap,
    LogOrphan,
    LogFork,
    LogFrozen,
    StatusObjectRejected,
}

impl V2ErrorClass {
    /// The wire spelling used by the shared conformance corpus.
    pub fn as_str(self) -> &'static str {
        use V2ErrorClass::*;
        match self {
            Unclassified => "unclassified",
            Malformed => "malformed",
            UnsupportedObjectType => "unsupported_object_type",
            KeyIdMismatch => "key_id_mismatch",
            DelegationDigestMismatch => "delegation_digest_mismatch",
            ChainLinkageMismatch => "chain_linkage_mismatch",
            DuplicateCertificateRef => "duplicate_certificate_ref",
            InvalidSignature => "invalid_signature",
            InvalidRequiredScope => "invalid_required_scope",
            ConfigurationInvalid => "configuration_invalid",
            ExpectedChallengeUnavailable => "expected_challenge_unavailable",
            NamespaceMismatch => "namespace_mismatch",
            StaleReplayEpoch => "stale_replay_epoch",
            VerifierIdMismatch => "verifier_id_mismatch",
            ChallengeMismatch => "challenge_mismatch",
            ChallengeNotFresh => "challenge_not_fresh",
            ExpectedAgentMismatch => "expected_agent_mismatch",
            SessionContextMismatch => "session_context_mismatch",
            ReceiverAudienceRequired => "receiver_audience_required",
            ReceiverAudienceMismatch => "receiver_audience_mismatch",
            ReceiverBindingRejected => "receiver_binding_rejected",
            ClaimReplay => "claim_replay",
            ClaimStoreUnavailable => "claim_store_unavailable",
            StatusKeyBindingMismatch => "status_key_binding_mismatch",
            ReceiptBundleMismatch => "receipt_bundle_mismatch",
            BundleHashMismatch => "bundle_hash_mismatch",
            TransactionPartyMismatch => "transaction_party_mismatch",
            TransactionContextMismatch => "transaction_context_mismatch",
            TransactionSignatureSetInvalid => "transaction_signature_set_invalid",
            RotationStateMismatch => "rotation_state_mismatch",
            RotationKeyReused => "rotation_key_reused",
            RotationFutureDated => "rotation_future_dated",
            RotationFork => "rotation_fork",
            RotationFrozen => "rotation_frozen",
            RotationRecoveryInvalid => "rotation_recovery_invalid",
            LogStateMismatch => "log_state_mismatch",
            LogGap => "log_gap",
            LogOrphan => "log_orphan",
            LogFork => "log_fork",
            LogFrozen => "log_frozen",
            StatusObjectRejected => "status_object_rejected",
        }
    }
}

impl fmt::Display for V2ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A classified diagnostic error. `class` is the conformance-relevant part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Error {
    pub class: V2ErrorClass,
    pub message: String,
}

impl V2Error {
    pub fn new(class: V2ErrorClass, message: impl Into<String>) -> Self {
        V2Error {
            class,
            message: message.into(),
        }
    }

    /// An error not yet assigned a class (Go: a plain `error`).
    pub fn plain(message: impl Into<String>) -> Self {
        V2Error::new(V2ErrorClass::Unclassified, message)
    }

    /// Go `v2Classify`: assign `class` only when the error is unclassified.
    pub fn classify(mut self, class: V2ErrorClass) -> Self {
        if self.class == V2ErrorClass::Unclassified {
            self.class = class;
        }
        self
    }

    /// Prefix the diagnostic message, keeping the class.
    pub fn context(mut self, prefix: impl fmt::Display) -> Self {
        self.message = format!("{prefix}: {}", self.message);
        self
    }
}

impl fmt::Display for V2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.class)
    }
}

impl std::error::Error for V2Error {}

/// Result alias for Protocol v2 operations.
pub type V2Result<T> = Result<T, V2Error>;

pub(crate) fn err<T>(class: V2ErrorClass, message: impl Into<String>) -> V2Result<T> {
    Err(V2Error::new(class, message))
}

pub(crate) fn plain<T>(message: impl Into<String>) -> V2Result<T> {
    Err(V2Error::plain(message))
}

pub(crate) trait Classify<T> {
    fn classify(self, class: V2ErrorClass) -> V2Result<T>;
}

impl<T> Classify<T> for V2Result<T> {
    fn classify(self, class: V2ErrorClass) -> V2Result<T> {
        self.map_err(|e| e.classify(class))
    }
}

/// Go `V2ErrorClassOf`: `None` for success.
pub fn v2_error_class_of<T>(result: &V2Result<T>) -> Option<V2ErrorClass> {
    result.as_ref().err().map(|e| e.class)
}
