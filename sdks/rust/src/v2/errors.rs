//! Language-neutral Protocol v2 failure classes (SPEC-v2 §2.7, Go
//! `errors_v2.go`) and the typed signing error (SPEC-v2 §3.2).

use std::fmt;

macro_rules! error_classes {
    ($($variant:ident => $text:literal,)*) => {
        /// The closed list of SPEC-v2 §2.7 failure classes. Every v2 failure
        /// that is not a terminal Protocol result, a release result, or a
        /// signing error has exactly one of these classes. Messages are
        /// diagnostic only; conformance compares classes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum V2ErrorClass {
            $($variant,)*
        }

        impl V2ErrorClass {
            /// Every class, in SPEC-v2 §2.7 table order.
            pub const ALL: &'static [V2ErrorClass] = &[$(V2ErrorClass::$variant,)*];

            /// The spelling shared by every SDK and the conformance corpus.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(V2ErrorClass::$variant => $text,)*
                }
            }

            /// Parse a class spelling; `None` for anything outside §2.7.
            pub fn parse(text: &str) -> Option<V2ErrorClass> {
                match text {
                    $($text => Some(V2ErrorClass::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

error_classes! {
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
    StreamSequenceMismatch => "stream_sequence_mismatch",
    ClaimStoreUnavailable => "claim_store_unavailable",
    ReceiptAbandoned => "receipt_abandoned",
    EvaluationCancelled => "evaluation_cancelled",
    ClockRegressed => "clock_regressed",
    AllowHorizonPassed => "allow_horizon_passed",
    ClaimLeaseLive => "claim_lease_live",
    ClaimLeaseLost => "claim_lease_lost",
    ClaimAlreadyTerminal => "claim_already_terminal",
    ClaimNotFound => "claim_not_found",
    StatusKeyBindingMismatch => "status_key_binding_mismatch",
    StatusObjectRejected => "status_object_rejected",
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
}

impl fmt::Display for V2ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A classified Protocol v2 failure. `class` is the conformance-relevant
/// part; `message` is diagnostic text only.
///
/// Internally an error may be created before its class is known (the Go
/// reference's unclassified error, later passed through `v2Classify`). Such an
/// error carries a provisional `malformed` class until the first
/// [`V2Error::classify`] fixes it, so a public API never reports a class
/// outside SPEC-v2 §2.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Error {
    pub class: V2ErrorClass,
    pub message: String,
    explicit: bool,
}

impl V2Error {
    /// A classified error.
    pub fn new(class: V2ErrorClass, message: impl Into<String>) -> Self {
        V2Error {
            class,
            message: message.into(),
            explicit: true,
        }
    }

    /// An error whose class is assigned later by [`V2Error::classify`]
    /// (Go: a plain `error`). Until then it reports `malformed`.
    pub(crate) fn plain(message: impl Into<String>) -> Self {
        V2Error {
            class: V2ErrorClass::Malformed,
            message: message.into(),
            explicit: false,
        }
    }

    /// Go `v2Classify`: assign `class` only when no class was fixed yet.
    pub fn classify(mut self, class: V2ErrorClass) -> Self {
        if !self.explicit {
            self.class = class;
            self.explicit = true;
        }
        self
    }

    /// Whether the class was fixed deliberately (Go: the error is a
    /// `*V2Error`); false for a provisional (Go: unclassified) error.
    pub(crate) fn is_classified(&self) -> bool {
        self.explicit
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

/// A typed signing failure (SPEC-v2 §3.2). Signing failures are not
/// verification error classes: a refusal creates no object and no signer
/// method runs after an issuer-duty or validation refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2SignError {
    /// The object fails its schema, bounds, or encoding (the wrapped error
    /// carries the class a decoder would report).
    InvalidObject(V2Error),
    /// An issuer duty (SPEC-v2 §5.1, §5.4) refuses the object.
    IssuerDuty(String),
    /// The signer's complete key is not the key the object or the
    /// caller-authenticated configuration names for this role.
    KeyBinding(String),
    /// The signer reported an invalid public key or private key material.
    InvalidSignerKey(String),
    /// The signer reported a mode this SDK does not implement.
    UnsupportedMode,
    /// The provider failed or refused.
    Provider(String),
    /// The caller's context was cancelled before or during signing; any
    /// signature that arrived afterwards was discarded.
    Cancelled,
    /// The provider returned a signature that does not verify under the
    /// bound key over the SDK-computed message and context.
    SignatureRejected(V2Error),
}

impl fmt::Display for V2SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            V2SignError::InvalidObject(e) => write!(f, "v2 signing refused: {e}"),
            V2SignError::IssuerDuty(m) => write!(f, "v2 issuer duty: {m}"),
            V2SignError::KeyBinding(m) => write!(f, "v2 signer key binding: {m}"),
            V2SignError::InvalidSignerKey(m) => write!(f, "v2 signer key: {m}"),
            V2SignError::UnsupportedMode => f.write_str("v2 signer reports an unsupported mode"),
            V2SignError::Provider(m) => write!(f, "v2 signer: {m}"),
            V2SignError::Cancelled => f.write_str("v2 signing cancelled"),
            V2SignError::SignatureRejected(e) => {
                write!(f, "v2 signer returned a signature that does not verify: {e}")
            }
        }
    }
}

impl std::error::Error for V2SignError {}

impl From<V2Error> for V2SignError {
    fn from(e: V2Error) -> Self {
        V2SignError::InvalidObject(e)
    }
}

/// Result alias for typed v2 signing.
pub type V2SignResult<T> = Result<T, V2SignError>;
