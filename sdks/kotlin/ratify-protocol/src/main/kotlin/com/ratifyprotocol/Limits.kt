package com.ratifyprotocol

/** Public v2 wire limits and time bounds enforced by the decoder and verifier. */
public const val MAX_DELEGATION_CERT_BYTES_V2: Int = 32_768
public const val MAX_PROOF_BUNDLE_BYTES_V2: Int = 131_072
public const val MAX_KEY_ROTATION_STATEMENT_BYTES_V2: Int = 32_768
public const val MAX_REVOCATION_PUSH_BYTES_V2: Int = 262_144
public const val MAX_REVOCATION_PUSH_REFS_V2: Int = 512
public const val MAX_REVOCATION_LIST_BYTES_V2: Int = 4_194_304
public const val MAX_REVOCATION_LIST_REFS_V2: Int = 10_000
public const val MAX_WITNESS_ENTRY_BYTES_V2: Int = 65_536
public const val MAX_WITNESS_ENTRY_DATA_BYTES_V2: Int = 16_384
public const val MAX_VERIFICATION_RECEIPT_BYTES_V2: Int = 65_536
public const val MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2: Int = 65_536
public const val MAX_STATUS_EVIDENCE_BATCH_BYTES_V2: Int = 8_388_608
public const val MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2: Int = 64
public const val MAX_TRANSACTION_RECEIPT_BYTES_V2: Int = 5_242_880
public const val MAX_TRANSACTION_PARTIES_V2: Int = 32
public const val MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2: Int = 1_024
public const val MAX_AUDIENCE_IDS_V2: Int = 64
public const val MAX_CONSTRAINT_EVALUATORS_V2: Int = 32
public const val MAX_EXTENSION_TYPE_BYTES_V2: Int = 128
public const val MAX_PROFILE_ID_BYTES_V2: Int = 128
public const val MAX_EXTENSION_CONTEXT_ENTRIES_V2: Int = 64
public const val MAX_EXTENSION_CONTEXT_NAME_BYTES_V2: Int = 128
public const val MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2: Int = 512
public const val MAX_ALLOWED_VALUES_V2: Int = 64
public const val MAX_CONSTRAINT_EVALUATOR_TIMEOUT_SECONDS_V2: Long = 10L
public const val MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES: Int = 67_108_864
public const val V2_SIGNING_MESSAGE_SIZE: Int = 77

public const val V2_MAX_TIMESTAMP_SECONDS: Long = 253_402_300_799L
public const val V2_MAX_FUTURE_SKEW_SECONDS: Long = 300L
public const val V2_MAX_CHALLENGE_AGE_SECONDS: Long = 300L
public const val V2_MAX_STATUS_LIFETIME_SECONDS: Long = 86_400L
public const val V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS: Long = 86_400L
public const val V2_MAX_RATE_WINDOW_SECONDS: Long = 86_400L
public const val V2_MAX_DELEGATION_LIFETIME_SECONDS: Long = 315_360_000L
public const val V2_MAX_SAFE_INTEGER: Long = 9_007_199_254_740_991L

public const val CONSTRAINT_TIME_WINDOW: String = "time_window"
public const val CONSTRAINT_MAX_AMOUNT: String = "max_amount"
public const val CONSTRAINT_MAX_RATE: String = "max_rate"
public const val CONSTRAINT_RESOURCE_PATH: String = "resource_path"
public const val CONSTRAINT_RECEIVER_AUDIENCE: String = "ratify.receiver_audience"
public const val CONSTRAINT_MAX_COUNT_V2: String = "com.ratifyprotocol.max_count"
public const val CONSTRAINT_ALLOWED_VALUES_V2: String = "com.ratifyprotocol.allowed_values"
public const val PROFILE_MAX_COUNT_V2: String = "com.ratifyprotocol.max_count/v1"
public const val PROFILE_ALLOWED_VALUES_V2: String = "com.ratifyprotocol.allowed_values/v1"
public const val FRESHNESS_UNVERIFIED_V2: String = "freshness_unverified"
public const val SECURITY_JOURNAL_CONFLICT_MESSAGE_V2: String = "security journal compare-and-swap conflict"
public const val TZDB_VERSION_V2: String = "2025c"
