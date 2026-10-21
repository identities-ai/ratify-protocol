package ratify

import "fmt"

// Protocol v2 per-object wire limits (SPEC-v2 limit table). Each byte limit
// bounds the complete encoded object exactly as received, including every
// signature and any insignificant whitespace, and is checked before the
// bytes are parsed. A limit violation is the malformed error class. The
// existing chain-depth, JSON-depth, identifier, scope, constraint and
// transaction-party limits continue to apply.
const (
	// MaxDelegationCertBytesV2 bounds one encoded DelegationCertV2.
	MaxDelegationCertBytesV2 = 32 << 10
	// MaxProofBundleBytesV2 bounds one encoded ProofBundleV2.
	MaxProofBundleBytesV2 = 128 << 10
	// MaxKeyRotationStatementBytesV2 bounds one encoded KeyRotationStatementV2.
	MaxKeyRotationStatementBytesV2 = 32 << 10
	// MaxRevocationPushBytesV2 bounds one encoded RevocationPushV2.
	MaxRevocationPushBytesV2 = 256 << 10
	// MaxRevocationPushRefsV2 bounds len(RevocationPushV2.Revoked).
	MaxRevocationPushRefsV2 = 512
	// MaxRevocationListBytesV2 bounds one encoded RevocationListV2. It is a
	// practical ceiling, not a promise that MaxRevocationListRefsV2
	// maximum-length certificate IDs fit.
	MaxRevocationListBytesV2 = 4 << 20
	// MaxRevocationListRefsV2 bounds len(RevocationListV2.Revoked).
	MaxRevocationListRefsV2 = 10000
	// MaxWitnessEntryBytesV2 bounds one encoded WitnessEntryV2.
	MaxWitnessEntryBytesV2 = 64 << 10
	// MaxWitnessEntryDataBytesV2 bounds the decoded entry_data bytes.
	MaxWitnessEntryDataBytesV2 = 16 << 10
	// MaxVerificationReceiptBytesV2 bounds one encoded signed VerificationReceiptV2.
	MaxVerificationReceiptBytesV2 = 64 << 10
	// MaxVerificationReceiptBodyBytesV2 bounds one prepared receipt body.
	MaxVerificationReceiptBodyBytesV2 = 64 << 10
	// MaxTransactionReceiptBytesV2 bounds one encoded TransactionReceiptV2
	// including every embedded proof bundle and signature.
	MaxTransactionReceiptBytesV2 = MaxTransactionReceiptBytes
)

// checkV2WireSize is the pre-parse size gate shared by every v2 decoder.
// The message names the limit so diagnostics distinguish the size gate from
// later malformed-input checks with the same class.
func checkV2WireSize(data []byte, object, limitName string, limit int) error {
	if len(data) > limit {
		return fmt.Errorf("wire v2: %s exceeds %s (%d bytes)", object, limitName, limit)
	}
	return nil
}
