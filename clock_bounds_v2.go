package ratify

// Protocol v2 configuration and clock bounds (SPEC-v2 §6, amendment A5).
// Every time value is an integer number of seconds since the Unix epoch.
// Every deadline is exclusive: a value is current only while now < deadline.
// Configuration outside these bounds is rejected before any challenge claim
// with configuration_invalid.
const (
	// V2MaxTimestampSeconds is 9999-12-31T23:59:59Z. Timestamps are 0..this.
	V2MaxTimestampSeconds int64 = 253402300799
	// V2MaxFutureSkewSeconds bounds the configured future clock skew (0..300).
	V2MaxFutureSkewSeconds int64 = 300
	// V2MaxChallengeAgeSeconds bounds the configured challenge maximum age (1..300).
	V2MaxChallengeAgeSeconds int64 = 300
	// V2MaxStatusLifetimeSeconds bounds the configured status list lifetime and
	// accepted status age (1..86400; 0 means not configured for the reducer).
	V2MaxStatusLifetimeSeconds int64 = 86400
	// V2MaxAudienceMembershipAgeSeconds bounds max_membership_age_seconds (1..86400).
	V2MaxAudienceMembershipAgeSeconds int64 = 86400
	// V2MaxRateWindowSeconds bounds a max_rate window_s (1..86400).
	V2MaxRateWindowSeconds int64 = 86400
	// V2MaxDelegationLifetimeSeconds bounds expires_at - issued_at of a v2
	// delegation certificate (ten 365-day years).
	V2MaxDelegationLifetimeSeconds int64 = 315360000
)

// validV2Timestamp reports whether t is inside the v2 timestamp domain.
func validV2Timestamp(t int64) bool { return t >= 0 && t <= V2MaxTimestampSeconds }

// checkedAddV2 adds two second counts and reports overflow of the v2
// timestamp domain. Callers never use a result when ok is false.
func checkedAddV2(a, b int64) (sum int64, ok bool) {
	if a < 0 || b < 0 || a > V2MaxTimestampSeconds || b > V2MaxTimestampSeconds {
		return 0, false
	}
	sum = a + b // both operands are bounded far below int64 overflow
	return sum, true
}

// v2ChallengeTimeCurrent applies the exclusive challenge deadlines: issued_at
// may be at most futureSkew ahead of now, and the challenge is current only
// while now < expires_at and now < issued_at + max_age. All inputs must
// already be inside their bounds.
func v2ChallengeTimeCurrent(now, issuedAt, expiresAt, maxAge, futureSkew int64) bool {
	if !validV2Timestamp(now) || !validV2Timestamp(issuedAt) || !validV2Timestamp(expiresAt) {
		return false
	}
	if issuedAt > now && issuedAt-now > futureSkew {
		return false
	}
	ageDeadline, ok := checkedAddV2(issuedAt, maxAge)
	return ok && now < expiresAt && now < ageDeadline
}

// validateV2FreshnessConfiguration checks the request-level clock bounds.
func validateV2FreshnessConfiguration(now, maxAgeSeconds, futureSkewSeconds int64) error {
	if !validV2Timestamp(now) {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 verifier time is outside 0..%d", V2MaxTimestampSeconds)
	}
	if maxAgeSeconds < 1 || maxAgeSeconds > V2MaxChallengeAgeSeconds {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 challenge maximum age must be 1..%d seconds", V2MaxChallengeAgeSeconds)
	}
	if futureSkewSeconds < 0 || futureSkewSeconds > V2MaxFutureSkewSeconds {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 future skew must be 0..%d seconds", V2MaxFutureSkewSeconds)
	}
	return nil
}
