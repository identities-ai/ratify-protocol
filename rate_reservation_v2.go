package ratify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// ErrV2RateLimitExceeded means a complete atomic batch had no capacity.
// Other store errors are unavailable or ambiguous and cannot authorize.
var ErrV2RateLimitExceeded = errors.New("v2 signed rate limit has no remaining capacity")

// V2RateReservation identifies one issuer-scoped rolling-window counter.
// The effective limit is the smallest signed limit for this certificate and
// window; duplicate constraints never consume more than one slot per claim.
type V2RateReservation struct {
	IssuerID string
	CertID   string
	WindowS  int64
	Limit    int64
}

// signedV2RateReservationBatch seals every rate counter from an already
// preflight-verified proof into the immutable challenge claim. Reservation is
// still deferred until status and other ordered checks have completed.
func signedV2RateReservationBatch(bundle *ProofBundleV2) ([]V2RateReservation, error) {
	deferred := make([]V2DeferredConstraint, 0)
	for i, cert := range bundle.Delegations {
		for j, constraint := range cert.Constraints {
			if constraint.Type != ConstraintMaxRate {
				continue
			}
			encoded, err := CanonicalJSON(constraint)
			if err != nil {
				return nil, err
			}
			deferred = append(deferred, V2DeferredConstraint{
				DelegationIndex: i, ConstraintIndex: j, IssuerID: cert.IssuerID,
				CertID: cert.CertID, Type: ConstraintMaxRate, CanonicalJSON: encoded,
			})
		}
	}
	return BuildV2RateReservationBatch(deferred)
}

// BuildV2RateReservationBatch derives a deterministic atomic reservation
// request from signed max_rate constraints retained in the claimed proof.
func BuildV2RateReservationBatch(deferred []V2DeferredConstraint) (_ []V2RateReservation, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	type counterKey struct {
		issuerID string
		certID   string
		windowS  int64
	}
	counters := make(map[counterKey]int64)
	seenPositions := make(map[[2]int]bool)
	for _, item := range deferred {
		position := [2]int{item.DelegationIndex, item.ConstraintIndex}
		if item.DelegationIndex < 0 || item.ConstraintIndex < 0 || seenPositions[position] || !validV2ID(item.IssuerID) || item.CertID == "" || len(item.CertID) > MaxIdentifierLengthBytes {
			return nil, fmt.Errorf("v2 rate constraint has invalid identity or duplicate position")
		}
		seenPositions[position] = true
		if err := validateV2ConstraintFields(item.CanonicalJSON); err != nil {
			return nil, fmt.Errorf("v2 rate constraint is invalid: %w", err)
		}
		var constraint ConstraintV2
		if err := json.Unmarshal(item.CanonicalJSON, &constraint); err != nil || constraint.Type != item.Type {
			return nil, fmt.Errorf("v2 rate constraint has wrong type")
		}
		canonical, err := CanonicalJSON(constraint)
		if err != nil || !bytes.Equal(canonical, item.CanonicalJSON) {
			return nil, fmt.Errorf("v2 rate constraint has noncanonical fields")
		}
		if item.Type != ConstraintMaxRate && item.Type != ConstraintReceiverAudience {
			return nil, fmt.Errorf("v2 rate batch contains an unexpected deferred constraint type")
		}
		if item.Type == ConstraintReceiverAudience {
			continue
		}
		if constraint.Count <= 0 || constraint.Count > maxSafeInteger || constraint.WindowS <= 0 || constraint.WindowS > V2MaxRateWindowSeconds {
			return nil, fmt.Errorf("v2 rate constraint has noncanonical or invalid limits")
		}
		key := counterKey{item.IssuerID, item.CertID, constraint.WindowS}
		limit := constraint.Count
		if previous, exists := counters[key]; !exists || limit < previous {
			counters[key] = limit
		}
	}
	batch := make([]V2RateReservation, 0, len(counters))
	for key, limit := range counters {
		batch = append(batch, V2RateReservation{IssuerID: key.issuerID, CertID: key.certID, WindowS: key.windowS, Limit: limit})
	}
	slices.SortFunc(batch, func(a, b V2RateReservation) int {
		if a.IssuerID != b.IssuerID {
			if a.IssuerID < b.IssuerID {
				return -1
			}
			return 1
		}
		if a.CertID != b.CertID {
			if a.CertID < b.CertID {
				return -1
			}
			return 1
		}
		if a.WindowS < b.WindowS {
			return -1
		}
		if a.WindowS > b.WindowS {
			return 1
		}
		return 0
	})
	return batch, nil
}
