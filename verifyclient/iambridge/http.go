package iambridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

var ErrDefinitivePublication = errors.New("Verify definitively rejected IAM status publication")
var ErrRefreshRequired = errors.New("Verify requires a fresh IAM status list")
var ErrClockAhead = errors.New("IAM status-list clock is ahead of Verify")
var ErrPublisherConflict = errors.New("another status publisher holds this issuer in Verify")

// ErrSequenceConflict is Verify's 409 status_publication_conflict: the list
// conflicts with the issuer's anchored history or sequence. It is definitive
// for the list, but when Verify's accepted floor has reached the pending
// sequence the bridge reconciles instead of blocking (see Bridge).
var ErrSequenceConflict = fmt.Errorf("%w: status_publication_conflict", ErrDefinitivePublication)

// ErrRevocationOmitted is Verify's 409 status_revocation_omitted: the list
// leaves out a revocation Verify already holds for the issuer, typically one
// another publisher revoked that IAM does not report. It blocks the bridge
// until the customer adds the ID to IAM and an operator unblocks it.
var ErrRevocationOmitted = fmt.Errorf("%w: status_revocation_omitted", ErrDefinitivePublication)

// HTTPSource reads the customer's authoritative, complete status snapshot.
// The bearer token is sent only to the configured customer endpoint.
type HTTPSource struct {
	Client *http.Client
	URL    string
	Token  string
}

func (s HTTPSource) Snapshot(ctx context.Context) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return Snapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Accept", "application/json")
	response, err := s.Client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("IAM source returned HTTP %d", response.StatusCode)
	}
	var body struct {
		IssuerID       string    `json:"issuer_id"`
		Revision       string    `json:"revision"`
		Complete       bool      `json:"complete"`
		ObservedAt     time.Time `json:"observed_at"`
		RevokedCertIDs []string  `json:"revoked_cert_ids"`
	}
	const maxSnapshotBytes = 4 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSnapshotBytes+1))
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) > maxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("IAM snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return Snapshot{}, fmt.Errorf("decode IAM snapshot: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Snapshot{}, fmt.Errorf("IAM snapshot has trailing data")
	}
	return Snapshot{IssuerID: body.IssuerID, Revision: body.Revision, Complete: body.Complete,
		ObservedAt: body.ObservedAt, RevokedCertIDs: body.RevokedCertIDs}, nil
}

// HTTPPublisher uses the receiver's API credential. Verify binds that
// credential to its workspace and receiver, then validates the signed list
// against the receiver's pinned issuer, status key, and epoch.
// PublisherID identifies this running process to Verify's per-issuer
// single-writer lease; a second process must never share it.
type HTTPPublisher struct {
	Client      *http.Client
	URL         string
	APIKey      string
	IssuerID    string
	Epoch       uint64
	PublisherID string
}

func (p HTTPPublisher) Publish(ctx context.Context, wire []byte) error {
	body, err := json.Marshal(struct {
		IssuerID    string `json:"issuer_id"`
		Epoch       uint64 `json:"epoch"`
		PublisherID string `json:"publisher_id"`
		List        []byte `json:"list"`
	}{p.IssuerID, p.Epoch, p.PublisherID, wire})
	if err != nil {
		return err
	}
	response, result, err := p.post(ctx, p.URL, body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusConflict {
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.Unmarshal(result, &body)
			switch body.Error.Code {
			case "status_publication_refresh_required":
				return ErrRefreshRequired
			case "status_publication_clock_ahead":
				return ErrClockAhead
			case "status_publisher_conflict":
				return ErrPublisherConflict
			case "status_publication_conflict":
				return ErrSequenceConflict
			case "status_revocation_omitted":
				return ErrRevocationOmitted
			}
		}
		if response.StatusCode >= 400 && response.StatusCode < 500 &&
			response.StatusCode != http.StatusRequestTimeout && response.StatusCode != http.StatusTooManyRequests {
			return fmt.Errorf("%w: HTTP %d", ErrDefinitivePublication, response.StatusCode)
		}
		return fmt.Errorf("Verify rejected status publication with HTTP %d", response.StatusCode)
	}
	return nil
}

// Release hands this process's issuer lease to a successor on shutdown.
// releaseURL is the receiver status-publisher release endpoint.
func (p HTTPPublisher) Release(ctx context.Context, releaseURL string) error {
	body, err := json.Marshal(struct {
		IssuerID    string `json:"issuer_id"`
		Epoch       uint64 `json:"epoch"`
		PublisherID string `json:"publisher_id"`
	}{p.IssuerID, p.Epoch, p.PublisherID})
	if err != nil {
		return err
	}
	response, _, err := p.post(ctx, releaseURL, body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Verify refused status publisher release with HTTP %d", response.StatusCode)
	}
	return nil
}

func (p HTTPPublisher) post(ctx context.Context, url string, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("X-Ratify-API-Key", p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	response, err := noRedirect(p.Client).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	result, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return response, result, nil
}

var acceptedDigest = regexp.MustCompile(`^sha384:[0-9a-f]{96}$`)

// HTTPStatusReader reads the receiver's checkpoint-bound issuer status from
// Verify's GET /v1/verify/v2/status with the receiver API credential.
type HTTPStatusReader struct {
	Client   *http.Client
	URL      string
	APIKey   string
	IssuerID string
}

func (s HTTPStatusReader) IssuerStatus(ctx context.Context) (RemoteStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return RemoteStatus{}, err
	}
	req.Header.Set("X-Ratify-API-Key", s.APIKey)
	req.Header.Set("Accept", "application/json")
	response, err := noRedirect(s.Client).Do(req)
	if err != nil {
		return RemoteStatus{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RemoteStatus{}, fmt.Errorf("Verify status returned HTTP %d", response.StatusCode)
	}
	const maxStatusBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxStatusBytes+1))
	if err != nil {
		return RemoteStatus{}, err
	}
	if len(data) > maxStatusBytes {
		return RemoteStatus{}, errors.New("Verify status response is too large")
	}
	var body struct {
		StatusCheckpoint *struct {
			Digest string `json:"digest"`
		} `json:"status_checkpoint"`
		Issuers []struct {
			IssuerID       string `json:"issuer_id"`
			StatusKeyEpoch uint64 `json:"status_key_epoch"`
			// Sequence is required and null only when no floor is accepted;
			// RawMessage tells an omitted field from an explicit null.
			Sequence            json.RawMessage `json:"sequence"`
			AcceptedListDigest  string          `json:"accepted_list_digest"`
			MaxObservedSequence *int64          `json:"max_observed_sequence"`
		} `json:"issuers"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return RemoteStatus{}, fmt.Errorf("decode Verify status: %w", err)
	}
	if body.StatusCheckpoint == nil || body.StatusCheckpoint.Digest == "" {
		return RemoteStatus{}, errors.New("Verify status is not bound to a status checkpoint")
	}
	found := -1
	for i, issuer := range body.Issuers {
		if issuer.IssuerID == s.IssuerID {
			if found >= 0 {
				return RemoteStatus{}, errors.New("Verify status lists the issuer twice")
			}
			found = i
		}
	}
	if found < 0 {
		return RemoteStatus{}, errors.New("receiver configuration does not bind this issuer")
	}
	issuer := body.Issuers[found]
	var floor *int64
	if len(issuer.Sequence) == 0 || json.Unmarshal(issuer.Sequence, &floor) != nil {
		return RemoteStatus{}, errors.New("Verify issuer status omits its accepted floor")
	}
	// Reconciliation decides from these fields, so an incomplete or
	// inconsistent checkpoint view is an error, never a zero.
	if issuer.StatusKeyEpoch == 0 || issuer.MaxObservedSequence == nil || *issuer.MaxObservedSequence < 0 ||
		floor != nil && (*floor < 0 || *issuer.MaxObservedSequence < *floor) ||
		issuer.AcceptedListDigest != "" && (floor == nil || !acceptedDigest.MatchString(issuer.AcceptedListDigest)) {
		return RemoteStatus{}, errors.New("Verify issuer status is incomplete or inconsistent")
	}
	remote := RemoteStatus{Epoch: issuer.StatusKeyEpoch, AcceptedDigest: issuer.AcceptedListDigest,
		MaxObserved: *issuer.MaxObservedSequence}
	if floor != nil {
		remote.HasFloor, remote.Floor = true, *floor
	}
	return remote, nil
}

// noRedirect returns a copy of client that never follows a redirect. The
// receiver API key travels in a custom header, which Go's redirect policy
// would forward to any host a response names; a redirect is returned as the
// response instead and treated as a refusal.
func noRedirect(client *http.Client) *http.Client {
	copied := http.Client{}
	if client != nil {
		copied = *client
	}
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copied
}
