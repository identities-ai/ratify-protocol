// Package feedbatch defines the signed evidence feed batch and its offline
// verification.
//
// A batch carries up to MaxEvents consecutive positions of one
// organization's activity stream. Batches of a destination are numbered from
// 1; each names the digest of the one before it and the stream position it
// continues from, and is signed with the Verify export key (artifact type
// feed_batch). A verifier holding the published export keys can therefore
// detect an edited, reordered, or dropped batch, and a gap in the stream.
package feedbatch

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/exportsig"
)

const (
	Type      = "ratify.evidence_feed.batch"
	Version   = "1"
	MaxEvents = 500
)

// Event is one activity stream envelope. ID is "<org_id>:<seq>" and is the
// dedupe key for at-least-once delivery.
type Event struct {
	ID         string          `json:"id"`
	Seq        int64           `json:"seq"`
	Source     string          `json:"source"`
	Kind       string          `json:"kind"`
	OccurredAt time.Time       `json:"occurred_at"`
	Payload    json.RawMessage `json:"payload"`
}

// Batch is the signed content.
type Batch struct {
	Type            string    `json:"type"`
	Version         string    `json:"version"`
	OrgID           string    `json:"org_id"`
	DestinationID   string    `json:"destination_id"`
	BatchSeq        int64     `json:"batch_seq"`
	AfterSeq        int64     `json:"after_seq"`
	LastSeq         int64     `json:"last_seq"`
	PrevBatchDigest string    `json:"prev_batch_digest"`
	CreatedAt       time.Time `json:"created_at"`
	Events          []Event   `json:"events"`
}

// Record is how a batch travels: the exact signed bytes (base64), their
// digest, and the export signature. It is the last line of every delivery.
type Record struct {
	Type          string              `json:"type"` // "batch"
	DestinationID string              `json:"destination_id"`
	BatchSeq      int64               `json:"batch_seq"`
	Batch         string              `json:"batch"`
	Digest        string              `json:"digest"`
	Signature     exportsig.Signature `json:"signature"`
}

// EventID is the dedupe key of a stream position.
func EventID(orgID string, seq int64) string { return fmt.Sprintf("%s:%d", orgID, seq) }

// Digest is the lowercase hex SHA-256 of the signed bytes.
func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (b Batch) check() error {
	if b.Type != Type || b.Version != Version {
		return fmt.Errorf("not a version %s evidence feed batch", Version)
	}
	if b.OrgID == "" || b.DestinationID == "" {
		return errors.New("batch has no organization or destination")
	}
	if b.BatchSeq < 1 || b.AfterSeq < 0 {
		return errors.New("batch numbering is invalid")
	}
	if (b.BatchSeq == 1) != (b.PrevBatchDigest == "") {
		return errors.New("only the first batch has no predecessor")
	}
	if len(b.Events) == 0 || len(b.Events) > MaxEvents {
		return fmt.Errorf("batch holds %d events, want 1 to %d", len(b.Events), MaxEvents)
	}
	for i, e := range b.Events {
		if e.Seq != b.AfterSeq+int64(i)+1 {
			return fmt.Errorf("batch %d: event %d has position %d, want %d", b.BatchSeq, i, e.Seq, b.AfterSeq+int64(i)+1)
		}
		if e.ID != EventID(b.OrgID, e.Seq) {
			return fmt.Errorf("batch %d: event %d has ID %q", b.BatchSeq, e.Seq, e.ID)
		}
	}
	if b.LastSeq != b.AfterSeq+int64(len(b.Events)) {
		return fmt.Errorf("batch %d: last position %d does not match its events", b.BatchSeq, b.LastSeq)
	}
	return nil
}

// Checkpoint is what a verifier has already accepted for a destination: the
// last batch number, its digest, and its last stream position. The zero
// value means the verifier starts from the destination's first batch.
type Checkpoint struct {
	BatchSeq int64  `json:"batch_seq"`
	Digest   string `json:"digest"`
	LastSeq  int64  `json:"last_seq"`
}

// VerifyChain checks records in order against the published export keys and
// returns the decoded batches and the new checkpoint. It fails on a bad
// signature, an edited batch, a batch out of order or missing, or a stream
// gap. With a zero checkpoint the first record must be batch 1.
func VerifyChain(keys exportsig.KeySet, from Checkpoint, records []Record) ([]Batch, Checkpoint, error) {
	cp := from
	var org, dest string
	out := make([]Batch, 0, len(records))
	for i, r := range records {
		payload, err := base64.StdEncoding.DecodeString(r.Batch)
		if err != nil {
			return nil, from, fmt.Errorf("record %d: batch encoding: %w", i, err)
		}
		if Digest(payload) != r.Digest {
			return nil, from, fmt.Errorf("record %d: digest does not match the batch", i)
		}
		if r.Signature.ArtifactType != exportsig.ArtifactFeedBatch || r.Signature.Version != Version {
			return nil, from, fmt.Errorf("record %d: signature is not a feed batch signature", i)
		}
		if err := exportsig.Verify(keys, r.Signature, payload); err != nil {
			return nil, from, fmt.Errorf("record %d: %w", i, err)
		}
		var b Batch
		if err := json.Unmarshal(payload, &b); err != nil {
			return nil, from, fmt.Errorf("record %d: batch: %w", i, err)
		}
		if err := b.check(); err != nil {
			return nil, from, fmt.Errorf("record %d: %w", i, err)
		}
		if b.BatchSeq != r.BatchSeq || b.DestinationID != r.DestinationID {
			return nil, from, fmt.Errorf("record %d: envelope does not match the signed batch", i)
		}
		if org == "" {
			org, dest = b.OrgID, b.DestinationID
		} else if b.OrgID != org || b.DestinationID != dest {
			return nil, from, fmt.Errorf("batch %d belongs to another destination", b.BatchSeq)
		}
		if cp.BatchSeq == 0 {
			if b.BatchSeq != 1 {
				return nil, from, fmt.Errorf("chain starts at batch %d, want 1 or a checkpoint", b.BatchSeq)
			}
		} else {
			if b.BatchSeq != cp.BatchSeq+1 {
				return nil, from, fmt.Errorf("batch %d follows batch %d: batches missing or reordered", b.BatchSeq, cp.BatchSeq)
			}
			if b.PrevBatchDigest != cp.Digest {
				return nil, from, fmt.Errorf("batch %d does not link to batch %d", b.BatchSeq, cp.BatchSeq)
			}
			if b.AfterSeq != cp.LastSeq {
				return nil, from, fmt.Errorf("batch %d continues after position %d, want %d: stream gap", b.BatchSeq, b.AfterSeq, cp.LastSeq)
			}
		}
		cp = Checkpoint{BatchSeq: b.BatchSeq, Digest: r.Digest, LastSeq: b.LastSeq}
		out = append(out, b)
	}
	return out, cp, nil
}
