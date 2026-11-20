package feedbatch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/exportsig"
)

type testSigner struct {
	key  *ecdsa.PrivateKey
	keys exportsig.KeySet
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return &testSigner{key: key, keys: exportsig.KeySet{Keys: []exportsig.Key{{
		KeyID: "test-key", Algorithm: exportsig.AlgorithmP256SHA256, PublicKeyPEM: pemText,
		NotBefore: time.Now().Add(-time.Hour)}}}}
}

func (s *testSigner) record(t *testing.T, b Batch) Record {
	t.Helper()
	payload, err := json.Marshal(b) // bypasses Encode so tests can sign bad batches
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	digest, err := exportsig.Digest(exportsig.ArtifactFeedBatch, Version, "test-key", at, payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	return newRecord(b.DestinationID, b.BatchSeq, payload, exportsig.Signature{
		ArtifactType: exportsig.ArtifactFeedBatch, Version: Version, KeyID: "test-key",
		Algorithm: exportsig.AlgorithmP256SHA256, SignedAt: at, Signature: base64.StdEncoding.EncodeToString(raw)})
}

func batch(seq, after int64, n int, prev string) Batch {
	b := Batch{Type: Type, Version: Version, OrgID: "org-1", DestinationID: "dest-1", BatchSeq: seq,
		AfterSeq: after, LastSeq: after + int64(n), PrevBatchDigest: prev, CreatedAt: time.Unix(1700000000, 0).UTC()}
	for i := 1; i <= n; i++ {
		b.Events = append(b.Events, Event{ID: EventID("org-1", after+int64(i)), Seq: after + int64(i),
			Source: "decision", Kind: "decision.deny", OccurredAt: b.CreatedAt, Payload: json.RawMessage(`{"decision":"deny"}`)})
	}
	return b
}

// chain returns three correctly linked, signed batches starting after
// stream position 10 (a destination added mid-stream).
func chain(t *testing.T, s *testSigner) []Record {
	t.Helper()
	var out []Record
	prev, after := "", int64(10)
	for seq := int64(1); seq <= 3; seq++ {
		r := s.record(t, batch(seq, after, 2, prev))
		out = append(out, r)
		prev, after = r.Digest, after+2
	}
	return out
}

func TestVerifyChainAcceptsLinkedBatches(t *testing.T) {
	s := newTestSigner(t)
	batches, cp, err := VerifyChain(s.keys, Checkpoint{}, chain(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 || cp.BatchSeq != 3 || cp.LastSeq != 16 {
		t.Fatalf("got %d batches, checkpoint %+v", len(batches), cp)
	}
	// Resuming from a checkpoint continues the chain.
	next := s.record(t, batch(4, 16, 1, cp.Digest))
	if _, _, err := VerifyChain(s.keys, cp, []Record{next}); err != nil {
		t.Fatal(err)
	}
}

// A customer must be able to detect, offline, any batch that was edited,
// dropped, reordered, or that skips stream positions; otherwise the feed is
// not evidence.
func TestVerifyChainRejectsTamperingAndGaps(t *testing.T) {
	s := newTestSigner(t)
	cases := map[string]func([]Record) []Record{
		"edited event": func(r []Record) []Record {
			raw, _ := base64.StdEncoding.DecodeString(r[1].Batch)
			edited := strings.Replace(string(raw), `"deny"`, `"allow"`, 1)
			r[1].Batch = base64.StdEncoding.EncodeToString([]byte(edited))
			r[1].Digest = Digest([]byte(edited))
			return r
		},
		"dropped batch":   func(r []Record) []Record { return []Record{r[0], r[2]} },
		"reordered":       func(r []Record) []Record { return []Record{r[0], r[2], r[1]} },
		"missing first":   func(r []Record) []Record { return r[1:] },
		"digest mismatch": func(r []Record) []Record { r[0].Digest = strings.Repeat("0", 64); return r },
		"stream gap": func(r []Record) []Record {
			// Correctly signed and linked, but skips positions 15-16.
			return []Record{r[0], r[1], s.record(t, batch(3, 16, 2, r[1].Digest))}
		},
		"unpublished key": func(r []Record) []Record { r[2].Signature.KeyID = "other"; return r },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := VerifyChain(s.keys, Checkpoint{}, mutate(chain(t, s))); err == nil {
				t.Fatal("tampered chain verified")
			}
		})
	}
}

func TestEncodeRejectsNonContiguousEvents(t *testing.T) {
	b := batch(1, 0, 3, "")
	if _, err := encode(b); err != nil {
		t.Fatal(err)
	}
	b.Events[1].Seq = 5
	if _, err := encode(b); err == nil {
		t.Fatal("non-contiguous batch encoded")
	}
	if _, err := encode(batch(2, 3, 1, "")); err == nil {
		t.Fatal("second batch without a predecessor encoded")
	}
}

// A feed key's published entry is bound to feed_batch, so its holder cannot
// mint a review record or report bundle that verifies.
func TestFeedKeyCannotSignOtherExports(t *testing.T) {
	s := newTestSigner(t)
	s.keys.Keys[0].ArtifactTypes = []string{exportsig.ArtifactFeedBatch}
	r := s.record(t, batch(1, 0, 1, ""))
	if _, _, err := VerifyChain(s.keys, Checkpoint{}, []Record{r}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"review":"forged"}`)
	at := time.Now().UTC().Truncate(time.Second)
	digest, _ := exportsig.Digest(exportsig.ArtifactReviewRecord, "1", "test-key", at, payload)
	raw, _ := ecdsa.SignASN1(rand.Reader, s.key, digest)
	sig := exportsig.Signature{ArtifactType: exportsig.ArtifactReviewRecord, Version: "1", KeyID: "test-key",
		Algorithm: exportsig.AlgorithmP256SHA256, SignedAt: at, Signature: base64.StdEncoding.EncodeToString(raw)}
	if err := exportsig.Verify(s.keys, sig, payload); err == nil {
		t.Fatal("feed key verified a review record")
	}
}

// encode and newRecord are the producer side of the format, which Verify
// implements; the tests build fixtures with them.
func encode(b Batch) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func newRecord(destinationID string, batchSeq int64, payload []byte, sig exportsig.Signature) Record {
	return Record{Type: "batch", DestinationID: destinationID, BatchSeq: batchSeq,
		Batch: base64.StdEncoding.EncodeToString(payload), Digest: Digest(payload), Signature: sig}
}
