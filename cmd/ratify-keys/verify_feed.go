package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/exportsig"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/feedbatch"
)

// feedEventLine is one delivered event line: what a SIEM indexes.
type feedEventLine struct {
	DestinationID string          `json:"destination_id"`
	BatchSeq      int64           `json:"batch_seq"`
	Event         json.RawMessage `json:"event"`
}

// verifyFeedCommand checks evidence feed deliveries offline: every batch
// record's signature against the feed keys, that the batches link without an
// edit, a missing batch, or a skipped stream position, and that every signed
// event arrived as exactly one matching event line under its own destination
// and batch. Lines may be the webhook's NDJSON or Splunk HEC events (the line
// under "event"); a batch delivered more than once is counted once.
func verifyFeedCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ratify-keys verify-feed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	keysPath := fs.String("keys", "", "feed key set from GET /v1/verify/feed-keys")
	deliveriesPath := fs.String("deliveries", "", "received deliveries, one JSON line each")
	fromPath := fs.String("from", "", "checkpoint printed by an earlier run (optional)")
	batchesOnly := fs.Bool("batches-only", false, "verify the batch records alone, without event lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keysPath == "" || *deliveriesPath == "" {
		return errors.New("verify-feed needs --keys FEED_KEYS.json and --deliveries FILE")
	}
	var keys exportsig.KeySet
	if err := readJSONFile(*keysPath, maxInputBytes, &keys); err != nil {
		return err
	}
	for _, k := range keys.Keys {
		if len(k.ArtifactTypes) != 1 || k.ArtifactTypes[0] != exportsig.ArtifactFeedBatch {
			return fmt.Errorf("key %q is not a feed key; save the key set from /v1/verify/feed-keys", k.KeyID)
		}
	}
	var from feedbatch.Checkpoint
	if *fromPath != "" {
		if err := readJSONFile(*fromPath, maxInputBytes, &from); err != nil {
			return err
		}
	}
	data, err := readLimitedFile(*deliveriesPath, maxExportPayloadBytes)
	if err != nil {
		return err
	}
	records, lines, err := feedRecords(data)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("no batch records found")
	}
	batches, cp, err := feedbatch.VerifyChain(keys, from, records)
	if err != nil {
		return fmt.Errorf("feed NOT verified: %w", err)
	}
	count := 0
	for _, b := range batches {
		count += len(b.Events)
	}
	if *batchesOnly {
		if len(lines) > 0 {
			return errors.New("--batches-only was given but the file has event lines; verify them too")
		}
	} else if err := matchFeedEvents(batches, lines); err != nil {
		return fmt.Errorf("feed NOT verified: %w", err)
	}
	checkpoint, _ := json.Marshal(cp)
	scope := "events and event lines"
	if *batchesOnly {
		scope = "events (batch records only; event lines not checked)"
	}
	fmt.Fprintf(stdout, "verified: %d batches (%d to %d), %d %s, stream positions %d to %d\ncheckpoint: %s\n",
		len(batches), batches[0].BatchSeq, cp.BatchSeq, count, scope, batches[0].AfterSeq+1, cp.LastSeq, checkpoint)
	return nil
}

// matchFeedEvents requires a one-to-one match between signed events and
// event lines (identical retries collapse): each line names its batch and
// destination and carries exactly the signed event.
func matchFeedEvents(batches []feedbatch.Batch, lines []feedEventLine) error {
	type where struct {
		dest string
		seq  int64
	}
	signed := map[string]json.RawMessage{}
	at := map[string]where{}
	for _, b := range batches {
		for _, e := range b.Events {
			raw, err := json.Marshal(e)
			if err != nil {
				return err
			}
			signed[e.ID], at[e.ID] = raw, where{b.DestinationID, b.BatchSeq}
		}
	}
	seen := map[string]bool{}
	for _, line := range lines {
		var e feedbatch.Event
		if err := json.Unmarshal(line.Event, &e); err != nil {
			return fmt.Errorf("event line: %w", err)
		}
		want, ok := signed[e.ID]
		got, _ := json.Marshal(e)
		if !ok || !bytes.Equal(want, got) {
			return fmt.Errorf("event %s does not match a verified batch", e.ID)
		}
		if w := at[e.ID]; line.DestinationID != w.dest || line.BatchSeq != w.seq {
			return fmt.Errorf("event %s arrived under destination %s batch %d, signed in batch %d", e.ID, line.DestinationID, line.BatchSeq, w.seq)
		}
		seen[e.ID] = true
	}
	for id := range signed {
		if !seen[id] {
			return fmt.Errorf("event %s is in a verified batch but no event line carries it", id)
		}
	}
	return nil
}

// feedRecords extracts batch records ordered by batch number, and the event
// lines. Duplicate deliveries of one batch must be identical; any other line
// type is refused.
func feedRecords(data []byte) ([]feedbatch.Record, []feedEventLine, error) {
	var events []feedEventLine
	bySeq := map[int64]feedbatch.Record{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var probe struct {
			Type  string          `json:"type"`
			Event json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, nil, fmt.Errorf("line %d is not JSON: %w", line, err)
		}
		if probe.Type == "" && len(probe.Event) > 0 { // Splunk HEC event
			raw = probe.Event
			if err := json.Unmarshal(raw, &probe); err != nil {
				return nil, nil, fmt.Errorf("line %d: %w", line, err)
			}
		}
		switch probe.Type {
		case "event":
			var e feedEventLine
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, nil, fmt.Errorf("line %d: %w", line, err)
			}
			events = append(events, e)
		case "batch":
			var r feedbatch.Record
			if err := json.Unmarshal(raw, &r); err != nil {
				return nil, nil, fmt.Errorf("line %d: %w", line, err)
			}
			if prev, ok := bySeq[r.BatchSeq]; ok && (prev.Digest != r.Digest || prev.Batch != r.Batch) {
				return nil, nil, fmt.Errorf("batch %d was delivered twice with different content", r.BatchSeq)
			}
			bySeq[r.BatchSeq] = r
		default:
			return nil, nil, fmt.Errorf("line %d is neither an event nor a batch record", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	out := make([]feedbatch.Record, 0, len(bySeq))
	for _, r := range bySeq {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BatchSeq < out[j].BatchSeq })
	return out, events, nil
}
