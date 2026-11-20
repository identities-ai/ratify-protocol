package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/feedbatch"
)

// Deliveries arrive as webhook NDJSON or as Splunk HEC events, possibly more
// than once; the verifier must read both and refuse a batch number that
// arrived with two different contents.
func TestFeedRecordsReadsWebhookAndHEC(t *testing.T) {
	webhook := `{"type":"event","destination_id":"d","batch_seq":1,"event":{"id":"o:1"}}
{"type":"batch","destination_id":"d","batch_seq":2,"batch":"Yg==","digest":"x2"}
{"type":"batch","destination_id":"d","batch_seq":1,"batch":"YQ==","digest":"x1"}
`
	hec := `{"time":1,"sourcetype":"ratify:evidence","event":{"type":"batch","destination_id":"d","batch_seq":1,"batch":"YQ==","digest":"x1"}}`
	records, events, err := feedRecords([]byte(webhook + hec))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].BatchSeq != 1 || records[1].BatchSeq != 2 || len(events) != 1 {
		t.Fatalf("records: %+v events %d", records, len(events))
	}
	conflict := strings.Replace(hec, `"digest":"x1"`, `"digest":"other"`, 1)
	if _, _, err := feedRecords([]byte(webhook + conflict)); err == nil {
		t.Fatal("conflicting duplicate batch accepted")
	}
	if _, _, err := feedRecords([]byte(`{"type":"other"}`)); err == nil {
		t.Fatal("unknown line accepted")
	}
}

// A SIEM indexes the event lines, so a verified batch is not enough: every
// signed event must have arrived, under its own batch, unaltered.
func TestMatchFeedEventsRequiresEveryEvent(t *testing.T) {
	ev := func(id string, seq int64) feedbatch.Event {
		return feedbatch.Event{ID: id, Seq: seq, Source: "audit", Kind: "k", Payload: json.RawMessage(`{"a":1}`)}
	}
	b := feedbatch.Batch{DestinationID: "d", BatchSeq: 1, Events: []feedbatch.Event{ev("o:1", 1), ev("o:2", 2)}}
	line := func(e feedbatch.Event, seq int64) feedEventLine {
		raw, _ := json.Marshal(e)
		return feedEventLine{DestinationID: "d", BatchSeq: seq, Event: raw}
	}
	if err := matchFeedEvents([]feedbatch.Batch{b}, []feedEventLine{line(b.Events[0], 1), line(b.Events[1], 1)}); err != nil {
		t.Fatal(err)
	}
	if err := matchFeedEvents([]feedbatch.Batch{b}, []feedEventLine{line(b.Events[0], 1)}); err == nil {
		t.Fatal("missing event line accepted")
	}
	if err := matchFeedEvents([]feedbatch.Batch{b}, []feedEventLine{line(b.Events[0], 1), line(b.Events[1], 2)}); err == nil {
		t.Fatal("event under the wrong batch accepted")
	}
	edited := b.Events[1]
	edited.Kind = "other"
	if err := matchFeedEvents([]feedbatch.Batch{b}, []feedEventLine{line(b.Events[0], 1), line(edited, 1)}); err == nil {
		t.Fatal("edited event accepted")
	}
}
