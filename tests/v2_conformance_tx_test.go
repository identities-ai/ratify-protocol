package ratify_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// TestV2ConformanceTransactionVerification replays
// testvectors/v2/transaction-verification.json (SPEC-v2 §5.7) with the same
// provider and journal construction as the verifier-ordering vectors.
func TestV2ConformanceTransactionVerification(t *testing.T) {
	var f struct {
		Version     int               `json:"version"`
		Description string            `json:"description"`
		Semantics   map[string]string `json:"semantics"`
		Vectors     []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			ReceiptB64  string `json:"receipt_b64"`
			v2OrderingInputs
			Expected struct {
				ErrorClass string          `json:"error_class"`
				Result     json.RawMessage `json:"result"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	loadV2Vector(t, "transaction-verification.json", &f)
	if len(f.Vectors) == 0 {
		t.Fatal("no transaction verification vectors")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			req, cb, _ := v2BuildVerifyRequest(t, v.v2OrderingInputs, nil, &v2Counts{})
			sources := ratify.TransactionVerifySourcesV2{StatusEvidence: cb.StatusEvidence, StatusJournal: cb.StatusJournal, StatusKeys: req.StatusKeys, StatusPolicy: req.StatusPolicy}
			if v.Trust != nil {
				sources.Trust = cb.Trust
			}
			got, err := ratify.VerifyTransactionReceiptV2(context.Background(), ratify.TransactionVerifyRequestV2{
				Receipt: unb64(t, v.ReceiptB64), Now: v.Now, FutureSkewSeconds: v.FutureSkewSeconds,
			}, sources)
			if v.Expected.ErrorClass != "" {
				if string(ratify.V2ErrorClassOf(err)) != v.Expected.ErrorClass {
					t.Fatalf("class %q (%v), want %s", ratify.V2ErrorClassOf(err), err, v.Expected.ErrorClass)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want ratify.TransactionReceiptVerificationV2
			if err := json.Unmarshal(v.Expected.Result, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				gotJSON, _ := json.Marshal(got)
				t.Fatalf("result\n got %s\nwant %s", gotJSON, v.Expected.Result)
			}
		})
	}
}
