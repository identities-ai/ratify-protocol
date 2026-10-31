package ratify

import "testing"

func TestV2ByteFieldsDoNotChangeV1ExtensionParams(t *testing.T) {
	for _, field := range []string{"delegation_digest", "previous_statement_hash"} {
		t.Run(field, func(t *testing.T) {
			nested := []byte(`{"params":{"` + field + `":"not base64!"}}`)
			if err := CheckWireJSON(nested); err != nil {
				t.Fatalf("v1 extension params changed: %v", err)
			}
			if err := checkWireJSONV2(nested, field); err != nil {
				t.Fatalf("nested application data was treated as a v2 byte field: %v", err)
			}
			root := []byte(`{"` + field + `":"not base64!"}`)
			if err := checkWireJSONV2(root, field); err == nil {
				t.Fatal("noncanonical top-level v2 byte field was accepted")
			}
		})
	}
}
