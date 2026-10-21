package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestBuildSessionContextV2KnownAnswer(t *testing.T) {
	const expectedSession = "1c6f1471a65a3565c2954e19f9380d795b953f638b2e6bf2262b82cdc39357d2"
	fixtureBytes, err := os.ReadFile("testvectors/v2/operation-session-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input struct {
			VerifierID   string `json:"verifier_id"`
			WorkspaceID  string `json:"workspace_id"`
			AgentID      string `json:"agent_id"`
			SessionID    string `json:"session_id"`
			InvocationID string `json:"invocation_id"`
			RequestHash  string `json:"request_hash_hex"`
		} `json:"input"`
		Expected string `json:"expected_session_context_hex"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	requestHash, err := hex.DecodeString(fixture.Input.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BuildSessionContextV2(SessionContextV2Inputs{
		VerifierID: fixture.Input.VerifierID, WorkspaceID: fixture.Input.WorkspaceID,
		AgentID: fixture.Input.AgentID, SessionID: fixture.Input.SessionID,
		InvocationID: fixture.Input.InvocationID, RequestHash: requestHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Expected != expectedSession {
		t.Fatalf("fixture session context = %s, want pinned value %s", fixture.Expected, expectedSession)
	}
	if hex.EncodeToString(got) != expectedSession {
		t.Fatalf("session context = %x, want %s", got, expectedSession)
	}
}

func TestBuildSessionContextV2RejectsNonCanonicalIdentifiers(t *testing.T) {
	requestHash := make([]byte, 32)
	base := SessionContextV2Inputs{VerifierID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", WorkspaceID: "00000000-0000-4000-8000-000000000001", AgentID: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", RequestHash: requestHash}
	cases := []struct {
		name   string
		mutate func(*SessionContextV2Inputs)
	}{
		{"uppercase verifier", func(v *SessionContextV2Inputs) {
			v.VerifierID = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
		}},
		{"v1-length verifier ID", func(v *SessionContextV2Inputs) { v.VerifierID = "0123456789abcdef0123456789abcdef" }},
		{"v1-length agent ID", func(v *SessionContextV2Inputs) { v.AgentID = "00112233445566778899aabbccddeeff" }},
		{"noncanonical workspace", func(v *SessionContextV2Inputs) { v.WorkspaceID = "00000000000040008000000000000001" }},
		{"malformed agent", func(v *SessionContextV2Inputs) { v.AgentID = "agent" }},
		{"short request hash", func(v *SessionContextV2Inputs) { v.RequestHash = make([]byte, 31) }},
		{"invalid UTF-8 session ID", func(v *SessionContextV2Inputs) { v.SessionID = string([]byte{0xff}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			if _, err := BuildSessionContextV2(in); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestVerifySessionContextPolicyDigestKnownAnswer(t *testing.T) {
	const expectedDigest = "sha384:610c40faa472aa2a4f905988899733758cccf30f243aed35f1f42433228a28dbab1725cb2a4a6811029a8109da0b9b29"
	const expectedCanonical = `{"profile":"ratify.verify.session-context/v1","require_bound":true,"required_fields":["verifier_id","workspace_id","agent_id","session_id","invocation_id","request_hash"],"version":1}`
	fixtureBytes, err := os.ReadFile("testvectors/v2/operation-session-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Policy json.RawMessage `json:"context_policy"`
		Digest string          `json:"context_policy_digest"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(fixture.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, []byte(expectedCanonical)) {
		t.Fatalf("canonical Verify context policy = %s, want %s", canonical, expectedCanonical)
	}
	digest := sha512.Sum384(canonical)
	if fixture.Digest != expectedDigest {
		t.Fatalf("fixture policy digest = %s, want pinned value %s", fixture.Digest, expectedDigest)
	}
	want := strings.TrimPrefix(expectedDigest, "sha384:")
	if got := fmt.Sprintf("%x", digest); got != want {
		t.Fatalf("context policy digest = %s, want %s; canonical=%s", got, want, json.RawMessage(canonical))
	}
}

func TestBuildOperationContextV2SeparatesFields(t *testing.T) {
	const expectedRequestHash = "06ae35bea047663f0a732f1c161a579f2c244a7fe6f8b1697bfea6c44c3f9631"
	fixtureBytes, err := os.ReadFile("testvectors/v2/operation-session-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Operation struct {
			RequiredScope string `json:"required_scope"`
			Operation     string `json:"operation"`
			ResourceID    string `json:"resource_id"`
			RequestedPath string `json:"requested_path"`
			PayloadDigest string `json:"payload_digest_hex"`
		} `json:"operation_input"`
		ExpectedRequestHash string `json:"expected_request_hash_hex"`
		InvalidRequiredScopes []string `json:"invalid_required_scopes"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := hex.DecodeString(fixture.Operation.PayloadDigest)
	if err != nil {
		t.Fatal(err)
	}
	a, err := BuildOperationContextV2(OperationContextV2Inputs{
		RequiredScope: fixture.Operation.RequiredScope,
		Operation:     fixture.Operation.Operation,
		ResourceID:    fixture.Operation.ResourceID,
		RequestedPath: fixture.Operation.RequestedPath,
		PayloadDigest: payloadDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.ExpectedRequestHash != expectedRequestHash {
		t.Fatalf("fixture request hash = %s, want pinned value %s", fixture.ExpectedRequestHash, expectedRequestHash)
	}
	if got := hex.EncodeToString(a); got != expectedRequestHash {
		t.Fatalf("request hash = %s, want %s", got, expectedRequestHash)
	}
	b, err := BuildOperationContextV2(OperationContextV2Inputs{RequiredScope: "data:read", Operation: "read", ResourceID: "r1", RequestedPath: "/records/1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildOperationContextV2(OperationContextV2Inputs{RequiredScope: "data:read", Operation: "read", ResourceID: "r1/records", RequestedPath: "/1"})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) == hex.EncodeToString(c) {
		t.Fatal("length-prefixed fields must not collide across boundaries")
	}
	if _, err := BuildOperationContextV2(OperationContextV2Inputs{RequiredScope: "data:read", PayloadDigest: make([]byte, 31)}); err == nil {
		t.Fatal("expected malformed payload digest rejection")
	}
	for _, scope := range fixture.InvalidRequiredScopes {
		if _, err := BuildOperationContextV2(OperationContextV2Inputs{RequiredScope: scope}); err == nil {
			t.Errorf("accepted non-canonical v2 required scope %q", scope)
		}
	}
}

func TestOperationSessionFixtureHasKnownVersionAndFields(t *testing.T) {
	fixtureBytes, err := os.ReadFile("testvectors/v2/operation-session-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version                      int             `json:"version"`
		ContextPolicy                json.RawMessage `json:"context_policy"`
		ContextPolicyDigest          string          `json:"context_policy_digest"`
		Input                        json.RawMessage `json:"input"`
		ExpectedSessionContext       string          `json:"expected_session_context_hex"`
		OperationInput               json.RawMessage `json:"operation_input"`
		ExpectedRequestHash          string          `json:"expected_request_hash_hex"`
		VerifyAPIOperationInput      json.RawMessage `json:"verify_api_operation_input"`
		ExpectedVerifyAPIRequestHash string          `json:"expected_verify_api_request_hash_hex"`
		EmptyPayloadOperationInput   json.RawMessage `json:"empty_payload_operation_input"`
		ExpectedEmptyRequestHash     string          `json:"expected_empty_request_hash_hex"`
		ExpectedEmptySessionContext  string          `json:"expected_empty_session_context_hex"`
		InvalidRequiredScopes        json.RawMessage `json:"invalid_required_scopes"`
		VerifyAPIPayloadDigestCases  json.RawMessage `json:"verify_api_payload_digest_decode_cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(fixtureBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 2 || len(fixture.ContextPolicy) == 0 || fixture.ContextPolicyDigest == "" || len(fixture.Input) == 0 || fixture.ExpectedSessionContext == "" || len(fixture.OperationInput) == 0 || fixture.ExpectedRequestHash == "" || len(fixture.VerifyAPIOperationInput) == 0 || fixture.ExpectedVerifyAPIRequestHash == "" || len(fixture.EmptyPayloadOperationInput) == 0 || fixture.ExpectedEmptyRequestHash == "" || fixture.ExpectedEmptySessionContext == "" || len(fixture.InvalidRequiredScopes) == 0 || len(fixture.VerifyAPIPayloadDigestCases) == 0 {
		t.Fatal("fixture is missing a required v2 known-answer field")
	}
}

func TestVerifyAPIPayloadDigestDecodesToOperationVectorBytes(t *testing.T) {
	fixtureBytes, err := os.ReadFile("testvectors/v2/operation-session-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RawOperation struct {
			RequiredScope    string  `json:"required_scope"`
			Operation        string  `json:"operation"`
			ResourceID       string  `json:"resource_id"`
			RequestedPath    string  `json:"requested_path"`
			PayloadDigestHex *string `json:"payload_digest_hex"`
		} `json:"operation_input"`
		Operation struct {
			RequiredScope string `json:"required_scope"`
			Operation     string `json:"operation"`
			ResourceID    string `json:"resource_id"`
			RequestedPath string `json:"requested_path"`
			PayloadDigest string `json:"payload_digest"`
		} `json:"verify_api_operation_input"`
		Expected          string `json:"expected_verify_api_request_hash_hex"`
		DigestDecodeCases []struct {
			Name        string  `json:"name"`
			Encoded     *string `json:"encoded"`
			Valid       bool    `json:"valid"`
			ExpectedHex string  `json:"expected_hex"`
		} `json:"verify_api_payload_digest_decode_cases"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.RawOperation.PayloadDigestHex == nil {
		t.Fatal("raw operation vector must include its payload digest")
	}
	payloadDigest, err := DecodePayloadDigest(&fixture.Operation.PayloadDigest)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := BuildOperationContextV2(OperationContextV2Inputs{
		RequiredScope: fixture.Operation.RequiredScope, Operation: fixture.Operation.Operation,
		ResourceID: fixture.Operation.ResourceID, RequestedPath: fixture.Operation.RequestedPath,
		PayloadDigest: payloadDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(requestHash); got != fixture.Expected || got != "06ae35bea047663f0a732f1c161a579f2c244a7fe6f8b1697bfea6c44c3f9631" {
		t.Fatalf("Verify API request hash = %s, want %s", got, fixture.Expected)
	}
	rawDigest, err := hex.DecodeString(*fixture.RawOperation.PayloadDigestHex)
	if err != nil {
		t.Fatal(err)
	}
	rawRequestHash, err := BuildOperationContextV2(OperationContextV2Inputs{
		RequiredScope: fixture.RawOperation.RequiredScope, Operation: fixture.RawOperation.Operation,
		ResourceID: fixture.RawOperation.ResourceID, RequestedPath: fixture.RawOperation.RequestedPath,
		PayloadDigest: rawDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestHash, rawRequestHash) {
		t.Fatalf("Verify API wire hash %x differs from raw operation vector hash %x", requestHash, rawRequestHash)
	}
	if len(fixture.DigestDecodeCases) == 0 {
		t.Fatal("missing Verify API payload digest decoder vectors")
	}
	for _, tc := range fixture.DigestDecodeCases {
		got, err := DecodePayloadDigest(tc.Encoded)
		if tc.Valid {
			if err != nil {
				t.Errorf("%s: DecodePayloadDigest returned error: %v", tc.Name, err)
				continue
			}
			if hex.EncodeToString(got) != tc.ExpectedHex {
				t.Errorf("%s: decoded digest %x, want %s", tc.Name, got, tc.ExpectedHex)
			}
		} else if err == nil {
			t.Errorf("%s: DecodePayloadDigest accepted malformed input", tc.Name)
		}
	}
}

func TestBuildEmptyPayloadOperationContextChainsIntoSessionContext(t *testing.T) {
	const requestHashHex = "7c8898e3e79cee60099a3bfeef03eb641c3e9112130cdc8052f87a20a98567b5"
	const sessionHex = "baf54a0c7cb89b813b2bc4b65b2a960dd9a32becb6c3a7c0ad3c3969fabc7aa3"
	fixtureBytes, err := os.ReadFile("testvectors/v2/operation-session-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Operation struct {
			RequiredScope string  `json:"required_scope"`
			Operation     string  `json:"operation"`
			ResourceID    string  `json:"resource_id"`
			RequestedPath string  `json:"requested_path"`
			PayloadDigest *string `json:"payload_digest_hex"`
		} `json:"empty_payload_operation_input"`
		ExpectedRequestHash string `json:"expected_empty_request_hash_hex"`
		ExpectedSession     string `json:"expected_empty_session_context_hex"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Operation.PayloadDigest != nil || fixture.ExpectedRequestHash != requestHashHex || fixture.ExpectedSession != sessionHex {
		t.Fatal("empty-payload operation fixture differs from its pinned known answers")
	}
	operationHash, err := BuildOperationContextV2(OperationContextV2Inputs{
		RequiredScope: fixture.Operation.RequiredScope, Operation: fixture.Operation.Operation,
		ResourceID: fixture.Operation.ResourceID, RequestedPath: fixture.Operation.RequestedPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(operationHash); got != requestHashHex {
		t.Fatalf("empty-payload operation hash = %s, want %s", got, requestHashHex)
	}
	session, err := BuildSessionContextV2(SessionContextV2Inputs{
		VerifierID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", WorkspaceID: "00000000-0000-4000-8000-000000000001",
		AgentID: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", SessionID: "session-01", InvocationID: "invocation-01", RequestHash: operationHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(session); got != sessionHex {
		t.Fatalf("session context from empty-payload operation = %s, want %s", got, sessionHex)
	}
}
