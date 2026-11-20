package main

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func TestVerifyEndpointsStayOnTheConfiguredReceiverAPI(t *testing.T) {
	status, release, err := verifyEndpoints("https://verify.example/v1/verify/v2/status-lists")
	if err != nil || status != "https://verify.example/v1/verify/v2/status" ||
		release != "https://verify.example/v1/verify/v2/status-publisher/release" {
		t.Fatalf("derived %q %q %v", status, release, err)
	}
	for _, bad := range []string{"https://verify.example/v1/verify/v2/status", "https://verify.example/v1/verify/v2/status-lists?x=1"} {
		if _, _, err := verifyEndpoints(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// A status key generated with ratify-keys (the tool customers use to create
// and enroll customer-held keys) loads directly, as does the original
// bridge key format. Other fields or loose permissions are refused.
func TestLoadStatusKeyAcceptsRatifyKeysFiles(t *testing.T) {
	_, private, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ml, err := private.MLDSA65.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, v any, perm os.FileMode) string {
		data, _ := json.Marshal(v)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, perm); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, path := range []string{
		write("ratify-keys.key", map[string][]byte{"ed25519_private_key": private.Ed25519, "mldsa65_private_key": ml}, 0600),
		write("bridge.key", map[string][]byte{"ed25519": private.Ed25519, "ml_dsa_65": ml}, 0600),
	} {
		key, err := loadStatusKey(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if string(key.Public().Ed25519) != string(private.Public().Ed25519) {
			t.Fatalf("%s loaded a different key", path)
		}
	}
	for _, path := range []string{
		write("loose.key", map[string][]byte{"ed25519_private_key": private.Ed25519, "mldsa65_private_key": ml}, 0644),
		write("mixed.key", map[string][]byte{"ed25519": private.Ed25519, "mldsa65_private_key": ml}, 0600),
		write("extra.key", map[string][]byte{"ed25519": private.Ed25519, "ml_dsa_65": ml, "note": nil}, 0600),
	} {
		if _, err := loadStatusKey(path); err == nil {
			t.Fatalf("%s: accepted", path)
		}
	}
}

// A customer source on a private CA is trusted only for the source; the
// Verify connection keeps the system roots.
func TestSourceClientTrustsOnlyTheConfiguredSourceCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	system, err := sourceClient("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := system.Get(server.URL); err == nil {
		t.Fatal("system-root client trusted a private source certificate")
	}
	private, err := sourceClient(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	response, err := private.Get(server.URL)
	if err != nil {
		t.Fatalf("source CA client: %v", err)
	}
	response.Body.Close()
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0600)
	if _, err := sourceClient(empty); err == nil {
		t.Fatal("accepted a CA file with no certificates")
	}
}
