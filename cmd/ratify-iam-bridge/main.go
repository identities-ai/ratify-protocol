package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/internal/toolversion"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/iambridge"
)

type config struct {
	IssuerID          string                 `json:"issuer_id"`
	Epoch             uint64                 `json:"epoch"`
	StatusPublicKey   ratify.HybridPublicKey `json:"status_public_key"`
	StatusPrivateFile string                 `json:"status_private_file"`
	StateFile         string                 `json:"state_file"`
	SourceURL         string                 `json:"source_url"`
	VerifyURL         string                 `json:"verify_url"`
	// SourceCAFile optionally names PEM roots for a source on a private CA.
	// They are trusted for the source only, never for Verify.
	SourceCAFile string `json:"source_ca_file,omitempty"`
}

// version is set at release build time with -ldflags "-X main.version=...";
// otherwise toolversion falls back to the module version from go install.
var version = "dev"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("ratify-iam-bridge", toolversion.String(version))
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configPath := os.Getenv("IAM_BRIDGE_CONFIG")
	if configPath == "" {
		return errors.New("IAM_BRIDGE_CONFIG is required")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("decode IAM bridge configuration: %w", err)
	}
	if cfg.IssuerID == "" || cfg.Epoch == 0 || cfg.StateFile == "" {
		return errors.New("IAM bridge issuer, epoch, and state file are required")
	}
	state := &iambridge.FileState{Path: cfg.StateFile}
	if err := state.Lock(); err != nil {
		return err
	}
	defer state.Close()
	if len(os.Args) > 1 {
		if len(os.Args) != 4 || os.Args[1] != "unblock" {
			return errors.New("usage: ratify-iam-bridge [unblock ACCEPTED_SEQUENCE MAX_OBSERVED_SEQUENCE]")
		}
		acceptedSequence, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil || acceptedSequence < 0 {
			return errors.New("accepted sequence must be a nonnegative integer")
		}
		maxObservedSequence, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil || maxObservedSequence < 0 {
			return errors.New("maximum observed sequence must be a nonnegative integer")
		}
		current, err := state.Load()
		if err != nil {
			return err
		}
		if current.IssuerID != cfg.IssuerID || current.Epoch != cfg.Epoch {
			return errors.New("IAM bridge configuration does not match locked state")
		}
		if err := state.Unblock(acceptedSequence, maxObservedSequence); err != nil {
			return err
		}
		log.Printf("IAM status bridge unblocked after operator confirmed accepted sequence %d and maximum observed sequence %d", acceptedSequence, maxObservedSequence)
		return nil
	}
	sourceToken := os.Getenv("IAM_BRIDGE_SOURCE_TOKEN")
	apiKey := os.Getenv("IAM_BRIDGE_RECEIVER_API_KEY")
	if sourceToken == "" || apiKey == "" || cfg.StatusPrivateFile == "" {
		return errors.New("IAM_BRIDGE_SOURCE_TOKEN, IAM_BRIDGE_RECEIVER_API_KEY, and status private key file are required")
	}
	for _, endpoint := range []string{cfg.SourceURL, cfg.VerifyURL} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return errors.New("IAM bridge endpoints must be HTTPS URLs without user info or fragments")
		}
	}
	key, err := loadStatusKey(cfg.StatusPrivateFile)
	if err != nil {
		return err
	}
	derived := key.Public()
	if string(derived.Ed25519) != string(cfg.StatusPublicKey.Ed25519) ||
		string(derived.MLDSA65) != string(cfg.StatusPublicKey.MLDSA65) {
		return errors.New("status private key does not match the configured public key")
	}
	statusURL, releaseURL, err := verifyEndpoints(cfg.VerifyURL)
	if err != nil {
		return err
	}
	// Verify's per-issuer lease fences writers by this secret identity. It is
	// new for every process, so a copied state file never shares a writer
	// slot, and it is never logged or reported by Verify.
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	publisherID := "iam-bridge-" + hex.EncodeToString(random)
	fingerprint := sha256.Sum256([]byte(publisherID))
	client := &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sourceHTTP, err := sourceClient(cfg.SourceCAFile)
	if err != nil {
		return err
	}
	publisher := iambridge.HTTPPublisher{Client: client, URL: cfg.VerifyURL, APIKey: apiKey,
		IssuerID: cfg.IssuerID, Epoch: cfg.Epoch, PublisherID: publisherID}
	bridge := &iambridge.Bridge{
		IssuerID: cfg.IssuerID, Epoch: cfg.Epoch, StatusKey: key, Store: state,
		Source:    iambridge.HTTPSource{Client: sourceHTTP, URL: cfg.SourceURL, Token: sourceToken},
		Publisher: publisher,
		Status:    iambridge.HTTPStatusReader{Client: client, URL: statusURL, APIKey: apiKey, IssuerID: cfg.IssuerID},
		Now:       time.Now, Lifetime: 5 * time.Minute, MaxSnapshotAge: 30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() {
		// Hand the issuer to a successor now instead of after lease expiry.
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := publisher.Release(release, releaseURL); err != nil {
			log.Printf("IAM status publisher lease release failed; a successor waits for expiry: %v", err)
		}
	}()
	wake := make(chan os.Signal, 1)
	signal.Notify(wake, syscall.SIGHUP)
	defer signal.Stop(wake)
	// The ID is a secret; owner health shows the same fingerprint.
	log.Printf("IAM status bridge publishing issuer %s epoch %d as publisher fingerprint %s",
		cfg.IssuerID, cfg.Epoch, hex.EncodeToString(fingerprint[:])[:16])
	for {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := bridge.Reconcile(attempt)
		cancel()
		next := time.Minute
		if err != nil && ctx.Err() == nil {
			log.Printf("IAM status reconciliation failed: %v", err)
			if errors.Is(err, iambridge.ErrPublisherConflict) || errors.Is(err, iambridge.ErrSequenceConflict) {
				// Another writer holds the issuer, or Verify already holds the
				// pending sequence; check again soon so a released or expired
				// lease is taken, or the sequence reconciled, before status
				// goes stale.
				next = 10 * time.Second
			}
		}
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		case <-wake: // An IAM event is only a wake-up hint; re-read the source.
			timer.Stop()
		}
	}
}

// verifyEndpoints derives the receiver status read and lease release URLs
// from the configured /v1/verify/v2/status-lists publication URL.
func verifyEndpoints(publishURL string) (string, string, error) {
	parsed, err := url.Parse(publishURL)
	if err != nil || !strings.HasSuffix(parsed.Path, "/v1/verify/v2/status-lists") || parsed.RawQuery != "" {
		return "", "", errors.New("verify_url must be the /v1/verify/v2/status-lists URL")
	}
	base := strings.TrimSuffix(parsed.Path, "/status-lists")
	status, release := *parsed, *parsed
	status.Path, release.Path = base+"/status", base+"/status-publisher/release"
	return status.String(), release.String(), nil
}

// sourceClient trusts the system roots, or only caFile's roots when set.
func sourceClient(caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("source CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("source CA file has no PEM certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func loadStatusKey(path string) (ratify.HybridPrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return ratify.HybridPrivateKey{}, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return ratify.HybridPrivateKey{}, errors.New("status private key file must be owner-only")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ratify.HybridPrivateKey{}, err
	}
	// The bridge format, or the key file ratify-keys generate writes.
	var raw struct {
		Ed25519   []byte `json:"ed25519"`
		MLDSA65   []byte `json:"ml_dsa_65"`
		KeysEd    []byte `json:"ed25519_private_key"`
		KeysMLDSA []byte `json:"mldsa65_private_key"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return ratify.HybridPrivateKey{}, errors.New("decode status private key: unrecognized key file")
	}
	bridgeFormat := raw.Ed25519 != nil || raw.MLDSA65 != nil
	keysFormat := raw.KeysEd != nil || raw.KeysMLDSA != nil
	if bridgeFormat == keysFormat {
		return ratify.HybridPrivateKey{}, errors.New("decode status private key: unrecognized key file")
	}
	if keysFormat {
		raw.Ed25519, raw.MLDSA65 = raw.KeysEd, raw.KeysMLDSA
	}
	if len(raw.Ed25519) != ed25519.PrivateKeySize {
		return ratify.HybridPrivateKey{}, errors.New("status Ed25519 private key has invalid length")
	}
	var ml mldsa65.PrivateKey
	if err := ml.UnmarshalBinary(raw.MLDSA65); err != nil {
		return ratify.HybridPrivateKey{}, fmt.Errorf("decode status ML-DSA-65 private key: %w", err)
	}
	return ratify.HybridPrivateKey{Ed25519: ed25519.PrivateKey(raw.Ed25519), MLDSA65: &ml}, nil
}
