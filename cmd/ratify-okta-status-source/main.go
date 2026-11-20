// ratify-okta-status-source is a customer-run, read-only reference IAM
// snapshot source for ratify-iam-bridge. It maps exact delegation
// certificate IDs to Okta users through a customer-owned mapping file and
// serves the bridge's source contract over HTTPS with a bearer token.
//
// The revocation rule (deactivated, suspended, deleted, or unassigned from a
// configured app) is this reference's choice for the customer; Ratify only
// sees the resulting revoked certificate IDs. Copy and change it to apply a
// different customer policy.
//
// Usage:
//
//	ratify-okta-status-source init [REVOKED_IDS.json]  # once: create the state, optionally with prior revocations
//	ratify-okta-status-source recover INVENTORY.json   # after an interrupted read has been reconciled
//	ratify-okta-status-source          # serve GET /v1/revoked-cert-ids
//
// Configuration: OKTA_STATUS_SOURCE_CONFIG names the JSON config file;
// OKTA_API_TOKEN is a read-only Okta API token; IAM_SOURCE_BEARER_TOKEN is
// the token ratify-iam-bridge sends as IAM_BRIDGE_SOURCE_TOKEN.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/identities-ai/ratify-protocol/v2/internal/toolversion"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is set at release build time with -ldflags "-X main.version=...";
// otherwise toolversion falls back to the module version from go install.
var version = "dev"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("ratify-okta-status-source", toolversion.String(version))
		return
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	cfg, source, err := loadConfig(os.Getenv("OKTA_STATUS_SOURCE_CONFIG"), os.Getenv)
	if err != nil {
		return err
	}
	if len(args) >= 1 && len(args) <= 2 && args[0] == "init" {
		// An issuer that already has revocations (from an earlier source)
		// starts with them: one certificate ID per line.
		var seed []string
		if len(args) == 2 {
			// A JSON array of exact certificate IDs, kept verbatim.
			data, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &seed); err != nil {
				return errors.New("the revoked IDs file must be a JSON array of certificate ID strings")
			}
		}
		if err := initState(cfg.StateFile, cfg.IssuerID, seed...); err != nil {
			return err
		}
		log.Printf("created revocation state %s for issuer %s with %d revoked certificates", cfg.StateFile, cfg.IssuerID, len(seed))
		return nil
	}
	if len(args) == 2 && args[0] == "recover" {
		// Run only after reconciling the interrupted read: add any revoked
		// IDs from Okta's system log to the state, and pass the complete
		// cert_id to Okta user ID inventory (mapping format).
		lock, err := lockState(cfg.StateFile)
		if err != nil {
			return err
		}
		defer lock.Close()
		inventory, err := readInventory(args[1])
		if err != nil {
			return err
		}
		if err := recoverInterruptedRead(cfg.StateFile, cfg.IssuerID, inventory); err != nil {
			return err
		}
		log.Printf("recovered %s with %d inventoried certificates", cfg.StateFile, len(inventory))
		return nil
	}
	if len(args) != 0 {
		return errors.New("usage: ratify-okta-status-source [init [REVOKED_IDS.json] | recover INVENTORY.json]")
	}
	lock, err := lockState(cfg.StateFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := loadState(cfg.StateFile, cfg.IssuerID); err != nil {
		return err
	}
	// Track the mapping read at startup before serving, so an entry removed
	// before the first request is still checked.
	if !interruptedScan(cfg.StateFile) {
		if err := trackInventory(cfg.StateFile, cfg.IssuerID, source.Mapping); err != nil {
			return err
		}
	}
	if interruptedScan(cfg.StateFile) {
		return fmt.Errorf("an Okta read started at %s was interrupted before its results were saved; check Okta's system log from then for deactivations, suspensions, and unassignments of mapped users, add any revoked certificate IDs to the state, then run recover with the complete cert_id inventory",
			interruptedScanStart(cfg.StateFile))
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/revoked-cert-ids", snapshotHandler(source, os.Getenv("IAM_SOURCE_BEARER_TOKEN")))
	server := &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout: 30 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("serving Okta snapshots for issuer %s (%d mapped certificates) on https://%s/v1/revoked-cert-ids",
		cfg.IssuerID, len(source.Mapping), cfg.ListenAddr)
	// On SIGTERM or SIGINT, finish the read in flight so its marker clears.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// Keep the state lock until the read in flight has finished.
	return <-shutdownDone
}
