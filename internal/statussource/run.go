package statussource

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Run implements a reference source command:
//
//	TOOL init [REVOKED_IDS.json]  # once: create the state, optionally with prior revocations
//	TOOL recover INVENTORY.json   # after an interrupted read has been reconciled
//	TOOL                          # serve GET /v1/revoked-cert-ids
func Run(tool string, args []string, cfg Config, source *Source, bearer string) error {
	name := source.Provider.Name()
	if len(args) >= 1 && len(args) <= 2 && args[0] == "init" {
		var seed []string
		if len(args) == 2 {
			data, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &seed); err != nil {
				return errors.New("the revoked IDs file must be a JSON array of certificate ID strings")
			}
		}
		if err := InitState(cfg.StateFile, cfg.IssuerID, seed...); err != nil {
			return err
		}
		log.Printf("created revocation state %s for issuer %s with %d revoked certificates", cfg.StateFile, cfg.IssuerID, len(seed))
		return nil
	}
	if len(args) == 2 && args[0] == "recover" {
		lock, err := LockState(cfg.StateFile)
		if err != nil {
			return err
		}
		defer lock.Close()
		inventory, err := ReadInventory(args[1], source.Provider)
		if err != nil {
			return err
		}
		if err := RecoverInterruptedRead(cfg.StateFile, cfg.IssuerID, source.Provider, inventory); err != nil {
			return err
		}
		log.Printf("recovered %s with %d inventoried certificates", cfg.StateFile, len(inventory))
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: %s [init [REVOKED_IDS.json] | recover INVENTORY.json]", tool)
	}
	lock, err := LockState(cfg.StateFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := LoadState(cfg.StateFile, cfg.IssuerID, source.Provider); err != nil {
		return err
	}
	// Track the startup mapping before serving, so an entry removed before
	// the first request is still checked.
	if !InterruptedScan(cfg.StateFile) {
		if err := TrackInventory(cfg.StateFile, cfg.IssuerID, source.Provider, source.Mapping); err != nil {
			return err
		}
	}
	if InterruptedScan(cfg.StateFile) {
		return fmt.Errorf("a %s read started at %s was interrupted before its results were saved; check the %s audit log from then for disabled, deleted, and removed mapped users, add any revoked certificate IDs to the state, then run recover with the complete cert_id inventory",
			name, InterruptedScanStart(cfg.StateFile), name)
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/revoked-cert-ids", Handler(source, bearer))
	server := &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout: 30 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("serving %s snapshots for issuer %s (%d mapped certificates) on https://%s/v1/revoked-cert-ids",
		name, cfg.IssuerID, len(source.Mapping), cfg.ListenAddr)
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
	return <-shutdownDone
}

// NoRedirectClient refuses redirects (a redirect to a login page is an
// error, never data) and bounds each request.
func NoRedirectClient(base *http.Client) *http.Client {
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Second
	}
	return &client
}
