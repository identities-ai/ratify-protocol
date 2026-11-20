// ratify-google-status-source is a customer-run, read-only reference IAM
// snapshot source for ratify-iam-bridge, for Google Workspace. It maps
// exact delegation certificate IDs to Google Workspace user IDs through a
// customer-owned mapping file and serves the bridge's source contract over
// HTTPS with a bearer token.
//
// The revocation rule (user suspended, archived, deleted, or no longer a
// direct or nested member of every configured group) is this reference's
// choice for the customer; Ratify only sees the resulting revoked
// certificate IDs. Copy and change it to apply a different customer policy.
//
// Usage:
//
//	ratify-google-status-source init [REVOKED_IDS.json]  # once: create the state, optionally with prior revocations
//	ratify-google-status-source recover INVENTORY.json   # after an interrupted read has been reconciled
//	ratify-google-status-source          # serve GET /v1/revoked-cert-ids
//
// Configuration: GOOGLE_STATUS_SOURCE_CONFIG names the JSON config file;
// GOOGLE_SERVICE_ACCOUNT_KEY_FILE names the owner-only service account JSON
// key; IAM_SOURCE_BEARER_TOKEN is the token ratify-iam-bridge sends as
// IAM_BRIDGE_SOURCE_TOKEN.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/identities-ai/ratify-protocol/v2/internal/statussource"
	"github.com/identities-ai/ratify-protocol/v2/internal/toolversion"
)

// version is set at release build time with -ldflags "-X main.version=...";
// otherwise toolversion falls back to the module version from go install.
var version = "dev"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("ratify-google-status-source", toolversion.String(version))
		return
	}
	cfg, source, err := loadConfig(os.Getenv("GOOGLE_STATUS_SOURCE_CONFIG"), os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if err := statussource.Run("ratify-google-status-source", os.Args[1:], cfg.Config, source, os.Getenv("IAM_SOURCE_BEARER_TOKEN")); err != nil {
		log.Fatal(err)
	}
}
