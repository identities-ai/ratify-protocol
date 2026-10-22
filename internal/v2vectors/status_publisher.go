package v2vectors

// Signed-status publisher vectors (SPEC-v2 §5.4, status publisher duties).
// The publisher output is described by its signed fields, not its bytes,
// because ML-DSA-65 signing may be hedged; every produced object must verify
// under the configured status key and is then ingested into a
// SecurityJournalV2 to show the verifier-side result.

type publishedListJSON struct {
	Sequence   int64    `json:"sequence"`
	UpdatedAt  int64    `json:"updated_at"`
	NextUpdate int64    `json:"next_update"`
	Revoked    []string `json:"revoked"`
}

type publishedPushJSON struct {
	Sequence int64    `json:"sequence"`
	PushedAt int64    `json:"pushed_at"`
	Revoked  []string `json:"revoked"`
}

type publisherExpectJSON struct {
	Result string             `json:"result,omitempty"`
	List   *publishedListJSON `json:"list,omitempty"`
	Push   *publishedPushJSON `json:"push,omitempty"`
	Status string             `json:"status,omitempty"`
	Reason string             `json:"reason,omitempty"`
}

type publisherStepJSON struct {
	Op          string              `json:"op"`
	At          int64               `json:"at,omitempty"`
	CertIDs     []string            `json:"cert_ids,omitempty"`
	CertID      string              `json:"cert_id,omitempty"`
	Publication *int                `json:"publication,omitempty"`
	Object      string              `json:"object,omitempty"`
	Expect      publisherExpectJSON `json:"expect"`
}

type publisherScenarioJSON struct {
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Issuer          string              `json:"issuer"`
	StatusKey       string              `json:"status_key"`
	OtherRoleKeys   []string            `json:"other_role_keys"`
	LifetimeSeconds int64               `json:"lifetime_seconds"`
	Publisher       string              `json:"publisher"`
	JournalSetup    string              `json:"journal_setup"`
	Steps           []publisherStepJSON `json:"steps"`
}

type statusPublisherFile struct {
	Version      int                     `json:"version"`
	Description  string                  `json:"description"`
	StatusPolicy statusPolicyJSON        `json:"status_policy"`
	Operations   map[string]string       `json:"operations"`
	Scenarios    []publisherScenarioJSON `json:"scenarios"`
}

func (g *gen) statusPublisherFile() any {
	const life = 3600
	t := Now - 7200
	list := func(seq, updated int64, revoked ...string) *publishedListJSON {
		if revoked == nil {
			revoked = []string{}
		}
		return &publishedListJSON{Sequence: seq, UpdatedAt: updated, NextUpdate: updated + life, Revoked: revoked}
	}
	published := func(l *publishedListJSON, p *publishedPushJSON) publisherExpectJSON {
		return publisherExpectJSON{Result: "published", List: l, Push: p}
	}
	refused := publisherExpectJSON{Result: "refused"}
	pub := func(n int) *int { return &n }
	status := func(cert string, at int64, s, reason string) publisherStepJSON {
		return publisherStepJSON{Op: "status", CertID: cert, At: at, Expect: publisherExpectJSON{Status: s, Reason: reason}}
	}
	ingest := func(publication int, object string, at int64) publisherStepJSON {
		return publisherStepJSON{Op: "ingest", Publication: pub(publication), Object: object, At: at, Expect: publisherExpectJSON{Result: "applied"}}
	}
	scenario := func(name, desc string, steps ...publisherStepJSON) publisherScenarioJSON {
		if steps == nil {
			steps = []publisherStepJSON{}
		}
		return publisherScenarioJSON{Name: name, Description: desc, Issuer: "root", StatusKey: "status_root", OtherRoleKeys: []string{"intermediate", "agent"},
			LifetimeSeconds: life, Publisher: "ok", JournalSetup: "configured", Steps: steps}
	}
	f := statusPublisherFile{
		Version:      1,
		Description:  "Minimal signed-status publisher (SPEC-v2 §5.4). A publisher binds an issuer's complete key to a separate status key and produces a genesis full list, same-sequence heartbeats, and revocations as a push plus the cumulative full list at the next sequence. Each produced object MUST verify under the status key with the typed revocation verifiers (codes 0x0003, 0x0005) and is described here by its signed fields; signature bytes may differ because ML-DSA-65 signing may be hedged.",
		StatusPolicy: statusPolicyJSON{MaxListLifetimeSeconds: 7200, MaxStatusAgeSeconds: 7200, ClockSkewSeconds: 5},
		Operations: map[string]string{
			"setup":     "construct the publisher from the issuer key, the status signer and other_role_keys (keys.json names) with lifetime_seconds; publisher ok = constructed, refused = the status key or a component equals the issuer key or another role key, and no object is signed. Then build a SecurityJournalV2: genesis, record the issuer key under role issuer and every other_role_keys entry under role delegation, then configure the status key for the issuer at epoch 1. journal_setup configured = accepted; rejected = the journal refuses the status key (cross-role reuse)",
			"genesis":   "publish the first full list at at. Publications are numbered from 0 in step order",
			"heartbeat": "re-sign the current sequence and revoked set with updated_at = at; refused when at is not later than the last list's updated_at",
			"revoke":    "revoke cert_ids at at: a push with exactly those IDs (sorted) and the cumulative full list, both at the next sequence; refused for an empty, duplicate or already revoked ID",
			"ingest":    "apply the list or push of publication number publication to the journal at now = at under status_policy; the operation succeeds",
			"status":    "derive the status of (issuer, cert_id) from the journal at now = at: not_revoked, revoked, or indeterminate with reason stale or unavailable",
		},
	}
	f.Scenarios = []publisherScenarioJSON{
		scenario("genesis_list", "the genesis list is sequence 1 with an empty revoked set and makes every certificate not_revoked while fresh",
			publisherStepJSON{Op: "genesis", At: t, Expect: published(list(1, t), nil)},
			ingest(0, "list", t+1),
			status("cert-leaf", t+1, "not_revoked", ""),
		),
		scenario("heartbeat_extends_freshness", "a same-sequence heartbeat with a later updated_at keeps status current past the genesis next_update; a heartbeat that does not move forward is refused",
			publisherStepJSON{Op: "genesis", At: t, Expect: published(list(1, t), nil)},
			ingest(0, "list", t+1),
			publisherStepJSON{Op: "heartbeat", At: t + 1800, Expect: published(list(1, t+1800), nil)},
			ingest(1, "list", t+1801),
			status("cert-leaf", t+life+100, "not_revoked", ""),
			publisherStepJSON{Op: "heartbeat", At: t + 1800, Expect: refused},
			publisherStepJSON{Op: "heartbeat", At: t + 1000, Expect: refused},
		),
		scenario("revoked_entry", "a revocation publishes a push and the cumulative list at sequence 2; the revoked certificate is revoked and others stay current",
			publisherStepJSON{Op: "genesis", At: t, Expect: published(list(1, t), nil)},
			ingest(0, "list", t+1),
			publisherStepJSON{Op: "revoke", At: t + 10, CertIDs: []string{"cert-leaf"}, Expect: published(list(2, t+10, "cert-leaf"), &publishedPushJSON{Sequence: 2, PushedAt: t + 10, Revoked: []string{"cert-leaf"}})},
			ingest(1, "push", t+11),
			status("cert-leaf", t+11, "revoked", ""),
			status("cert-root", t+11, "not_revoked", ""),
			ingest(1, "list", t+12),
			status("cert-leaf", t+12, "revoked", ""),
			publisherStepJSON{Op: "revoke", At: t + 20, CertIDs: []string{"cert-leaf"}, Expect: refused},
			publisherStepJSON{Op: "revoke", At: t + 20, CertIDs: []string{}, Expect: refused},
			publisherStepJSON{Op: "revoke", At: t + 20, CertIDs: []string{"cert-a", "cert-a"}, Expect: refused},
		),
		scenario("missing_update", "a verifier that misses sequence 2 and sees the push at sequence 3 has a gap: the pushed certificate is revoked, everything else is unavailable until the sequence 3 list reconciles it",
			publisherStepJSON{Op: "genesis", At: t, Expect: published(list(1, t), nil)},
			ingest(0, "list", t+1),
			publisherStepJSON{Op: "revoke", At: t + 10, CertIDs: []string{"cert-a"}, Expect: published(list(2, t+10, "cert-a"), &publishedPushJSON{Sequence: 2, PushedAt: t + 10, Revoked: []string{"cert-a"}})},
			publisherStepJSON{Op: "revoke", At: t + 20, CertIDs: []string{"cert-b"}, Expect: published(list(3, t+20, "cert-a", "cert-b"), &publishedPushJSON{Sequence: 3, PushedAt: t + 20, Revoked: []string{"cert-b"}})},
			ingest(2, "push", t+21),
			status("cert-b", t+21, "revoked", ""),
			status("cert-a", t+21, "indeterminate", "unavailable"),
			status("cert-leaf", t+21, "indeterminate", "unavailable"),
			ingest(2, "list", t+22),
			status("cert-a", t+22, "revoked", ""),
			status("cert-leaf", t+22, "not_revoked", ""),
		),
		scenario("offline_expiry", "a publisher that stops heartbeating leaves status stale exactly at next_update; a later heartbeat restores current status",
			publisherStepJSON{Op: "genesis", At: t, Expect: published(list(1, t), nil)},
			ingest(0, "list", t+1),
			status("cert-leaf", t+life-1, "not_revoked", ""),
			status("cert-leaf", t+life, "indeterminate", "stale"),
			publisherStepJSON{Op: "heartbeat", At: t + life + 60, Expect: published(list(1, t+life+60), nil)},
			ingest(1, "list", t+life+61),
			status("cert-leaf", t+life+61, "not_revoked", ""),
		),
	}
	reuseIssuer := scenario("status_key_is_issuer_key", "a status key equal to the issuer key is refused by the publisher before any signature, and a verifier journal that recorded the issuer role refuses it too")
	reuseIssuer.StatusKey, reuseIssuer.Publisher, reuseIssuer.JournalSetup = "root", "refused", "rejected"
	reuseOther := scenario("status_key_is_other_role_key", "a status key equal to another configured role key (an intermediate issuer) is refused by the publisher and the journal")
	reuseOther.StatusKey, reuseOther.Publisher, reuseOther.JournalSetup = "intermediate", "refused", "rejected"
	f.Scenarios = append(f.Scenarios, reuseIssuer, reuseOther)
	return f
}
