package tzdbv2

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// The pinned archive is part of the conformance contract: changing it changes
// time_window results and horizons, so it must be a deliberate version bump.
func TestEmbeddedArchiveIsPinned(t *testing.T) {
	sum := sha256.Sum256(Archive())
	if got := hex.EncodeToString(sum[:]); got != ZipSHA256 {
		t.Fatalf("embedded tzdata SHA-256 = %s, want %s (bump Version and the vectors together)", got, ZipSHA256)
	}
}

func TestLoadKnownAndUnknownZones(t *testing.T) {
	ny, err := Load("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-03-08 07:00 UTC is the US spring-forward instant (02:00 EST -> 03:00 EDT).
	before := time.Unix(1772953199, 0).In(ny)
	if _, off := before.Zone(); off != -5*3600 {
		t.Fatalf("offset before transition = %d", off)
	}
	if _, end := before.ZoneBounds(); end.Unix() != 1772953200 {
		t.Fatalf("transition = %d", end.Unix())
	}
	again, _ := Load("America/New_York")
	if again != ny {
		t.Fatal("zone not cached")
	}
	for _, name := range []string{"", "Local", "Mars/Olympus_Mons", "America", "../America/New_York"} {
		if _, err := Load(name); err == nil {
			t.Fatalf("Load(%q) succeeded", name)
		}
	}
}
