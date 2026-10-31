// Package tzdbv2 is the pinned IANA time-zone database used by Protocol v2
// time_window evaluation (SPEC-v2 §5.2). Zones are loaded only from the
// embedded zoneinfo.zip, never from the host system or the Go toolchain, so
// every verifier built from this module evaluates the same zone rules.
//
// zoneinfo.zip is the Go-format archive of IANA tzdata release Version
// (copied unchanged from the Go distribution's lib/time/zoneinfo.zip, whose
// update.bash records CODE and DATA 2025c). Its SHA-256 is ZipSHA256.
package tzdbv2

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"sync"
	"time"
)

// Version is the IANA tzdata release of the embedded database.
const Version = "2025c"

// ZipSHA256 is the lowercase hexadecimal SHA-256 of the embedded archive.
const ZipSHA256 = "8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8"

//go:embed zoneinfo.zip
var zoneinfoZip []byte

var (
	indexOnce sync.Once
	index     map[string]*zip.File
	indexErr  error
	cache     sync.Map // zone name -> *time.Location
)

func loadIndex() {
	reader, err := zip.NewReader(bytes.NewReader(zoneinfoZip), int64(len(zoneinfoZip)))
	if err != nil {
		indexErr = fmt.Errorf("embedded tzdata archive is unreadable: %w", err)
		return
	}
	index = make(map[string]*zip.File, len(reader.File))
	for _, f := range reader.File {
		index[f.Name] = f
	}
}

// Load returns the named zone from the embedded database. "Local" and any
// name that is not a zone file in the archive are errors.
func Load(name string) (*time.Location, error) {
	if cached, ok := cache.Load(name); ok {
		return cached.(*time.Location), nil
	}
	indexOnce.Do(loadIndex)
	if indexErr != nil {
		return nil, indexErr
	}
	f, ok := index[name]
	if !ok || name == "" || name == "Local" || f.FileInfo().IsDir() {
		return nil, fmt.Errorf("time zone %q is not in IANA tzdata %s", name, Version)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	if err != nil {
		return nil, err
	}
	loc, err := time.LoadLocationFromTZData(name, data)
	if err != nil {
		return nil, fmt.Errorf("time zone %q in IANA tzdata %s is unreadable: %w", name, Version, err)
	}
	actual, _ := cache.LoadOrStore(name, loc)
	return actual.(*time.Location), nil
}

// Archive returns a copy of the embedded archive bytes.
func Archive() []byte { return bytes.Clone(zoneinfoZip) }
