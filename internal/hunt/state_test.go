package hunt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybercdh/kitphishr/internal/sources"
)

func TestStateLogTTLAndCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-history.jsonl")
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	l, live, err := openStateLog(path, "url", 24*time.Hour, clock)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("fresh log has %d entries", len(live))
	}
	l.Append("http://old.example/a")
	l.Close()

	// 30h later: the entry has expired, a new one is added.
	now = now.Add(30 * time.Hour)
	l, live, err = openStateLog(path, "url", 24*time.Hour, clock)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("expired entry still live: %v", live)
	}
	l.Append("http://new.example/b")
	l.Close()

	now = now.Add(time.Hour)
	l, live, err = openStateLog(path, "url", 24*time.Hour, clock)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, ok := live["http://new.example/b"]; !ok || len(live) != 1 {
		t.Fatalf("live = %v, want only new.example", live)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "old.example") {
		t.Fatalf("expired line not compacted away:\n%s", data)
	}
}

func TestStateLogHostField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dead-hosts.jsonl")
	l, _, err := OpenStateLog(path, "host", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	l.Append("dead.example:443")
	l.Close()
	l, live, err := OpenStateLog(path, "host", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, ok := live["dead.example:443"]; !ok {
		t.Fatalf("host not reloaded: %v", live)
	}
}

func TestNilStateLogIsNoop(t *testing.T) {
	var l *StateLog
	if err := l.Append("x"); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// Every origin completes exactly once after all its targets are Done, including
// an origin whose targets were all claimed by an earlier origin.
func TestTrackedTargetsCompleteEachOriginOnce(t *testing.T) {
	in := []sources.PhishUrls{
		{URL: "http://a.example/x/login.php", Origin: "http://a.example/x/login.php"},
		{URL: "http://a.example/x/", Origin: "http://a.example/x/"}, // fully covered by the first
		{URL: "http://b.example/y", Origin: "http://b.example/y"},
	}
	var mu sync.Mutex
	done := map[string]int{}
	tr := NewOriginTracker(func(o string) { mu.Lock(); done[o]++; mu.Unlock() })

	var targets []sources.PhishUrls
	for tgt := range GenerateTrackedTargets(context.Background(), in, []string{"kit"}, []string{"zip"}, tr, TargetOptions{}) {
		targets = append(targets, tgt)
	}
	mu.Lock()
	if done["http://a.example/x/"] != 1 {
		t.Fatalf("fully-covered origin not completed at seal: %v", done)
	}
	if done["http://a.example/x/login.php"] != 0 {
		t.Fatalf("origin completed before its targets were processed: %v", done)
	}
	mu.Unlock()

	for i, tgt := range targets {
		if i == len(targets)-1 {
			break // hold one back: its origin must stay unfinished
		}
		tr.Done(tgt.Origin)
	}
	last := targets[len(targets)-1].Origin
	mu.Lock()
	if done[last] != 0 {
		t.Fatalf("origin %s completed with a target outstanding", last)
	}
	mu.Unlock()
	tr.Done(last)
	for _, row := range in {
		if done[row.Origin] != 1 {
			t.Fatalf("origin %s completed %d times, want 1 (%v)", row.Origin, done[row.Origin], done)
		}
	}
}

func TestIndexCapturedWithin(t *testing.T) {
	dir := t.TempDir()
	idx, err := NewIndex(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	idx.Record(IndexRecord{Timestamp: time.Now().UTC().Format(time.RFC3339), URL: "http://k.example/kit.zip", SHA256: "aa", SavedPath: "x.zip"})
	idx.Record(IndexRecord{Timestamp: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339), URL: "http://k.example/old.zip", SHA256: "bb", SavedPath: "y.zip"})
	idx.Close()

	// reload from disk
	idx, err = NewIndex(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	if !idx.CapturedWithin("http://k.example/kit.zip", 24*time.Hour) {
		t.Fatal("recent capture not recognised after reload")
	}
	if idx.CapturedWithin("http://k.example/old.zip", 24*time.Hour) {
		t.Fatal("old capture should be eligible for re-download")
	}
}
