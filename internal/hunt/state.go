package hunt

// Cross-run state kept in the output directory so a relaunch carries on
// instead of starting from scratch:
//
//   - scan-history.jsonl: feed URLs whose every generated target was probed,
//     skipped on later runs until they are older than the rescan window.
//   - dead-hosts.jsonl: hosts found unreachable, skipped for a shorter TTL.
//
// Both are append-only JSONL written as events happen (not at exit), so an
// interrupted or crashed run loses at most the work in flight. Expired lines
// are compacted away when the file is next opened.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type stateRecord struct {
	TS  string `json:"ts"`
	Key string `json:"url,omitempty"`
	// Host is used by dead-hosts.jsonl instead of Key.
	Host string `json:"host,omitempty"`
}

func (r stateRecord) key() string {
	if r.Key != "" {
		return r.Key
	}
	return r.Host
}

// StateLog is an append-only, TTL-filtered JSONL set of keys (URLs or hosts).
type StateLog struct {
	mu    sync.Mutex
	file  *os.File
	field string // "url" or "host"
	now   func() time.Time
}

// OpenStateLog loads the entries of path younger than ttl, rewrites the file
// with only those entries (dropping expired lines), and returns the live set
// plus a log open for appending. A missing file is an empty set.
func OpenStateLog(path, field string, ttl time.Duration) (*StateLog, map[string]time.Time, error) {
	return openStateLog(path, field, ttl, time.Now)
}

func openStateLog(path, field string, ttl time.Duration, now func() time.Time) (*StateLog, map[string]time.Time, error) {
	live := make(map[string]time.Time)
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		cutoff := now().Add(-ttl)
		for sc.Scan() {
			var rec stateRecord
			if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.key() == "" {
				continue
			}
			ts, err := time.Parse(time.RFC3339, rec.TS)
			if err != nil || ts.Before(cutoff) {
				continue
			}
			if prev, ok := live[rec.key()]; !ok || ts.After(prev) {
				live[rec.key()] = ts
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}

	// Compact: rewrite only live entries, atomically, so the file does not
	// grow forever across daily runs.
	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return nil, nil, err
	}
	w := bufio.NewWriter(out)
	for k, ts := range live {
		w.Write(encodeState(field, k, ts))
	}
	if err := w.Flush(); err != nil {
		out.Close()
		return nil, nil, err
	}
	if err := out.Close(); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, nil, err
	}
	return &StateLog{file: f, field: field, now: now}, live, nil
}

func encodeState(field, key string, ts time.Time) []byte {
	rec := stateRecord{TS: ts.UTC().Format(time.RFC3339)}
	if field == "host" {
		rec.Host = key
	} else {
		rec.Key = key
	}
	b, _ := json.Marshal(rec)
	return append(b, '\n')
}

// Append records key as of now. One write per line, so lines are never torn
// between concurrent callers. Safe on a nil log (feature disabled).
func (l *StateLog) Append(key string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.file.Write(encodeState(l.field, key, l.now()))
	return err
}

func (l *StateLog) Close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}

// ScanHistoryPath / DeadHostsPath are the state files inside the output dir.
func ScanHistoryPath(outputDir string) string { return filepath.Join(outputDir, "scan-history.jsonl") }
func DeadHostsPath(outputDir string) string   { return filepath.Join(outputDir, "dead-hosts.jsonl") }

// OriginTracker counts the outstanding targets of each feed URL (origin) and
// fires onDone once all of them have been processed. A feed URL is therefore
// only "scanned" when its whole path explosion is done: an interrupted run
// leaves partly-probed URLs unrecorded, and the next run retries them.
type OriginTracker struct {
	mu      sync.Mutex
	pending map[string]int
	onDone  func(origin string)
}

func NewOriginTracker(onDone func(origin string)) *OriginTracker {
	return &OriginTracker{pending: make(map[string]int), onDone: onDone}
}

// register declares an origin (possibly with zero targets of its own).
func (t *OriginTracker) register(origin string) {
	if t == nil || origin == "" {
		return
	}
	t.mu.Lock()
	if _, ok := t.pending[origin]; !ok {
		t.pending[origin] = 0
	}
	t.mu.Unlock()
}

// add counts one more target for origin. Called while targets are generated,
// before any is emitted.
func (t *OriginTracker) add(origin string) {
	if t == nil || origin == "" {
		return
	}
	t.mu.Lock()
	t.pending[origin]++
	t.mu.Unlock()
}

// seal completes origins whose every target was claimed by an earlier origin
// (e.g. a second feed URL on an already-covered path). Called once generation
// finishes.
func (t *OriginTracker) seal() {
	if t == nil {
		return
	}
	t.mu.Lock()
	var done []string
	for o, n := range t.pending {
		if n == 0 {
			done = append(done, o)
			delete(t.pending, o)
		}
	}
	t.mu.Unlock()
	for _, o := range done {
		t.onDone(o)
	}
}

// Done marks one target of origin as fully processed.
func (t *OriginTracker) Done(origin string) {
	if t == nil || origin == "" {
		return
	}
	t.mu.Lock()
	n, ok := t.pending[origin]
	if !ok {
		t.mu.Unlock()
		return
	}
	n--
	if n > 0 {
		t.pending[origin] = n
		t.mu.Unlock()
		return
	}
	delete(t.pending, origin)
	t.mu.Unlock()
	t.onDone(origin)
}
