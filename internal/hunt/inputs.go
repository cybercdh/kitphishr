package hunt

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Input loading: wordlists, known-hashes, scanned-URL sets, extension parsing, and archive-extension recognition.

// kitArchiveNames is the built-in wordlist of common phishing-kit archive
// names. Used for "${dir}/${name}.${ext}" guess generation when the user
// hasn't supplied their own via -wordlist. Kept short and brand-neutral;
// supply a longer file with -wordlist for targeted hunting.
var kitArchiveNames = []string{
	"kit", "panel", "admin", "mailer", "files", "backup", "upload",
	"update", "script", "config", "data", "login", "new", "html",
	"www", "phish", "scam", "mail",
}

// archiveRecognitionExts is the list of archive extensions kitphishr will
// *recognise* in HTTP responses (open-dir hrefs and HEAD probes). This is
// independent of the user's -extensions guess list: we want to spot a .rar
// in an open dir even if the user only asked us to guess .zip.
var archiveRecognitionExts = []string{
	".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
	".rar", ".7z", ".gz", ".bz2",
}

// hasArchiveExtension reports whether s ends in any extension we treat as
// an archive (after stripping a trailing query string).
func hasArchiveExtension(s string) bool {
	s = strings.ToLower(s)
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}
	for _, ext := range archiveRecognitionExts {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

// captureArchiveExts is the subset of archive types a live scan will SAVE.
// It is narrower than archiveRecognitionExts (which governs what we *spot* in
// open dirs): every entry here must be both routable to a sha-named object by
// extensionFromURL AND wired to the analyzer's S3 trigger — keep in sync with
// the suffix list in kitphishr-infra/lib/ingestion-stack.ts. We deliberately
// omit bz2/xz/tbz2/txz: the analyzer isn't triggered for them, so capturing
// one would leave an un-analysed orphan in the bucket. (.tar.gz is covered by
// the .gz suffix; .gz/.tgz/.rar/.7z get a degraded single-file analysis until
// extraction support lands, which still beats dropping the kit.)
var captureArchiveExts = []string{".zip", ".gz", ".rar", ".7z", ".tgz"}

// HasCaptureExtension reports whether a URL ends in an extension we capture
// (query string stripped). Gate for saving a fetched archive.
func HasCaptureExtension(s string) bool {
	s = strings.ToLower(s)
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}
	for _, ext := range captureArchiveExts {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

// LoadKnownHashes reads a file of sha256 strings, one per line, with '#'
// for comments. Used to seed the in-memory dedup index with hashes
// captured by prior scans (cross-run dedup). Returns nil for empty path.
// Lines that aren't 64-char lowercase hex are silently ignored.
func LoadKnownHashes(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) != 64 {
			continue
		}
		valid := true
		for _, c := range line {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				valid = false
				break
			}
		}
		if valid {
			out = append(out, line)
		}
	}
	return out, nil
}

// LoadScannedURLs reads a file of feed URLs (one per line, '#' for comments,
// blank lines ignored) that were scanned within the cross-run dedup window.
// Matching feed URLs are skipped on this run so we don't re-explode + re-probe
// paths for hosts we already exhausted recently. Returns an empty (non-nil) set
// for an empty path. Feeds return URLs verbatim, so exact-string match is the
// right key (no normalisation).
func LoadScannedURLs(path string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = struct{}{}
	}
	return out, nil
}

// WriteScannedURLs writes the set of feed URLs actually probed this run (one per
// line) so a wrapper can persist them with a TTL for cross-run scan dedup. Only
// URLs we genuinely attempted are recorded: a timed-out run's unprobed tail is
// left out so the next run still reaches it (with the freed budget from skipping
// the already-scanned URLs). No-op for an empty set.
func WriteScannedURLs(path string, scanned map[string]struct{}) error {
	if len(scanned) == 0 {
		return nil
	}
	var b strings.Builder
	for u := range scanned {
		b.WriteString(u)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0640)
}

// ScanStats is the per-run effectiveness record: distinct feed URLs probed per
// source feed, plus run totals. Synced to S3 alongside scanned-urls.txt and
// joined with kits-captured-per-source for the source-effectiveness dashboard.
type ScanStats struct {
	TS           string         `json:"ts"`
	ScannedTotal int            `json:"scanned_total"`
	Found        int            `json:"found"`
	Saved        int            `json:"saved"`
	BySource     map[string]int `json:"by_source"`
}

// WriteScanStats writes the per-run scan-stats.json. bySource maps each source
// feed to the count of distinct feed URLs probed from it this run.
func WriteScanStats(path string, bySource map[string]int, scannedTotal, found, saved int) error {
	if bySource == nil {
		bySource = map[string]int{}
	}
	stats := ScanStats{
		TS:           time.Now().UTC().Format(time.RFC3339),
		ScannedTotal: scannedTotal,
		Found:        found,
		Saved:        saved,
		BySource:     bySource,
	}
	data, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

// LoadWordlist reads a wordlist file (one entry per line, '#' for comments,
// blank lines ignored). An empty path returns the built-in default.
func LoadWordlist(path string) ([]string, error) {
	if path == "" {
		return kitArchiveNames, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	return words, nil
}

// ParseExtensions splits a comma-separated extension list, strips any
// leading dots, and discards empties. Defaults to {"zip"} if everything
// was empty/garbage.
func ParseExtensions(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		e = strings.TrimPrefix(e, ".")
		if e == "" {
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		out = []string{"zip"}
	}
	return out
}
