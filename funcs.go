package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	termutil "github.com/andrew-d/go-termutil"
	"golang.org/x/time/rate"
)

type PhishUrls struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
	// Origin is the feed URL this target was expanded from (the path-explosion
	// root). Internal only — used to record which feed URLs we actually probed
	// for cross-run scan dedup. Not serialised.
	Origin string `json:"-"`
	// Intel is optional threat-feed metadata about the URL, carried from the
	// feed through to capture.json so the analyzer can use it. nil for feeds
	// that don't expose it. Rides alongside Source.
	Intel *SourceIntel `json:"intel,omitempty"`
}

// SourceIntel is optional threat-feed metadata about the URL a kit was captured
// from. Populated by feeds that expose it (PhishStats, phishunt.io). It flows
// feed → target → Response → IndexRecord → capture.json (provenance, like
// Source), and the analyzer Lambda both feeds the semantic fields
// (title/tags/score/brand) to the SLM and persists the whole block in kit.json.
// All fields optional; a feed fills what it has.
type SourceIntel struct {
	Feed         string   `json:"feed,omitempty"`  // feed that produced this intel
	Score        *float64 `json:"score,omitempty"` // feed's phishing-confidence score
	Title        string   `json:"title,omitempty"` // page <title> (often names the impersonated brand)
	Tags         string   `json:"tags,omitempty"`  // feed-assigned tags
	Brand        string   `json:"brand,omitempty"` // feed-labelled impersonated brand (phishunt `company`)
	IP           string   `json:"ip,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	ISP          string   `json:"isp,omitempty"` // hosting provider / network operator (phishunt `org`)
	CountryCode  string   `json:"country_code,omitempty"`
	Cert         string   `json:"cert,omitempty"` // TLS cert issuer (e.g. "Let's Encrypt")
	AbuseContact string   `json:"abuse_contact,omitempty"`
	FirstSeen    string   `json:"first_seen,omitempty"` // feed's first-seen date for the URL
	// Corroboration counts how many independent sources also flag this URL
	// (phishunt's malicious_{google,openphish,phishtank,tweetfeed,urlscan}).
	// nil when the feed doesn't provide cross-source signals.
	Corroboration *int `json:"corroboration,omitempty"`
}

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

// hasCaptureExtension reports whether a URL ends in an extension we capture
// (query string stripped). Gate for saving a fetched archive.
func hasCaptureExtension(s string) bool {
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

type fetchFn func() ([]PhishUrls, error)

type Response struct {
	StatusCode    int
	Body          []byte
	URL           string
	ContentLength int64
	ContentType   string
	Source        string
	Intel         *SourceIntel
}

type IndexRecord struct {
	Timestamp    string       `json:"ts"`
	URL          string       `json:"url"`
	SHA256       string       `json:"sha256"`
	Size         int          `json:"size"`
	ContentType  string       `json:"content_type,omitempty"`
	Source       string       `json:"source,omitempty"`
	Intel        *SourceIntel `json:"intel,omitempty"`
	SavedPath    string       `json:"saved_path,omitempty"`
	Deduplicated bool         `json:"deduplicated,omitempty"`
}

type Index struct {
	mu     sync.Mutex
	file   *os.File
	hashes map[string]string // sha256 -> saved_path
}

func NewIndex(path string) (*Index, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	idx := &Index{file: f, hashes: make(map[string]string)}
	if err := idx.loadExisting(); err != nil {
		f.Close()
		return nil, err
	}
	return idx, nil
}

func (i *Index) loadExisting() error {
	if _, err := i.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(i.file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec IndexRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.SHA256 != "" && rec.SavedPath != "" && !rec.Deduplicated {
			i.hashes[rec.SHA256] = rec.SavedPath
		}
	}
	if _, err := i.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// SeedHashes pre-populates the dedup map with sha256s known from prior
// runs (typically read from a Lambda-published derived/known-hashes.txt).
// Doesn't overwrite an existing entry (loaded index records win since they
// have the real saved path). The sentinel value identifies these as
// known-from-elsewhere so future readers can distinguish.
const knownHashSentinel = "known-from-prior-run"

func (i *Index) SeedHashes(hashes []string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	added := 0
	for _, h := range hashes {
		if _, ok := i.hashes[h]; ok {
			continue
		}
		i.hashes[h] = knownHashSentinel
		added++
	}
	return added
}

// SeenPath returns the saved path for a previously-recorded sha256, or "" if unseen.
func (i *Index) SeenPath(sha string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hashes[sha]
}

// Record appends a new record to the index. If the record is a fresh save
// (not deduplicated), it also memoises the sha256 -> path mapping so future
// hits dedup against it.
func (i *Index) Record(rec IndexRecord) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := i.file.Write(data); err != nil {
		return err
	}
	if !rec.Deduplicated && rec.SHA256 != "" && rec.SavedPath != "" {
		i.hashes[rec.SHA256] = rec.SavedPath
	}
	return nil
}

func (i *Index) Close() error {
	if i == nil || i.file == nil {
		return nil
	}
	return i.file.Close()
}

// --- per-host rate limiting ---

type hostRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

// newHostRateLimiter builds a per-host token bucket. Passing rps <= 0
// returns an "unlimited" limiter — useful when scanning burner phishing
// infrastructure where the politeness/throughput trade-off doesn't apply.
func newHostRateLimiter(rps float64, burst int) *hostRateLimiter {
	limit := rate.Limit(rps)
	if rps <= 0 {
		limit = rate.Inf
		if burst < 1 {
			burst = 1
		}
	}
	return &hostRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     limit,
		burst:    burst,
	}
}

func (h *hostRateLimiter) limiterFor(host string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l, ok := h.limiters[host]; ok {
		return l
	}
	l := rate.NewLimiter(h.rate, h.burst)
	h.limiters[host] = l
	return l
}

func (h *hostRateLimiter) Wait(ctx context.Context, host string) error {
	if h.rate == rate.Inf {
		return nil // skip the syscall entirely
	}
	return h.limiterFor(host).Wait(ctx)
}

// --- feed fetchers ---

/*
iterate over a list of functions to pull the latest
phishfeed urls from each source. each source tags its
URLs with its name so we can record provenance.
*/
func GetPhishURLsFromManyFeeds() ([]PhishUrls, error) {

	// NOTE on licensing: several of these feeds (PhishTank, OpenPhish free
	// feed, PhishStats) restrict commercial use of their URL lists.
	// TweetFeed is CC0 1.0 (public domain) and safe to use commercially. For
	// a commercial deployment, prefer the commercial-safe subset.
	fetchFns := []fetchFn{
		getPhishTankURLs,
		getOpenPhishURLs,
		getPhishingDatabaseLinks,
		getPhishStatsInfo,
		getPhishuntFeed,
		getTweetFeedURLs,
		getDanielKitURLs,
	}

	phishing_urls := make(chan PhishUrls)
	out := make([]PhishUrls, 0)

	var wg sync.WaitGroup
	for _, fn := range fetchFns {
		wg.Add(1)
		fetch := fn
		go func() {
			defer wg.Done()
			resp, err := fetch()
			if err != nil {
				return
			}
			for _, r := range resp {
				phishing_urls <- r
			}
		}()
	}

	go func() {
		wg.Wait()
		close(phishing_urls)
	}()

	for w := range phishing_urls {
		out = append(out, w)
	}

	return out, nil
}

func getOpenPhishURLs() ([]PhishUrls, error) {
	phishfeed := "https://openphish.com/feed.txt"
	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	out := make([]PhishUrls, 0)
	for sc.Scan() {
		out = append(out, PhishUrls{URL: sc.Text(), Source: "openphish"})
	}
	return out, nil
}

func getPhishTankURLs() ([]PhishUrls, error) {
	phishfeed := "http://data.phishtank.com/data/online-valid.json"
	apiKey := os.Getenv("PT_API_KEY")
	if apiKey != "" {
		phishfeed = fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json", apiKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", phishfeed, nil)
	if err != nil {
		return []PhishUrls{}, err
	}
	req.Header.Set("User-Agent", "kitphishr/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer resp.Body.Close()

	var urls []PhishUrls
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []PhishUrls{}, err
	}
	if err := json.Unmarshal(body, &urls); err != nil {
		return []PhishUrls{}, err
	}
	for i := range urls {
		urls[i].Source = "phishtank"
	}
	return urls, nil
}

func getPhishingDatabaseLinks() ([]PhishUrls, error) {
	// Phishing.Database's currently-active full-link feed. (The old
	// phishing-links-NEW-today.txt was abandoned in Dec 2025 when the project
	// moved to domain feeds; this ACTIVE set is still maintained.)
	phishfeed := "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE/phishing-links-ACTIVE1.txt"
	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	out := make([]PhishUrls, 0)
	for sc.Scan() {
		out = append(out, PhishUrls{URL: sc.Text(), Source: "phishing.database"})
	}
	return out, nil
}

// getPhishStatsInfo pulls the newest phishing URLs from PhishStats' JSON API.
// The old phish_score.csv endpoint is gone (404); the maintained API at
// api.phishstats.info returns JSON, capped at 100 rows/page, newest-first via
// _sort=-id. We page through phishStatsPages to gather a few hundred fresh
// URLs, stopping early on a short page or error. Dedup happens downstream.
func getPhishStatsInfo() ([]PhishUrls, error) {
	const phishStatsPages = 5 // 100 rows/page → up to ~500 newest URLs

	client := &http.Client{Timeout: 30 * time.Second}
	out := make([]PhishUrls, 0)
	for page := 1; page <= phishStatsPages; page++ {
		feed := fmt.Sprintf("https://api.phishstats.info/api/phishing?_size=100&_sort=-id&_p=%d", page)
		req, err := http.NewRequest("GET", feed, nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", "kitphishr/1.0")
		res, err := client.Do(req)
		if err != nil {
			break
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			break
		}
		// The API row is far richer than a bare URL — keep the fields that help
		// the analyzer (title/tags/score for the SLM; ip/asn/isp/abuse_contact
		// as provenance). Nullable fields (score, title, tags) decode to the
		// zero value / nil when the API sends null.
		var rows []struct {
			URL          string   `json:"url"`
			IP           string   `json:"ip"`
			ASN          string   `json:"asn"`
			ISP          string   `json:"isp"`
			CountryCode  string   `json:"countrycode"`
			AbuseContact string   `json:"abuse_contact"`
			Title        string   `json:"title"`
			Tags         string   `json:"tags"`
			Score        *float64 `json:"score"`
			Date         string   `json:"date"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			break
		}
		for _, r := range rows {
			if r.URL == "" {
				continue
			}
			out = append(out, PhishUrls{
				URL:    r.URL,
				Source: "phishstats",
				Intel: &SourceIntel{
					Feed:         "phishstats",
					Score:        r.Score,
					Title:        r.Title,
					Tags:         r.Tags,
					IP:           r.IP,
					ASN:          r.ASN,
					ISP:          r.ISP,
					CountryCode:  r.CountryCode,
					AbuseContact: r.AbuseContact,
					FirstSeen:    r.Date,
				},
			})
		}
		if len(rows) < 100 {
			break // reached the end of the feed
		}
	}
	return out, nil
}

// getPhishuntFeed pulls phishunt.io's live JSON feed (~300 active phishing
// URLs). It's the richest feed we consume: each row carries a pre-labelled
// brand (`company`), host infra (ip/asn/org/country/cert), and cross-source
// detection flags (google/openphish/phishtank/tweetfeed/urlscan). We map all of
// it into SourceIntel — `company`→Brand (a strong SLM brand hint), `org`→ISP,
// and the malicious_* flags→Corroboration count (a confidence/prioritisation
// signal). These are phishing SITE URLs, so normal path-explosion applies.
//
// phishunt is the upstream feeding 0xDanielLopez/phishing_kits — see
// project-0xdaniel-intel-sources. JSON endpoint is feed.json (the /feed/
// HTML page's ?format=json path 404s).
func getPhishuntFeed() ([]PhishUrls, error) {
	const feed = "https://phishunt.io/feed.json"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", feed, nil)
	if err != nil {
		return []PhishUrls{}, err
	}
	req.Header.Set("User-Agent", "kitphishr/1.0")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return []PhishUrls{}, err
	}

	var rows []struct {
		URL          string `json:"url"`
		Company      string `json:"company"`
		FirstSeen    string `json:"first_seen"`
		IP           string `json:"ip"`
		Country      string `json:"country"`
		ASN          string `json:"asn"`
		Org          string `json:"org"`
		Cert         string `json:"cert"`
		MalGoogle    bool   `json:"malicious_google"`
		MalOpenPhish bool   `json:"malicious_openphish"`
		MalPhishTank bool   `json:"malicious_phishtank"`
		MalTweetFeed bool   `json:"malicious_tweetfeed"`
		MalURLScan   bool   `json:"malicious_urlscan"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return []PhishUrls{}, err
	}

	out := make([]PhishUrls, 0, len(rows))
	for _, r := range rows {
		if r.URL == "" {
			continue
		}
		corr := 0
		for _, m := range []bool{r.MalGoogle, r.MalOpenPhish, r.MalPhishTank, r.MalTweetFeed, r.MalURLScan} {
			if m {
				corr++
			}
		}
		out = append(out, PhishUrls{
			URL:    r.URL,
			Source: "phishunt",
			Intel: &SourceIntel{
				Feed:          "phishunt",
				Brand:         r.Company,
				IP:            r.IP,
				ASN:           r.ASN,
				ISP:           r.Org,
				CountryCode:   r.Country,
				Cert:          r.Cert,
				FirstSeen:     r.FirstSeen,
				Corroboration: &corr,
			},
		})
	}
	return out, nil
}

// getDanielKitURLs pulls the direct kit-archive URLs 0xDanielLopez publishes in
// github.com/0xDanielLopez/phishing_kits — one urls.txt per month, listing the
// .zip/.rar archives he captured from phishunt.io. These are EXACT archive
// links (e.g. https://host/root.zip), so kitphishr fetches the still-live ones
// directly instead of having to guess paths. We read the current + previous
// month for gap-free coverage across month boundaries; cross-run dedup skips
// repeats. Many entries will already be dead (he grabbed them days ago) — that
// is expected, and the dead ones are exactly the case for a future
// direct-archive ingest (he keeps the zip even when the URL is gone).
//
// License: the repo is "Research / OSINT use only". We fetch the live kit and
// derive our OWN intelligence (no redistribution of his archives); the
// 0xdaniel-kits source tag keeps the provenance/attribution explicit.
func getDanielKitURLs() ([]PhishUrls, error) {
	out := make([]PhishUrls, 0)
	now := time.Now().UTC()
	y, mo := now.Year(), int(now.Month())
	py, pm := y, mo-1
	if pm == 0 {
		py, pm = y-1, 12
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, m := range [][2]int{{y, mo}, {py, pm}} {
		feed := fmt.Sprintf(
			"https://raw.githubusercontent.com/0xDanielLopez/phishing_kits/master/%04d/%04d%02d/urls.txt",
			m[0], m[0], m[1],
		)
		req, err := http.NewRequest("GET", feed, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "kitphishr/1.0")
		res, err := client.Do(req)
		if err != nil {
			continue
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			continue
		}
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			u := strings.TrimSpace(sc.Text())
			if u != "" {
				out = append(out, PhishUrls{URL: u, Source: "0xdaniel-kits"})
			}
		}
		res.Body.Close()
	}
	return out, nil
}

// getTweetFeedURLs pulls the rolling 7-day CSV from 0xDanielLopez/TweetFeed,
// which scrapes infosec tweets for IOCs. The CSV mixes types (url, domain,
// sha256, ip); we keep url-typed rows tagged #phishing or #scam.
//
// week.csv (not today.csv): today.csv resets at 00:00 UTC, so a scan cadence
// coarser than the reset window drops URLs added in the final pre-midnight
// hours. The rolling week window is gap-free; cross-run dedup absorbs repeats.
//
// License: CC0 1.0 (public domain) — reuse freely, no attribution required.
func getTweetFeedURLs() ([]PhishUrls, error) {
	const feed = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv"
	res, err := http.Get(feed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	return parseTweetFeedCSV(res.Body)
}

// parseTweetFeedCSV is split out so the filtering logic is unit-testable
// without hitting the network. Expected format (6 columns):
//
//	date, user, type, value, tags, tweet_url
//
// We yield only rows where type == "url" and tags contains "phishing".
func parseTweetFeedCSV(r io.Reader) ([]PhishUrls, error) {
	reader := csv.NewReader(r)
	reader.Comma = ','
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	data, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []PhishUrls
	for _, row := range data {
		if len(row) < 5 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(row[2]), "url") {
			continue
		}
		// #phishing or #scam — both are phishing-adjacent kit hosts. Skip
		// #malware/#ransomware (different threat class, not kit archives).
		tags := strings.ToLower(row[4])
		if !strings.Contains(tags, "phishing") && !strings.Contains(tags, "scam") {
			continue
		}
		u := strings.TrimSpace(row[3])
		if u == "" {
			continue
		}
		out = append(out, PhishUrls{URL: u, Source: "tweetfeed"})
	}
	return out, nil
}

/*
get a list of urls either from the user piping into this
program, or fetch the latest phishing urls from the feeds.

If forceFeeds is true, always fetch from feeds regardless of TTY
state. This is the right behaviour for scheduled/containerised runs
where there's no TTY but also no stdin pipe — without it the scanner
would read from an empty stdin and scan nothing.
*/
func GetUserInput(forceFeeds bool) ([]PhishUrls, error) {
	if forceFeeds {
		return GetPhishURLsFromManyFeeds()
	}
	var urls []PhishUrls
	if termutil.Isatty(os.Stdin.Fd()) {
		return GetPhishURLsFromManyFeeds()
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		urls = append(urls, PhishUrls{URL: sc.Text(), Source: "stdin"})
	}
	return urls, nil
}

/*
iterate through the paths of each url to generate a target list,
preserving the source feed annotation on every variant. for each path
prefix we emit the bare URL, a trailing-slash variant (servers often
respond differently to /foo vs /foo/), a ${path}.${ext} guess for each
configured extension, and a ${path-as-dir}/${word}.${ext} wordlist
guess for each (word, ext) pair. e.g. for /foo/bar with wordlist
{kit,panel} and extensions {zip}:

	http://example.com/foo/bar
	http://example.com/foo/bar/
	http://example.com/foo/bar.zip
	http://example.com/foo/bar/kit.zip
	http://example.com/foo/bar/panel.zip
	... (and similarly for /foo and /)
*/
func GenerateTargets(ctx context.Context, urls []PhishUrls, wordlist []string, extensions []string) chan PhishUrls {
	out := make(chan PhishUrls, 128)
	go func() {
		defer close(out)
		seen := make(map[string]bool)

		// Group all variants by host so we can round-robin emission: one
		// URL per host per round. Without this, the producer dumps 80+
		// variants for host A into the buffered targets channel before
		// any URL for host B appears, leaving 50 workers contending for
		// host A's single per-host rate limiter while the other 49 sit
		// idle. Round-robin keeps every host's queue active in parallel.
		hostQueues := make(map[string][]PhishUrls)
		hostOrder := []string{}
		add := func(u, source, origin string, intel *SourceIntel) {
			if seen[u] {
				return
			}
			seen[u] = true
			h := hostOf(u)
			if _, exists := hostQueues[h]; !exists {
				hostOrder = append(hostOrder, h)
			}
			hostQueues[h] = append(hostQueues[h], PhishUrls{URL: u, Source: source, Origin: origin, Intel: intel})
		}

		for _, row := range urls {
			u, err := url.Parse(row.URL)
			if err != nil {
				continue
			}
			paths := strings.Split(u.Path, "/")
			for i := 0; i < len(paths); i++ {
				_path := paths[:len(paths)-i]
				tmp_url := u.Scheme + "://" + u.Host + strings.Join(_path, "/")

				add(tmp_url, row.Source, row.Origin, row.Intel)

				if !strings.HasSuffix(tmp_url, "/") {
					add(tmp_url+"/", row.Source, row.Origin, row.Intel)
				}

				for _, ext := range extensions {
					guess := tmp_url + "." + ext
					if strings.HasSuffix(guess, "/."+ext) || strings.Count(guess, "/") < 3 {
						continue
					}
					add(guess, row.Source, row.Origin, row.Intel)
				}

				dirBase := tmp_url
				if !strings.HasSuffix(dirBase, "/") {
					dirBase += "/"
				}
				if strings.Count(dirBase, "/") < 3 {
					continue
				}
				for _, word := range wordlist {
					for _, ext := range extensions {
						add(dirBase+word+"."+ext, row.Source, row.Origin, row.Intel)
					}
				}
			}
		}

		// Round-robin emit: one URL per host per round until all queues
		// are drained. This maximises parallelism across hosts.
		for {
			anySent := false
			for _, h := range hostOrder {
				q := hostQueues[h]
				if len(q) == 0 {
					continue
				}
				if !sendTarget(ctx, out, q[0]) {
					return
				}
				hostQueues[h] = q[1:]
				anySent = true
			}
			if !anySent {
				return
			}
		}
	}()
	return out
}

func sendTarget(ctx context.Context, ch chan<- PhishUrls, t PhishUrls) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- t:
		return true
	}
}

/*
parse the response to see if we've hit an open dir.
if we have, then look for hrefs that are zips.
*/
func ZipFromDir(resp Response) ([]string, error) {
	var zip_href []string
	data := bytes.NewReader(resp.Body)
	doc, err := goquery.NewDocumentFromReader(data)
	if err != nil {
		return nil, err
	}

	if !looksLikeOpenDir(doc, resp.ContentType) {
		return zip_href, nil
	}

	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		found_href, ok := s.Attr("href")
		if !ok {
			return
		}
		if hasArchiveExtension(found_href) {
			zip_href = append(zip_href, found_href)
		}
	})
	return zip_href, nil
}

// looksLikeOpenDir uses several heuristics to detect autoindex pages from
// Apache, nginx, Caddy, h5ai, FancyIndex, and similar reskins. The classic
// "Index of /" title catches Apache; the others need broader signals.
func looksLikeOpenDir(doc *goquery.Document, contentType string) bool {
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return false
	}
	title := strings.ToLower(doc.Find("title").Text())
	if strings.Contains(title, "index of /") {
		return true
	}
	if strings.Contains(title, "directory listing") {
		return true
	}
	// nginx default autoindex uses a <pre> with a "../" parent link and no body chrome
	hasParentLink := false
	doc.Find("a").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		h, _ := s.Attr("href")
		if h == "../" || h == ".." {
			hasParentLink = true
			return false
		}
		return true
	})
	if hasParentLink && doc.Find("pre").Length() > 0 {
		return true
	}
	// h5ai / FancyIndex tend to expose specific markers
	if doc.Find("#fancyindex").Length() > 0 || doc.Find("#h5ai").Length() > 0 {
		return true
	}
	return false
}

/*
make an http client.
allow redirects, skip ssl warnings, set timeouts.
*/
func MakeClient(timeoutSecs int, blockInternal bool) *http.Client {
	proxyURL := http.ProxyFromEnvironment
	timeout := time.Second * time.Duration(timeoutSecs)
	dial := (&net.Dialer{Timeout: timeout}).DialContext
	if blockInternal {
		// Swap in the SSRF-guarding dialer. net/http calls DialContext for the
		// initial request and every redirect hop, so this covers redirects too.
		dial = guardedDialContext(timeout)
	}
	tr := &http.Transport{
		Proxy:           proxyURL,
		MaxConnsPerHost: 50,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: dial,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

// ErrHostDead is returned when a target's host has already been observed
// as unreachable (NXDOMAIN, refused, dial timeout). Callers can suppress
// log noise by checking errors.Is(err, ErrHostDead) — only the first
// failure per host produces a "real" error worth printing.
var ErrHostDead = errors.New("host previously unreachable")

// deadHostSet tracks hosts that have failed to connect at the network
// level. Subsequent requests to the same host short-circuit. sync.Map's
// zero value is ready to use; no constructor needed.
var (
	deadHostSet   sync.Map
	deadHostCount atomic.Uint64 // distinct dead hosts seen, for progress reports
)

func markHostDead(host string) {
	if _, loaded := deadHostSet.LoadOrStore(host, struct{}{}); !loaded {
		deadHostCount.Add(1)
	}
}
func isHostMarkedDead(host string) bool {
	_, ok := deadHostSet.Load(host)
	return ok
}

// isUnreachableErr reports whether err means "we couldn't reach the host
// at all" — DNS failures, dial timeouts, connection refused. These are
// effectively permanent for the duration of a scan and shouldn't be
// retried per-URL.
func isUnreachableErr(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return false
}

// AttemptTarget performs a request against url. For URLs ending in .zip it
// HEADs first to avoid downloading large non-zip bodies; if the probe looks
// archive-shaped it then GETs. Per-host rate limiting and retry-with-backoff
// are applied to every network call. If the host has previously been seen
// as unreachable in this run, the call short-circuits with ErrHostDead.
func AttemptTarget(ctx context.Context, client *http.Client, limiter *hostRateLimiter, target PhishUrls) (Response, error) {
	host := hostOf(target.URL)

	if isHostMarkedDead(host) {
		return Response{}, fmt.Errorf("%w: %s", ErrHostDead, host)
	}

	if strings.HasSuffix(target.URL, ".zip") {
		if err := limiter.Wait(ctx, host); err != nil {
			return Response{}, err
		}
		probe, err := probeWithRetry(ctx, client, target.URL)
		if err != nil {
			return Response{}, err
		}
		probe.Source = target.Source
		probe.Intel = target.Intel
		if !shouldFetchAfterProbe(probe) {
			return probe, nil
		}
		// archive-shaped or inconclusive — do the GET (bounded + body-validated)
		if err := limiter.Wait(ctx, host); err != nil {
			return Response{}, err
		}
		full, err := fetchWithRetry(ctx, client, target.URL)
		if err != nil {
			return Response{}, err
		}
		full.Source = target.Source
		full.Intel = target.Intel
		return full, nil
	}

	if err := limiter.Wait(ctx, host); err != nil {
		return Response{}, err
	}
	resp, err := fetchWithRetry(ctx, client, target.URL)
	if err != nil {
		return Response{}, err
	}
	resp.Source = target.Source
	resp.Intel = target.Intel
	return resp, nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// archiveContentTypeSignals is a list of substrings that, when present in a
// Content-Type header, indicate the body is (likely) an archive. We match
// liberally rather than exactly because mime registrations vary widely
// across servers (application/zip, application/x-zip-compressed,
// application/x-7z-compressed, application/vnd.rar, application/x-tar, etc).
var archiveContentTypeSignals = []string{
	"zip", "octet-stream", "tar", "gzip", "bzip", "rar", "7z",
}

// shouldFetchAfterProbe decides whether to follow a HEAD probe with a GET. The
// HEAD is a bandwidth optimisation, NOT a capture gate: it exists only to avoid
// downloading an obvious HTML page or an advertised-oversize body. So it must
// fail OPEN — we GET whenever the probe is archive-shaped OR inconclusive.
// Inconclusive covers the cases that silently lost real kits: a non-200 HEAD
// (405 Method Not Allowed, or a redirect hop whose final HEAD is unreliable —
// e.g. http->https kit hosts), a missing Content-Length (chunked), or a
// missing/blank Content-Type. A needless GET costs at most one MAX_DOWNLOAD_SIZE
// download that validArchiveBody then rejects. We skip the GET only on a
// confident disqualification: a 200 HEAD advertising a concrete non-archive
// content type, or an advertised size over the cap.
func shouldFetchAfterProbe(r Response) bool {
	// HEAD blocked but GET often works: WAFs and HEAD-averse PHP hosts answer
	// 403/405 to HEAD yet serve the archive on GET. Worth one bounded GET.
	if r.StatusCode == http.StatusForbidden || r.StatusCode == http.StatusMethodNotAllowed {
		return true
	}
	// Any other non-200 (404/410/5xx, or an unresolved redirect — the client
	// already follows redirects, so a 3xx here is a dead end) is trusted as not
	// fetchable. We skip it so we don't double requests on the many dead feed
	// URLs (a HEAD AND a GET) for no gain.
	if r.StatusCode != http.StatusOK {
		return false
	}
	if r.ContentLength > MAX_DOWNLOAD_SIZE {
		return false // advertised oversize — never storable
	}
	// 200 with no/blank Content-Type is inconclusive — fetch to be sure.
	ct := strings.ToLower(strings.TrimSpace(r.ContentType))
	if ct == "" {
		return true
	}
	for _, sig := range archiveContentTypeSignals {
		if strings.Contains(ct, sig) {
			return true // archive-shaped (covers chunked: Content-Length is irrelevant here)
		}
	}
	return false // 200 with a concrete non-archive type (html/image/…) — skip the GET
}

// validZipBody reports whether body parses as a zip archive containing at
// least one file entry. Status + Content-Type alone aren't trustworthy:
// some hosts (e.g. IPFS gateways) answer every *.zip path with 200 +
// application/zip and a tiny constant error body, which we then catalogued
// as a "kit". Parsing the central directory rejects those, along with HTML
// error pages served as octet-stream and empty (entry-less) archives.
func validZipBody(body []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() {
			return true
		}
	}
	return false
}

// archiveMagics are the leading byte signatures of the non-zip archive families
// captureArchiveExts admits. Zips get the stronger validZipBody parse; for the
// rest a signature match is enough to do validZipBody's job — keep HTML/error
// pages served as application/octet-stream out of the catalogue.
var archiveMagics = [][]byte{
	{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, // RAR ("Rar!\x1a\x07", v4 and v5)
	{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, // 7z  ("7z\xBC\xAF'\x1C")
	{0x1F, 0x8B},                         // gzip (.gz / .tar.gz / .tgz)
}

// validArchiveBody reports whether body is a recognised archive: a parseable
// zip, or a known non-zip signature. Generalises validZipBody across every
// format captureArchiveExts admits, so a .rar/.7z/.tgz with a real archive body
// is saved while a stub/HTML body is still rejected.
func validArchiveBody(body []byte) bool {
	if validZipBody(body) {
		return true
	}
	for _, m := range archiveMagics {
		if len(body) >= len(m) && bytes.Equal(body[:len(m)], m) {
			return true
		}
	}
	return false
}

// retryable categorises errors and status codes that warrant a retry.
func retryable(statusCode int, err error) bool {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		// Permanent network-level failures (NXDOMAIN, connection refused,
		// dial timeout) won't be cured by retrying.
		if isUnreachableErr(err) {
			return false
		}
		// transient network errors (read EOF, connection reset mid-body)
		return true
	}
	if statusCode == 502 || statusCode == 503 || statusCode == 504 {
		return true
	}
	return false
}

const (
	// maxAttempts is total tries (1 initial + retries on transient errors).
	// ffuf-style fail-fast: one retry is enough for transient blips; more
	// just slows the scanner against persistently-broken targets.
	maxAttempts = 2
	// initialBackoff is the first retry delay. Exponential after that.
	initialBackoff = 100 * time.Millisecond
)

func probeWithRetry(ctx context.Context, client *http.Client, rawURL string) (Response, error) {
	var lastErr error
	var lastResp Response
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := probeOnce(ctx, client, rawURL)
		if err == nil && !retryable(resp.StatusCode, nil) {
			return resp, nil
		}
		lastResp = resp
		lastErr = err
		if !retryable(resp.StatusCode, err) {
			return resp, err
		}
		if !backoff(ctx, attempt) {
			return resp, ctx.Err()
		}
	}
	return lastResp, lastErr
}

func fetchWithRetry(ctx context.Context, client *http.Client, rawURL string) (Response, error) {
	var lastErr error
	var lastResp Response
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := fetchOnce(ctx, client, rawURL)
		if err == nil && !retryable(resp.StatusCode, nil) {
			return resp, nil
		}
		lastResp = resp
		lastErr = err
		if !retryable(resp.StatusCode, err) {
			return resp, err
		}
		if !backoff(ctx, attempt) {
			return resp, ctx.Err()
		}
	}
	return lastResp, lastErr
}

func backoff(ctx context.Context, attempt int) bool {
	d := initialBackoff * time.Duration(1<<attempt)
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func probeOnce(ctx context.Context, client *http.Client, rawURL string) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("User-Agent", ua)
	// Keep-alive is left on: we make many requests to the same host and
	// re-using the connection eliminates a TLS handshake per request,
	// which dominates per-request latency for HTTPS targets.

	httpresp, err := client.Do(req)
	if err != nil {
		if isUnreachableErr(err) {
			markHostDead(hostOf(rawURL))
		}
		return Response{}, err
	}
	defer httpresp.Body.Close()

	return Response{
		StatusCode:    httpresp.StatusCode,
		URL:           finalURL(httpresp, rawURL),
		ContentLength: httpresp.ContentLength,
		ContentType:   httpresp.Header.Get("Content-Type"),
	}, nil
}

func fetchOnce(ctx context.Context, client *http.Client, rawURL string) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("User-Agent", ua)
	// Keep-alive on — see probeOnce comment.

	httpresp, err := client.Do(req)
	if err != nil {
		if isUnreachableErr(err) {
			markHostDead(hostOf(rawURL))
		}
		return Response{}, err
	}
	defer httpresp.Body.Close()

	// LimitReader guards against hostile servers that advertise small
	// content-length but stream gigabytes. +1 lets us detect overflow.
	limited := io.LimitReader(httpresp.Body, MAX_DOWNLOAD_SIZE+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return Response{}, err
	}
	if int64(len(body)) > MAX_DOWNLOAD_SIZE {
		return Response{
			StatusCode:    httpresp.StatusCode,
			URL:           finalURL(httpresp, rawURL),
			ContentLength: httpresp.ContentLength,
			ContentType:   httpresp.Header.Get("Content-Type"),
		}, fmt.Errorf("response body exceeded max download size (%d bytes)", MAX_DOWNLOAD_SIZE)
	}

	return Response{
		StatusCode:    httpresp.StatusCode,
		Body:          body,
		URL:           finalURL(httpresp, rawURL),
		ContentLength: httpresp.ContentLength,
		ContentType:   httpresp.Header.Get("Content-Type"),
	}, nil
}

// finalURL returns the URL of the last request after any redirects.
// Falls back to the originally-requested URL if the Response.Request
// isn't populated (e.g. in synthetic test responses).
func finalURL(resp *http.Response, requested string) string {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return requested
	}
	return resp.Request.URL.String()
}

// --- save path ---

var filenameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// extensionFromURL pulls a safe-ish extension off the URL path for naming.
// Recognises compound extensions like .tar.gz so saved filenames are
// useful. Defaults to ".zip" when nothing else is detectable, since this
// code path only fires for things we believe to be archives.
func extensionFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ".zip"
	}
	p := strings.ToLower(u.Path)
	// compound extensions first, so foo.tar.gz -> .tar.gz not .gz
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz"} {
		if strings.HasSuffix(p, ext) {
			return ext
		}
	}
	ext := strings.ToLower(filepath.Ext(u.Path))
	if ext == "" || len(ext) > 8 {
		return ".zip"
	}
	clean := filenameSanitizer.ReplaceAllString(ext, "")
	if clean == "" {
		return ".zip"
	}
	return clean
}

// SaveResponse hashes the body, deduplicates against the index, and writes
// the kit to disk under <outputDir>/<sha256><ext>. Returns the saved path
// and whether the save was a deduplicated hit (no new file written).
func (r Response) SaveResponse(idx *Index, outputDir string) (savedPath string, deduplicated bool, err error) {
	if len(r.Body) < 1 {
		return "", false, errors.New("empty body")
	}

	sum := sha256.Sum256(r.Body)
	sha := hex.EncodeToString(sum[:])

	rec := IndexRecord{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		URL:         r.URL,
		SHA256:      sha,
		Size:        len(r.Body),
		ContentType: r.ContentType,
		Source:      r.Source,
		Intel:       r.Intel,
	}

	if existing := idx.SeenPath(sha); existing != "" {
		rec.SavedPath = existing
		rec.Deduplicated = true
		if err := idx.Record(rec); err != nil {
			return "", true, err
		}
		return existing, true, nil
	}

	ext := extensionFromURL(r.URL)
	target := path.Join(outputDir, sha+ext)

	// guard against the (extremely unlikely) race where two workers compute
	// the same sha simultaneously: O_EXCL means the second one bails.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		if os.IsExist(err) {
			rec.SavedPath = target
			rec.Deduplicated = true
			if err := idx.Record(rec); err != nil {
				return "", true, err
			}
			return target, true, nil
		}
		return "", false, err
	}
	if _, err := f.Write(r.Body); err != nil {
		f.Close()
		return "", false, err
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}

	rec.SavedPath = target
	if err := idx.Record(rec); err != nil {
		return target, false, err
	}
	if emitKitJSON {
		writeKitJSON(rec, target, outputDir)
	}
	if emitCaptureJSON {
		writeCaptureJSON(rec, outputDir)
	}
	return target, false, nil
}

// writeCaptureJSON writes a per-kit <sha>.capture.json next to a freshly-saved
// kit: the capture metadata only, no analysis. A downstream analyzer (the
// per-kit Lambda) joins this with the archive itself to produce the
// <sha>.kit.json the ingestion pipeline consumes — keeping analysis CPU out of
// the scan task. saved_path is reduced to its basename: the local directory is
// meaningless downstream, but the filename tells the analyzer which sibling
// object is the archive. Best-effort — errors are logged, never fatal.
func writeCaptureJSON(rec IndexRecord, outputDir string) {
	rec.SavedPath = path.Base(rec.SavedPath)
	out, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture-json: encode %s: %s\n", rec.SHA256, err)
		return
	}
	capPath := path.Join(outputDir, rec.SHA256+".capture.json")
	if err := os.WriteFile(capPath, out, 0640); err != nil {
		fmt.Fprintf(os.Stderr, "capture-json: write %s: %s\n", capPath, err)
	}
}

// writeKitJSON analyses a freshly-saved kit and writes a per-kit
// <sha>.kit.json next to it: the capture metadata (from the index record)
// merged with the kitphishr-analyze output. This is the at-capture record the
// event-driven ingestion pipeline consumes. Best-effort — errors are logged to
// stderr, never fatal to the scan.
func writeKitJSON(rec IndexRecord, savedPath, outputDir string) {
	ar := AnalyzePath(savedPath, kitJSONBrands)
	b, err := json.Marshal(ar)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: marshal %s: %s\n", rec.SHA256, err)
		return
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: remap %s: %s\n", rec.SHA256, err)
		return
	}
	// the analyser's local path is meaningless downstream; capture metadata wins.
	delete(m, "path")
	m["sha256"] = rec.SHA256
	m["ts"] = rec.Timestamp
	m["url"] = rec.URL
	if rec.Source != "" {
		m["source"] = rec.Source
	}
	if rec.ContentType != "" {
		m["content_type"] = rec.ContentType
	}
	if rec.Size > 0 {
		m["size"] = rec.Size
	}
	out, err := json.Marshal(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: encode %s: %s\n", rec.SHA256, err)
		return
	}
	kitPath := path.Join(outputDir, rec.SHA256+".kit.json")
	if err := os.WriteFile(kitPath, out, 0640); err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: write %s: %s\n", kitPath, err)
	}
}
