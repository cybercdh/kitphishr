package main

import (
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
	"time"

	"github.com/PuerkitoBio/goquery"
	termutil "github.com/andrew-d/go-termutil"
	"golang.org/x/time/rate"
)

type PhishUrls struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
}

type fetchFn func() ([]PhishUrls, error)

type Response struct {
	StatusCode    int
	Body          []byte
	URL           string
	ContentLength int64
	ContentType   string
	Source        string
}

type IndexRecord struct {
	Timestamp    string `json:"ts"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Size         int    `json:"size"`
	ContentType  string `json:"content_type,omitempty"`
	Source       string `json:"source,omitempty"`
	SavedPath    string `json:"saved_path,omitempty"`
	Deduplicated bool   `json:"deduplicated,omitempty"`
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
	rps      float64
	burst    int
}

func newHostRateLimiter(rps float64, burst int) *hostRateLimiter {
	return &hostRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		burst:    burst,
	}
}

func (h *hostRateLimiter) limiterFor(host string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l, ok := h.limiters[host]; ok {
		return l
	}
	l := rate.NewLimiter(rate.Limit(h.rps), h.burst)
	h.limiters[host] = l
	return l
}

func (h *hostRateLimiter) Wait(ctx context.Context, host string) error {
	return h.limiterFor(host).Wait(ctx)
}

// --- feed fetchers ---

/*
iterate over a list of functions to pull the latest
phishfeed urls from each source. each source tags its
URLs with its name so we can record provenance.
*/
func GetPhishURLsFromManyFeeds() ([]PhishUrls, error) {

	fetchFns := []fetchFn{
		getPhishTankURLs,
		getOpenPhishURLs,
		getNewLinksToday,
		getPhishStatsInfo,
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

func getNewLinksToday() ([]PhishUrls, error) {
	phishfeed := "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt"
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

func getPhishStatsInfo() ([]PhishUrls, error) {
	phishfeed := "https://phishstats.info/phish_score.csv"
	out := make([]PhishUrls, 0)
	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	reader := csv.NewReader(res.Body)
	reader.Comma = ','
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	data, err := reader.ReadAll()
	if err != nil {
		return []PhishUrls{}, err
	}
	for _, row := range data {
		if len(row) < 3 {
			continue
		}
		out = append(out, PhishUrls{URL: row[2], Source: "phishstats"})
	}
	return out, nil
}

/*
get a list of urls either from the user piping into this
program, or fetch the latest phishing urls from the feeds.
*/
func GetUserInput() ([]PhishUrls, error) {
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
respond differently to /foo vs /foo/), and a .zip-guess variant. e.g.

	http://example.com/foo/bar
	http://example.com/foo/bar/
	http://example.com/foo/bar.zip
	http://example.com/foo
	http://example.com/foo/
	http://example.com/foo.zip
	http://example.com
	http://example.com/
*/
func GenerateTargets(ctx context.Context, urls []PhishUrls) chan PhishUrls {
	out := make(chan PhishUrls, 1)
	go func() {
		defer close(out)
		seen := make(map[string]bool)
		emit := func(u string, source string) bool {
			if seen[u] {
				return true
			}
			seen[u] = true
			return sendTarget(ctx, out, PhishUrls{URL: u, Source: source})
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

				if !emit(tmp_url, row.Source) {
					return
				}

				// trailing-slash variant — different resource at the HTTP layer
				if !strings.HasSuffix(tmp_url, "/") {
					if !emit(tmp_url+"/", row.Source) {
						return
					}
				}

				// .zip guess (skip nonsensical /.zip and bare-host.zip)
				zipurl := tmp_url + ".zip"
				if strings.HasSuffix(zipurl, "/.zip") || strings.Count(zipurl, "/") < 3 {
					continue
				}
				if !emit(zipurl, row.Source) {
					return
				}
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
		lower := strings.ToLower(found_href)
		if strings.HasSuffix(lower, ".zip") || strings.Contains(lower, ".zip?") {
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
func MakeClient(timeoutSecs int) *http.Client {
	proxyURL := http.ProxyFromEnvironment
	tr := &http.Transport{
		Proxy:           proxyURL,
		MaxConnsPerHost: 50,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: (&net.Dialer{
			Timeout: time.Second * time.Duration(timeoutSecs),
		}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(timeoutSecs),
	}
}

// AttemptTarget performs a request against url. For URLs ending in .zip it
// HEADs first to avoid downloading large non-zip bodies; if the probe looks
// archive-shaped it then GETs. Per-host rate limiting and retry-with-backoff
// are applied to every network call.
func AttemptTarget(ctx context.Context, client *http.Client, limiter *hostRateLimiter, target PhishUrls) (Response, error) {
	host := hostOf(target.URL)

	if strings.HasSuffix(target.URL, ".zip") {
		if err := limiter.Wait(ctx, host); err != nil {
			return Response{}, err
		}
		probe, err := probeWithRetry(ctx, client, target.URL)
		if err != nil {
			return Response{}, err
		}
		probe.Source = target.Source
		if !probeLooksArchiveShaped(probe) {
			return probe, nil
		}
		// looks zippy — do the GET
		if err := limiter.Wait(ctx, host); err != nil {
			return Response{}, err
		}
		full, err := fetchWithRetry(ctx, client, target.URL)
		if err != nil {
			return Response{}, err
		}
		full.Source = target.Source
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
	return resp, nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

func probeLooksArchiveShaped(r Response) bool {
	if r.StatusCode != http.StatusOK {
		return false
	}
	if r.ContentLength <= 0 || r.ContentLength > MAX_DOWNLOAD_SIZE {
		return false
	}
	ct := strings.ToLower(r.ContentType)
	if strings.Contains(ct, "zip") {
		return true
	}
	// many servers serve archives as octet-stream
	if strings.Contains(ct, "application/octet-stream") {
		return true
	}
	if strings.Contains(ct, "application/x-zip") {
		return true
	}
	return false
}

// retryable categorises errors and status codes that warrant a retry.
func retryable(statusCode int, err error) bool {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		// network-level errors (dial timeouts, EOF, connection reset, etc.)
		return true
	}
	if statusCode == 502 || statusCode == 503 || statusCode == 504 {
		return true
	}
	return false
}

const maxAttempts = 3

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
	d := time.Duration(500*(1<<attempt)) * time.Millisecond
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
	req.Header.Set("Connection", "close")
	req.Close = true

	httpresp, err := client.Do(req)
	if err != nil {
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
	req.Header.Set("Connection", "close")
	req.Close = true

	httpresp, err := client.Do(req)
	if err != nil {
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
// Defaults to ".zip" when nothing else is detectable, since this code path
// only fires for things we believe to be archives.
func extensionFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ".zip"
	}
	ext := strings.ToLower(filepath.Ext(u.Path))
	if ext == "" || len(ext) > 8 {
		return ".zip"
	}
	// strip any junk past the dot
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
	return target, false, nil
}
