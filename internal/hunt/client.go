package hunt

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybercdh/kitphishr/internal/sources"
)

// HTTP client, target attempt, probe/fetch with retry, and dead-host short-circuiting.

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
func AttemptTarget(ctx context.Context, client *http.Client, limiter *HostRateLimiter, target sources.PhishUrls) (Response, error) {
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
// download that ValidArchiveBody then rejects. We skip the GET only on a
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

// ValidArchiveBody reports whether body is a recognised archive: a parseable
// zip, or a known non-zip signature. Generalises validZipBody across every
// format captureArchiveExts admits, so a .rar/.7z/.tgz with a real archive body
// is saved while a stub/HTML body is still rejected.
func ValidArchiveBody(body []byte) bool {
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
	req.Header.Set("User-Agent", Config.UserAgent)
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
	req.Header.Set("User-Agent", Config.UserAgent)
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
