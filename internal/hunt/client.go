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
	"syscall"
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
	// -t is the budget for a whole request INCLUDING a large kit download. The
	// connect / handshake / first-byte phases get much tighter caps: a
	// tarpitting host that accepts the socket and then stalls would otherwise
	// hold a worker for the full -t on every one of its generated targets.
	connectTimeout := minDuration(phaseConnectTimeout, timeout)
	dial := (&net.Dialer{Timeout: connectTimeout}).DialContext
	if blockInternal {
		// Swap in the SSRF-guarding dialer. net/http calls DialContext for the
		// initial request and every redirect hop, so this covers redirects too.
		dial = guardedDialContext(connectTimeout)
	}
	tr := &http.Transport{
		Proxy:                 proxyURL,
		TLSHandshakeTimeout:   minDuration(phaseTLSTimeout, timeout),
		ResponseHeaderTimeout: minDuration(phaseHeaderTimeout, timeout),
		MaxConnsPerHost:       50,
		// Default MaxIdleConnsPerHost is 2, so with 50 workers hitting one host
		// most connections were torn down after a single request and every
		// probe paid a fresh TLS handshake. Keep the whole pool reusable.
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
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

// Per-phase timeouts (each capped at -t). Generous for a real server, short
// enough that a host which never answers costs seconds, not -t.
const (
	phaseConnectTimeout = 8 * time.Second
	phaseTLSTimeout     = 8 * time.Second
	phaseHeaderTimeout  = 12 * time.Second
)

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
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
		if Config.OnHostDead != nil {
			Config.OnHostDead(host)
		}
	}
}

// SeedDeadHosts pre-marks hosts found unreachable by a recent run. They are
// skipped like hosts that died this run, but not counted in DeadHostCount
// (which reports what THIS run observed) nor re-reported via OnHostDead.
func SeedDeadHosts(hosts map[string]time.Time) {
	for h := range hosts {
		deadHostSet.Store(h, struct{}{})
	}
}

// ErrRecentlyCaptured is returned for an archive URL that a recent run
// already saved (see Options.SkipURL), so it is not downloaded again.
var ErrRecentlyCaptured = errors.New("archive url captured recently")

func isHostMarkedDead(host string) bool {
	_, ok := deadHostSet.Load(host)
	return ok
}

// hostStrikeLimit is how many consecutive stalls (timeouts, resets before any
// response) a host gets before it is treated as dead for the rest of the run.
// Tarpits and overloaded hosts never produce a dial error, so without this
// they were retried on every generated target.
const hostStrikeLimit = 3

var hostStrikes sync.Map // host -> *atomic.Int32 consecutive stalls

// recordStall counts a request that reached the host but got no response.
func recordStall(host string) {
	v, _ := hostStrikes.LoadOrStore(host, new(atomic.Int32))
	if v.(*atomic.Int32).Add(1) >= hostStrikeLimit {
		markHostDead(host)
	}
}

// recordAlive resets a host's stall count once it answers anything.
func recordAlive(host string) {
	if v, ok := hostStrikes.Load(host); ok {
		v.(*atomic.Int32).Store(0)
	}
}

// noteRequestError classifies a client.Do failure for host-health tracking.
// ctx is the scan context: a failure caused by the whole scan being cancelled
// or timing out says nothing about the host.
func noteRequestError(ctx context.Context, host string, err error) {
	if ctx.Err() != nil {
		return
	}
	if isUnreachableErr(err) {
		markHostDead(host)
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		recordStall(host)
	}
}

// isUnreachableErr reports whether err means "we couldn't reach the host
// at all" — DNS failures, dial timeouts, connection refused. These are
// effectively permanent for the duration of a scan and shouldn't be
// retried per-URL.
func isUnreachableErr(err error) bool {
	if err == nil {
		return false
	}
	// Our own machine running out of sockets/ports/fds under high
	// concurrency also surfaces as a dial error. It says nothing about the
	// host, and treating it as "dead" silently dropped live hosts (and kits).
	if isLocalResourceErr(err) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// Only a definitive "no such host" is permanent. A resolver timeout
		// or SERVFAIL (common when the local resolver is flooded) is not.
		return dnsErr.IsNotFound
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return !opErr.Timeout()
	}
	return false
}

// isLocalResourceErr reports exhaustion of the scanner's own resources:
// ephemeral ports (EADDRINUSE / EADDRNOTAVAIL, Windows WSAEADDRINUSE etc.),
// file descriptors, or socket buffers.
func isLocalResourceErr(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EADDRINUSE, syscall.EADDRNOTAVAIL, syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS:
		return true
	}
	// Winsock codes (WSAEMFILE, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAENOBUFS),
	// which the syscall constants above do not cover on Windows.
	switch uintptr(errno) {
	case 10024, 10048, 10049, 10055:
		return true
	}
	return false
}

// TuneForConcurrency sizes the client's idle-connection pool for the number
// of hosts kept active at once (see TargetOptions.ActiveHosts), so a host's
// keep-alive connection survives between its probes instead of being evicted
// and re-dialled (a new TCP + TLS handshake, and a TIME_WAIT port, per probe).
func TuneForConcurrency(client *http.Client, activeHosts int) {
	tr, ok := client.Transport.(*http.Transport)
	if !ok || activeHosts <= 0 {
		return
	}
	if n := activeHosts * 2; n > tr.MaxIdleConns {
		tr.MaxIdleConns = n
	}
}

// AttemptTarget performs a request against url. For URLs that end in an
// archive extension (any case, query string ignored) it HEADs first to avoid
// downloading large non-archive bodies; if the probe looks archive-shaped it
// then GETs. Per-host rate limiting and retry-with-backoff
// are applied to every network call. If the host has previously been seen
// as unreachable in this run, the call short-circuits with ErrHostDead.
func AttemptTarget(ctx context.Context, client *http.Client, limiter *HostRateLimiter, target sources.PhishUrls) (Response, error) {
	host := hostOf(target.URL)

	if isHostMarkedDead(host) {
		return Response{}, fmt.Errorf("%w: %s", ErrHostDead, host)
	}
	if Config.SkipURL != nil && hasArchiveExtension(target.URL) && Config.SkipURL(target.URL) {
		return Response{}, fmt.Errorf("%w: %s", ErrRecentlyCaptured, target.URL)
	}

	if hasArchiveExtension(target.URL) {
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
		// A connect/handshake/first-byte timeout means the host is stalling;
		// retrying immediately just doubles the wait. Host-strike tracking
		// retires it after a few of these instead.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
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
		noteRequestError(ctx, hostOf(rawURL), err)
		return Response{}, err
	}
	defer httpresp.Body.Close()
	recordAlive(hostOf(rawURL))

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
		noteRequestError(ctx, hostOf(rawURL), err)
		return Response{}, err
	}
	defer httpresp.Body.Close()
	recordAlive(hostOf(rawURL))

	final := finalURL(httpresp, rawURL)
	ct := httpresp.Header.Get("Content-Type")

	// Read only what HandleResponse can use. An archive URL (after redirects)
	// needs the full body; an HTML page is only ever inspected as a possible
	// directory listing, which is small; anything else (a video, an image, a
	// binary served at a guessed path) is never looked at, so don't download it.
	switch {
	case hasArchiveExtension(final):
		// fall through to the full, size-checked read below
	case strings.Contains(strings.ToLower(ct), "html"):
		body, err := io.ReadAll(io.LimitReader(httpresp.Body, maxHTMLBodySize))
		if err != nil {
			return Response{}, err
		}
		return Response{
			StatusCode:    httpresp.StatusCode,
			Body:          body,
			URL:           final,
			ContentLength: httpresp.ContentLength,
			ContentType:   ct,
		}, nil
	default:
		return Response{
			StatusCode:    httpresp.StatusCode,
			URL:           final,
			ContentLength: httpresp.ContentLength,
			ContentType:   ct,
		}, nil
	}

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
