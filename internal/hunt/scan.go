package hunt

// Response classification: turn a fetched response into a saved kit or an
// open-directory walk, de-duplicating kit URLs reachable via multiple paths.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/cybercdh/kitphishr/internal/sources"
	"github.com/gookit/color"
)

// Scanner classifies fetched responses and tracks per-run scan state: how many
// kit URLs it has surfaced, and which it has already claimed (so a kit
// discoverable via several open-dir paths is only fetched once).
type Scanner struct {
	client   *http.Client
	limiter  *HostRateLimiter
	verbose  bool
	download bool

	found atomic.Uint64

	claimMu sync.Mutex
	claimed map[string]struct{}
}

// NewScanner builds a Scanner bound to the run's HTTP client and rate limiter.
// verbose mirrors -v; download mirrors -d (whether found kits are queued to
// disk or merely reported).
func NewScanner(client *http.Client, limiter *HostRateLimiter, verbose, download bool) *Scanner {
	return &Scanner{
		client:   client,
		limiter:  limiter,
		verbose:  verbose,
		download: download,
		claimed:  make(map[string]struct{}),
	}
}

// Found reports how many distinct kit URLs the scanner has surfaced this run.
func (s *Scanner) Found() uint64 { return s.found.Load() }

// claim atomically marks a kit URL as "we are handling this" and returns true
// on the first claim. Prevents double-fetching when the same kit URL is
// discoverable via multiple open-dir paths (e.g. /uploads and /uploads/ both
// redirecting to the same listing).
func (s *Scanner) claim(u string) bool {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()
	if _, ok := s.claimed[u]; ok {
		return false
	}
	s.claimed[u] = struct{}{}
	return true
}

// HandleResponse classifies a fetch response: either it's an archive we should
// save, or it's an open-directory page we should walk for archive links.
func (s *Scanner) HandleResponse(ctx context.Context, resp Response, tosave chan<- Response) {
	if resp.StatusCode != http.StatusOK {
		return
	}

	if HasCaptureExtension(resp.URL) {
		// Gate on the BODY, not the headers: ValidArchiveBody is authoritative
		// (parses the zip central directory / matches an archive magic), so a
		// valid kit served chunked (no Content-Length) or with a wrong
		// Content-Type is still saved. Size is bounded by the fetch's
		// MAX_DOWNLOAD_SIZE LimitReader; reject a truncated oversize body.
		if n := len(resp.Body); n > 0 && n <= MAX_DOWNLOAD_SIZE && ValidArchiveBody(resp.Body) {
			if !s.claim(resp.URL) {
				return
			}
			s.found.Add(1)
			if s.verbose {
				color.Green.Printf("Zip found from URL folder at %s\n", resp.URL)
			} else {
				fmt.Println(resp.URL)
			}
			if s.download {
				select {
				case <-ctx.Done():
				case tosave <- resp:
				}
			}
			return
		}
	}

	hrefs, err := ZipFromDir(resp)
	if err != nil {
		return
	}
	for _, href := range hrefs {
		if href == "" {
			continue
		}
		hurl, ok := resolveHref(resp.URL, href)
		if !ok {
			continue
		}
		if !s.claim(hurl) {
			continue
		}
		s.found.Add(1)
		if s.verbose {
			color.Green.Printf("Zip found from Open Directory at %s\n", hurl)
		} else {
			fmt.Println(hurl)
		}
		if !s.download {
			continue
		}
		fetched, err := AttemptTarget(ctx, s.client, s.limiter, sources.PhishUrls{URL: hurl, Source: resp.Source})
		if err != nil {
			if s.verbose {
				color.Red.Printf("error downloading %s: %s\n", hurl, err)
			}
			continue
		}
		if !ValidArchiveBody(fetched.Body) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case tosave <- fetched:
		}
	}
}

// resolveHref converts an href found in an open-dir page into an absolute URL
// relative to the page's URL. Handles relative ("kit.zip"), absolute-path
// ("/files/kit.zip"), and absolute-URL hrefs.
func resolveHref(base, href string) (string, bool) {
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	h, err := url.Parse(href)
	if err != nil {
		return "", false
	}
	return b.ResolveReference(h).String(), true
}
