// Package sources defines kitphishr's open-source phishing-feed inputs.
//
// Each feed lives in its own file (openphish.go, phishtank.go, …) as an
// unexported fetch function. The exported surface is the declarative Registry
// — one Source entry per feed carrying its provenance tag, homepage, license,
// commercial-safe flag, and enabled state — plus FetchAll, which fans out over
// the enabled feeds. The Registry is the single source of truth: the README's
// sources table is rendered from it (see the RenderMarkdown/README sync test),
// so enabling, disabling, or documenting a feed is a one-line change here.
package sources

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// feedClient is shared by every fetcher. The default http client has no
// timeout, so one stalled feed used to hang FetchAll, and with it the whole
// scan, indefinitely.
var feedClient = &http.Client{Timeout: 60 * time.Second}

const feedUserAgent = "kitphishr/1.0"

// feedGet performs a GET against a feed URL and returns the body reader only
// for a 200. Error pages from a rate limiter or CDN (403/429/5xx) were
// previously parsed line by line as if they were URLs.
func feedGet(url string, accept string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", feedUserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	res, err := feedClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("%s: unexpected status %d", url, res.StatusCode)
	}
	return res.Body, nil
}

// feedLines fetches a newline separated URL feed and tags every non-blank,
// non-comment line with source.
func feedLines(url, source string) ([]PhishUrls, error) {
	body, err := feedGet(url, "")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return parseLines(body, source), nil
}

func parseLines(r io.Reader, source string) []PhishUrls {
	out := make([]PhishUrls, 0)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, PhishUrls{URL: line, Source: source})
	}
	return out
}

// PhishUrls is a single feed URL plus its provenance. It is the unit of work
// that flows feed → target expansion → capture: sources produce it, the hunt
// engine consumes it.
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

// fetchFn pulls the current URL set from one feed, tagging each with its Source.
type fetchFn func() ([]PhishUrls, error)

// Source is one open-source phishing feed, declared once in Registry. The
// metadata fields (Homepage/License/CommercialSafe) document provenance and
// licensing without prose that can drift; Enabled gates whether FetchAll pulls
// from it, so a feed can be turned off without deleting its code.
type Source struct {
	Name           string  // provenance tag recorded on every captured kit, e.g. "tweetfeed"
	Homepage       string  // feed's project/home page, linked from the README
	License        string  // reuse terms, e.g. "CC0-1.0" or "OpenPhish ToS (non-commercial)"
	CommercialSafe bool    // may this feed's URLs be used in a commercial deployment?
	Enabled        bool    // does FetchAll pull from this feed?
	Fetch          fetchFn // the feed's fetcher (see its own file)
}

// Registry is the authoritative list of feeds kitphishr can pull from.
//
// Licensing note: several feeds restrict commercial use of their URL lists
// (CommercialSafe=false). TweetFeed is CC0 1.0 (public domain) and safe to use
// commercially. For a commercial deployment, prefer the CommercialSafe subset.
var Registry = []Source{
	{
		Name:           "phishtank",
		Homepage:       "https://www.phishtank.com/",
		License:        "PhishTank ToS (non-commercial free feed)",
		CommercialSafe: false,
		Enabled:        true,
		Fetch:          getPhishTankURLs,
	},
	{
		Name:           "openphish",
		Homepage:       "https://openphish.com/",
		License:        "OpenPhish ToS (non-commercial free feed)",
		CommercialSafe: false,
		Enabled:        true,
		Fetch:          getOpenPhishURLs,
	},
	{
		Name:           "phishing.database",
		Homepage:       "https://github.com/Phishing-Database/Phishing.Database",
		License:        "See project repo",
		CommercialSafe: false,
		Enabled:        true,
		Fetch:          getPhishingDatabaseLinks,
	},
	{
		Name:           "phishstats",
		Homepage:       "https://phishstats.info/",
		License:        "PhishStats ToS (non-commercial)",
		CommercialSafe: false,
		Enabled:        true,
		Fetch:          getPhishStatsInfo,
	},
	{
		Name:           "phishunt",
		Homepage:       "https://phishunt.io/",
		License:        "phishunt.io ToS",
		CommercialSafe: false,
		Enabled:        true,
		Fetch:          getPhishuntFeed,
	},
	{
		Name:           "tweetfeed",
		Homepage:       "https://github.com/0xDanielLopez/TweetFeed",
		License:        "CC0-1.0",
		CommercialSafe: true,
		Enabled:        true,
		Fetch:          getTweetFeedURLs,
	},
	{
		Name:           "0xdaniel-kits",
		Homepage:       "https://github.com/0xDanielLopez/phishing_kits",
		License:        "Research / OSINT use only",
		CommercialSafe: false,
		Enabled:        true,
		Fetch:          getDanielKitURLs,
	},
}

// Enabled returns the subset of Registry that is currently switched on, in
// declaration order. Used by FetchAll and by the README sources table.
func Enabled() []Source {
	out := make([]Source, 0, len(Registry))
	for _, s := range Registry {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

// ErrAllFeedsFailed is returned by FetchAll when no enabled feed produced a
// result, so the caller can tell "the feeds are down" from "the feeds are empty".
var ErrAllFeedsFailed = errors.New("every enabled feed failed")

// FetchAll pulls the latest phishing URLs from every enabled source
// concurrently. Each source tags its URLs with its own Name so provenance is
// preserved. A feed that errors is reported on stderr and skipped rather than
// failing the whole fetch; only when every feed fails is an error returned.
func FetchAll() ([]PhishUrls, error) {
	enabled := Enabled()

	urls := make(chan PhishUrls)
	out := make([]PhishUrls, 0)

	var wg sync.WaitGroup
	var failMu sync.Mutex
	failed := 0
	for _, s := range enabled {
		wg.Add(1)
		src := s
		go func() {
			defer wg.Done()
			resp, err := src.Fetch()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: feed %s failed: %s\n", src.Name, err)
				failMu.Lock()
				failed++
				failMu.Unlock()
				return
			}
			for _, r := range resp {
				urls <- r
			}
		}()
	}

	go func() {
		wg.Wait()
		close(urls)
	}()

	for u := range urls {
		out = append(out, u)
	}

	if len(enabled) > 0 && failed == len(enabled) {
		return nil, ErrAllFeedsFailed
	}
	return out, nil
}
