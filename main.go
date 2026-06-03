package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gookit/color"
)

const (
	defaultUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	MAX_DOWNLOAD_SIZE = 104857600 // 100mb
)

var (
	verbose          bool
	downloadKits     bool
	concurrency      int
	to               int
	defaultOutputDir string
	ua               string
	rps              float64
	burst            int
	wordlistPath     string
	extensionsFlag   string
	progressInterval time.Duration
	idx              *Index

	seenKitURLsMu sync.Mutex
	seenKitURLs   = make(map[string]struct{})

	attemptedCount atomic.Uint64
	foundCount     atomic.Uint64
	savedCount     atomic.Uint64
)

// runProgress prints a one-line stats summary to stderr every interval
// until ctx is cancelled or done is closed. Useful for long unattended
// scans where verbose mode would be noisy. Disabled when interval <= 0.
func runProgress(ctx context.Context, interval time.Duration, start time.Time, done <-chan struct{}) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastAttempted uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			attempted := attemptedCount.Load()
			delta := attempted - lastAttempted
			rate := float64(delta) / interval.Seconds()
			lastAttempted = attempted
			elapsed := time.Since(start).Round(time.Second)
			fmt.Fprintf(os.Stderr, "[%s] scanned=%d found=%d saved=%d dead-hosts=%d | rate=%.1f/s\n",
				elapsed, attempted, foundCount.Load(), savedCount.Load(), deadHostCount.Load(), rate)
		}
	}
}

// claimKitURL atomically marks a kit URL as "we are handling this" and
// returns true if this is the first claim. Used to prevent double-fetching
// when the same kit URL is discoverable via multiple open-dir paths (e.g.
// /uploads and /uploads/ both redirecting to the same listing).
func claimKitURL(u string) bool {
	seenKitURLsMu.Lock()
	defer seenKitURLsMu.Unlock()
	if _, ok := seenKitURLs[u]; ok {
		return false
	}
	seenKitURLs[u] = struct{}{}
	return true
}

// resolveHref converts an href found in an open-dir page into an absolute
// URL relative to the page's URL. Handles relative ("kit.zip"),
// absolute-path ("/files/kit.zip"), and absolute-URL hrefs.
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

func main() {
	// subcommand dispatch — `kitphishr analyze <kit>` routes to the analyzer;
	// anything else (or no args) preserves the existing scan behaviour.
	if len(os.Args) >= 2 && os.Args[1] == "analyze" {
		runAnalyze(os.Args[2:])
		return
	}

	flag.IntVar(&concurrency, "c", 50, "set the concurrency level")
	flag.IntVar(&to, "t", 45, "set the connection timeout in seconds (useful to ensure the download of large files)")
	flag.BoolVar(&verbose, "v", false, "get more info on URL attempts")
	flag.BoolVar(&downloadKits, "d", false, "option to download suspected phishing kits")
	flag.StringVar(&ua, "u", defaultUserAgent, "User-Agent for requests")
	flag.StringVar(&defaultOutputDir, "o", "kits", "directory to save output files")
	flag.Float64Var(&rps, "rps", 10.0, "per-host request rate limit (requests per second; 0 = unlimited)")
	flag.IntVar(&burst, "burst", 20, "per-host burst capacity for the rate limiter")
	flag.StringVar(&wordlistPath, "wordlist", "", "path to a wordlist of common archive filenames, one per line (built-in default if empty; pass /dev/null to disable wordlist guessing)")
	flag.StringVar(&extensionsFlag, "extensions", "zip", "comma-separated list of archive extensions to guess (e.g. zip,tar.gz,rar,7z)")
	flag.DurationVar(&progressInterval, "progress", 30*time.Second, "interval between progress reports to stderr (0 to disable)")
	flag.Parse()

	scanStart := time.Now()
	progressDone := make(chan struct{})

	wordlist, err := LoadWordlist(wordlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load wordlist %q: %s\n", wordlistPath, err)
		os.Exit(1)
	}
	extensions := ParseExtensions(extensionsFlag)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go runProgress(ctx, progressInterval, scanStart, progressDone)

	client := MakeClient(to)
	limiter := newHostRateLimiter(rps, burst)

	if downloadKits {
		if err := os.MkdirAll(defaultOutputDir, os.ModePerm); err != nil {
			fmt.Fprintf(os.Stderr, "There was an error creating the output directory: %s\n", err)
			os.Exit(1)
		}
		indexPath := filepath.Join(defaultOutputDir, "index.jsonl")
		var err error
		idx, err = NewIndex(indexPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open index file for writing: %s\n", err)
			os.Exit(1)
		}
		defer idx.Close()
	}

	targets := make(chan PhishUrls, concurrency)
	responses := make(chan Response, concurrency)
	tosave := make(chan Response, concurrency)

	// fetch workers
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				if ctx.Err() != nil {
					return
				}
				if verbose {
					fmt.Printf("Attempting %s\n", target.URL)
				}
				res, err := AttemptTarget(ctx, client, limiter, target)
				attemptedCount.Add(1)
				if err != nil {
					if verbose && !errors.Is(err, ErrHostDead) {
						color.Red.Printf("error fetching %s: %s\n", target.URL, err)
					}
					continue
				}
				select {
				case <-ctx.Done():
					return
				case responses <- res:
				}
			}
		}()
	}

	// response analyzer workers
	var rg sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for resp := range responses {
				if ctx.Err() != nil {
					return
				}
				handleResponse(ctx, client, limiter, resp, tosave)
			}
		}()
	}

	// save workers
	var sg sync.WaitGroup
	if downloadKits {
		for i := 0; i < 10; i++ {
			sg.Add(1)
			go func() {
				defer sg.Done()
				for resp := range tosave {
					savedPath, dedup, err := resp.SaveResponse(idx, defaultOutputDir)
					if err != nil {
						if verbose {
							color.Red.Printf("error saving %s: %s\n", resp.URL, err)
						}
						continue
					}
					if dedup {
						if verbose {
							color.Yellow.Printf("duplicate of existing kit (%s) -> %s\n", resp.URL, savedPath)
						}
						continue
					}
					savedCount.Add(1)
					if verbose {
						color.Yellow.Printf("Successfully saved %s -> %s\n", resp.URL, savedPath)
					}
				}
			}()
		}
	} else {
		// no-op consumer so the analyzer doesn't block when -d is off
		sg.Add(1)
		go func() {
			defer sg.Done()
			for range tosave {
			}
		}()
	}

	input, err := GetUserInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "There was an error getting URLs from feeds.\n")
		os.Exit(3)
	}

	urls := GenerateTargets(ctx, input, wordlist, extensions)

sendLoop:
	for u := range urls {
		select {
		case <-ctx.Done():
			break sendLoop
		case targets <- u:
		}
	}

	close(targets)
	wg.Wait()
	close(responses)
	rg.Wait()
	close(tosave)
	sg.Wait()

	close(progressDone)
	fmt.Fprintf(os.Stderr, "Done. scanned=%d found=%d saved=%d dead-hosts=%d in %s\n",
		attemptedCount.Load(), foundCount.Load(), savedCount.Load(), deadHostCount.Load(),
		time.Since(scanStart).Round(time.Second))
}

// handleResponse classifies a fetch response: either it's a zip we should
// save, or it's an open-directory page we should walk for zip links.
func handleResponse(ctx context.Context, client *http.Client, limiter *hostRateLimiter, resp Response, tosave chan<- Response) {
	if resp.StatusCode != http.StatusOK {
		return
	}

	if strings.HasSuffix(resp.URL, ".zip") {
		if len(resp.Body) > 0 && resp.ContentLength > 0 && resp.ContentLength < MAX_DOWNLOAD_SIZE && (strings.Contains(strings.ToLower(resp.ContentType), "zip") || strings.Contains(strings.ToLower(resp.ContentType), "octet-stream")) {
			if !claimKitURL(resp.URL) {
				return
			}
			foundCount.Add(1)
			if verbose {
				color.Green.Printf("Zip found from URL folder at %s\n", resp.URL)
			} else {
				fmt.Println(resp.URL)
			}
			if downloadKits {
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
		if !claimKitURL(hurl) {
			continue
		}
		foundCount.Add(1)
		if verbose {
			color.Green.Printf("Zip found from Open Directory at %s\n", hurl)
		} else {
			fmt.Println(hurl)
		}
		if !downloadKits {
			continue
		}
		fetched, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: hurl, Source: resp.Source})
		if err != nil {
			if verbose {
				color.Red.Printf("error downloading %s: %s\n", hurl, err)
			}
			continue
		}
		if len(fetched.Body) == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case tosave <- fetched:
		}
	}
}
