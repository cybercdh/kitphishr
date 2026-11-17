package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cybercdh/kitphishr/internal/analyze"
	"github.com/cybercdh/kitphishr/internal/hunt"
	"github.com/cybercdh/kitphishr/internal/sources"
	"github.com/gookit/color"
)

const defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

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
	knownHashesPath  string
	extensionsFlag   string
	progressInterval time.Duration
	scanTimeout      time.Duration
	forceFeeds       bool
	emitKitJSON      bool
	emitCaptureJSON  bool
	blockInternal    bool
	sourceOverride   string
	dumpTargets      bool
	scannedURLsPath  string
	wordlistLevels   int
	rescanAfter      time.Duration
	deadHostTTL      time.Duration
	idx              *hunt.Index

	// scanned records the feed URLs fully explored this run (every generated
	// target processed), keyed by origin. Written to scanned-urls.txt at the
	// end and appended to scan-history.jsonl as each completes, so later runs
	// skip them. probed / sourceScanned count distinct feed URLs we started
	// probing, per source feed, for scan-stats.json.
	scannedMu     sync.Mutex
	scanned       = make(map[string]struct{})
	probed        = make(map[string]struct{})
	sourceScanned = make(map[string]int)

	attemptedCount atomic.Uint64
	plannedTotal   atomic.Int64 // targets generated for this run; 0 until known
	savedCount     atomic.Uint64
)

// dropLines is a log writer that discards lines containing substr and passes
// everything else through. The standard logger writes one line per call.
type dropLines struct {
	w      io.Writer
	substr []byte
}

func (d *dropLines) Write(p []byte) (int, error) {
	if bytes.Contains(p, d.substr) {
		return len(p), nil
	}
	return d.w.Write(p)
}

// runProgress prints a one-line stats summary to stderr every interval
// until ctx is cancelled or done is closed. Useful for long unattended
// scans where verbose mode would be noisy. Disabled when interval <= 0.
func runProgress(ctx context.Context, interval time.Duration, start time.Time, done <-chan struct{}, scanner *hunt.Scanner) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastAttempted uint64
	var smoothed float64 // EWMA of the per-interval rate, for a stable ETA
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			attempted := attemptedCount.Load()
			rate := float64(attempted-lastAttempted) / interval.Seconds()
			lastAttempted = attempted
			total := uint64(plannedTotal.Load())
			if total > 0 && attempted > 0 {
				if smoothed == 0 {
					smoothed = rate
				} else {
					smoothed = progressSmoothing*rate + (1-progressSmoothing)*smoothed
				}
			}
			fmt.Fprintln(os.Stderr, progressLine(time.Since(start), attempted, total, rate, smoothed,
				scanner.Found(), savedCount.Load(), hunt.DeadHostCount()))
		}
	}
}

// progressSmoothing weights the latest interval in the ETA's rate estimate.
// Rate swings a lot (dead hosts short-circuit instantly, slow hosts drag), so
// ~0.3 averages over the last few minutes at the default 30s interval.
const progressSmoothing = 0.3

// progressLine renders one progress report. total is 0 until target
// generation finishes (feeds still downloading / targets being built).
func progressLine(elapsed time.Duration, done, total uint64, rate, smoothed float64, found, saved, dead uint64) string {
	head := fmt.Sprintf("[%s]", elapsed.Round(time.Second))
	tail := fmt.Sprintf("found=%d saved=%d dead-hosts=%d", found, saved, dead)
	if total == 0 {
		return fmt.Sprintf("%s preparing targets (fetching feeds)... | %s", head, tail)
	}
	if done > total {
		done = total // open-dir follow-ups are fetched outside the planned total
	}
	pct := 100 * float64(done) / float64(total)
	eta := "ETA --"
	if smoothed > 0 {
		eta = "ETA " + formatETA(time.Duration(float64(total-done)/smoothed*float64(time.Second)))
	}
	return fmt.Sprintf("%s %d/%d (%.1f%%) | %.0f/s | %s | %s", head, done, total, pct, rate, eta, tail)
}

// formatETA rounds a remaining duration to a readable precision: seconds
// under a minute, minutes under an hour, then hours and minutes.
func formatETA(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	default:
		d = d.Round(time.Minute)
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func main() {
	// subcommand dispatch — `kitphishr analyze <kit>` routes to the analyzer;
	// anything else (or no args) preserves the existing scan behaviour.
	if len(os.Args) >= 2 && os.Args[1] == "analyze" {
		analyze.Run(os.Args[2:])
		return
	}

	// `kitphishr transcode <in.rar|in.7z> <out.zip>` re-emits a rar/7z archive
	// as a zip so the zip-only analyze/SLM path can process it.
	if len(os.Args) >= 2 && os.Args[1] == "transcode" {
		analyze.RunTranscode(os.Args[2:])
		return
	}

	flag.IntVar(&concurrency, "c", 200, "set the concurrency level (parallel requests; hosts are interleaved so each gets few at a time)")
	flag.IntVar(&to, "t", 45, "set the connection timeout in seconds (useful to ensure the download of large files)")
	flag.BoolVar(&verbose, "v", false, "get more info on URL attempts")
	flag.BoolVar(&downloadKits, "d", false, "option to download suspected phishing kits")
	flag.StringVar(&ua, "u", defaultUserAgent, "User-Agent for requests")
	flag.StringVar(&defaultOutputDir, "o", "kits", "directory to save output files")
	flag.Float64Var(&rps, "rps", 10.0, "per-host request rate limit (requests per second; 0 = unlimited)")
	flag.IntVar(&burst, "burst", 20, "per-host burst capacity for the rate limiter")
	flag.StringVar(&wordlistPath, "wordlist", "", "path to a wordlist of common archive filenames, one per line (built-in default if empty; pass /dev/null to disable wordlist guessing)")
	flag.IntVar(&wordlistLevels, "wordlist-levels", 0, "only guess wordlist names in the N directories nearest each feed URL (1 = the phishing page's own directory); 0 = every directory up to the web root. See by_guess in scan-stats.json for which levels actually find kits.")
	flag.StringVar(&extensionsFlag, "extensions", "zip", "comma-separated list of archive extensions to guess (e.g. zip,tar.gz,rar,7z)")
	flag.DurationVar(&progressInterval, "progress", 30*time.Second, "interval between progress reports to stderr (0 to disable)")
	flag.DurationVar(&scanTimeout, "timeout", 0, "max total scan duration (e.g. 30m, 1h); 0 = no limit. Workers drain gracefully when the deadline fires so partial captures survive.")
	flag.BoolVar(&forceFeeds, "feeds", false, "always fetch URLs from the built-in threat-intel feeds (overrides stdin / TTY auto-detection; needed for scheduled / containerised runs)")
	flag.StringVar(&knownHashesPath, "known-hashes", "", "path to a file of sha256 strings (one per line) to pre-seed the dedup index. Captures whose content matches a known sha get a dedup record in index.jsonl but are NOT saved to disk again. Used for cross-run dedup so repeated scans don't re-store the same kit.")
	flag.BoolVar(&emitKitJSON, "kit-json", false, "for each saved kit, also write <sha>.kit.json next to it (capture metadata + analysis) for event-driven ingestion. Requires -d.")
	flag.BoolVar(&emitCaptureJSON, "capture-json", false, "for each saved kit, also write <sha>.capture.json next to it (capture metadata ONLY, no analysis) so analysis can run elsewhere (e.g. an event-driven analyzer). Requires -d.")
	flag.BoolVar(&blockInternal, "block-internal", true, "SSRF guard (ON by default): resolve every target and every redirect hop and refuse to connect to any non-globally-routable address (loopback, RFC1918, link-local/IMDS, CGNAT, etc). Pass -block-internal=false to allow internal targets (e.g. scanning a trusted lab).")
	flag.StringVar(&sourceOverride, "source", "", "override the recorded source label for every captured kit this run (default: the feed name, or \"stdin\"). Used to tag the provenance of on-demand scans, e.g. a user submission.")
	flag.BoolVar(&dumpTargets, "dump-targets", false, "fetch the feed/stdin target URLs, print them to stdout (one per line), and exit WITHOUT scanning. For external dedup/orchestration (e.g. look the URLs up in a store before scanning).")
	flag.DurationVar(&rescanAfter, "rescan-after", 24*time.Hour, "skip feed URLs fully scanned within this window by an earlier run, and don't re-download archive URLs captured within it. History is kept in <output-dir>/scan-history.jsonl. 0 = always scan everything from scratch.")
	flag.DurationVar(&deadHostTTL, "dead-host-ttl", 6*time.Hour, "skip hosts an earlier run found unreachable within this window (kept in <output-dir>/dead-hosts.jsonl). 0 = don't remember dead hosts between runs.")
	flag.StringVar(&scannedURLsPath, "scanned-urls", "", "path to a file of feed URLs (one per line) scanned within the dedup window. Matching feed URLs are skipped (not re-explored/re-probed) this run, and the URLs actually probed are written to <output-dir>/scanned-urls.txt. Used for cross-run scan dedup so we don't re-hammer hosts already exhausted recently.")
	flag.Parse()

	// net/http logs "Unsolicited response received on idle HTTP channel"
	// whenever a server answers a HEAD with a body, or a middlebox injects a
	// block page. Routine on phishing infrastructure and harmless (the
	// connection is discarded), so only show it with -v.
	if !verbose {
		log.SetOutput(&dropLines{w: os.Stderr, substr: []byte("Unsolicited response received on idle HTTP channel")})
	}

	if concurrency < 1 {
		fmt.Fprintf(os.Stderr, "-c must be at least 1 (got %d)\n", concurrency)
		os.Exit(2)
	}
	// Analyzer workers are sized at half the fetch pool. Integer division
	// makes that zero for -c 1, and with no analyzer the responses channel is
	// never drained, so the fetch worker blocks forever. Always run at least one.
	analyzers := concurrency / 2
	if analyzers < 1 {
		analyzers = 1
	}

	// Publish the run-time settings the hunt engine reads while scanning.
	// KitJSONBrands is filled later, once brand signatures are loaded.
	hunt.Config = hunt.Options{
		UserAgent:       ua,
		EmitKitJSON:     emitKitJSON,
		EmitCaptureJSON: emitCaptureJSON,
	}

	scanStart := time.Now()
	progressDone := make(chan struct{})

	wordlist, err := hunt.LoadWordlist(wordlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load wordlist %q: %s\n", wordlistPath, err)
		os.Exit(1)
	}
	extensions := hunt.ParseExtensions(extensionsFlag)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if scanTimeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, scanTimeout)
		defer timeoutCancel()
		// Print a single notice when the deadline fires so the user can
		// distinguish "scan finished naturally" from "scan stopped early".
		go func(deadline time.Duration) {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				fmt.Fprintf(os.Stderr, "scan timeout (%s) reached, draining workers...\n", deadline)
			}
		}(scanTimeout)
	}

	client := hunt.MakeClient(to, blockInternal)
	// Interleave a bounded set of hosts (enough to keep every worker busy
	// under the per-host rate limit) and keep all of their connections warm.
	activeHosts := 4 * concurrency
	hunt.TuneForConcurrency(client, activeHosts)
	limiter := hunt.NewHostRateLimiter(rps, burst)
	scanner := hunt.NewScanner(client, limiter, verbose, downloadKits)

	go runProgress(ctx, progressInterval, scanStart, progressDone, scanner)

	if downloadKits || (!dumpTargets && (rescanAfter > 0 || deadHostTTL > 0)) {
		if err := os.MkdirAll(defaultOutputDir, os.ModePerm); err != nil {
			fmt.Fprintf(os.Stderr, "There was an error creating the output directory: %s\n", err)
			os.Exit(1)
		}
	}

	// Cross-run state: what earlier runs already finished, and which hosts
	// they found dead. Best-effort: a problem here only costs re-scanning.
	var history, deadLog *hunt.StateLog
	var recentlyScanned map[string]time.Time
	if rescanAfter > 0 && !dumpTargets {
		var herr error
		history, recentlyScanned, herr = hunt.OpenStateLog(hunt.ScanHistoryPath(defaultOutputDir), "url", rescanAfter)
		if herr != nil {
			fmt.Fprintf(os.Stderr, "warning: scan history unavailable (%s); scanning everything\n", herr)
		}
		defer history.Close()
	}
	if deadHostTTL > 0 && !dumpTargets {
		var deadHosts map[string]time.Time
		var derr error
		deadLog, deadHosts, derr = hunt.OpenStateLog(hunt.DeadHostsPath(defaultOutputDir), "host", deadHostTTL)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "warning: dead-host memory unavailable (%s)\n", derr)
		} else {
			hunt.SeedDeadHosts(deadHosts)
			if len(deadHosts) > 0 {
				fmt.Fprintf(os.Stderr, "resume: skipping %d hosts found unreachable within %s (-dead-host-ttl 0 to retry them)\n", len(deadHosts), deadHostTTL)
			}
			hunt.Config.OnHostDead = func(h string) { deadLog.Append(h) }
		}
		defer deadLog.Close()
	}

	if downloadKits {
		// Load brand signatures once up front when emitting per-kit JSON, so the
		// on-save analyse path doesn't re-load them for every kit.
		if emitKitJSON {
			b, berr := analyze.LoadBrandSignatures("")
			if berr != nil {
				fmt.Fprintf(os.Stderr, "failed to load brand signatures for -kit-json: %s\n", berr)
				os.Exit(1)
			}
			hunt.Config.KitJSONBrands = b
		}
		indexPath := filepath.Join(defaultOutputDir, "index.jsonl")
		var err error
		idx, err = hunt.NewIndex(indexPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open index file for writing: %s\n", err)
			os.Exit(1)
		}
		defer idx.Close()

		// Pre-seed dedup index with sha256s from prior runs, if supplied.
		// Errors here are non-fatal — worst case we re-capture some kits.
		if knownHashesPath != "" {
			known, kerr := hunt.LoadKnownHashes(knownHashesPath)
			if kerr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to load known-hashes %q: %s\n", knownHashesPath, kerr)
			} else if len(known) > 0 {
				added := idx.SeedHashes(known)
				fmt.Fprintf(os.Stderr, "seeded %d known sha256s for cross-run dedup (%d in file)\n", added, len(known))
			}
		}
		if rescanAfter > 0 {
			hunt.Config.SkipURL = func(u string) bool { return idx.CapturedWithin(u, rescanAfter) }
		}
	}

	// A feed URL counts as scanned only once every target it generated has
	// been processed; it is then recorded immediately (crash-safe). Work cut
	// short by Ctrl-C or -timeout is never marked done, so it is retried.
	tracker := hunt.NewOriginTracker(func(origin string) {
		scannedMu.Lock()
		scanned[origin] = struct{}{}
		scannedMu.Unlock()
		if err := history.Append(origin); err != nil && verbose {
			fmt.Fprintf(os.Stderr, "warning: could not record scan history: %s\n", err)
		}
	})

	targets := make(chan sources.PhishUrls, concurrency)
	responses := make(chan hunt.Response, concurrency)
	tosave := make(chan hunt.Response, concurrency)

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
				// Record the feed URL as scanned the moment we commit to probing
				// one of its targets — so even a dead/empty result counts (we
				// looked) and a timed-out tail we never reached does not.
				if target.Origin != "" {
					scannedMu.Lock()
					if _, exists := probed[target.Origin]; !exists {
						probed[target.Origin] = struct{}{}
						sourceScanned[target.Source]++
					}
					scannedMu.Unlock()
				}
				if verbose {
					fmt.Printf("Attempting %s\n", target.URL)
				}
				res, err := hunt.AttemptTarget(ctx, client, limiter, target)
				attemptedCount.Add(1)
				if !errors.Is(err, hunt.ErrHostDead) && !errors.Is(err, hunt.ErrRecentlyCaptured) {
					scanner.Guesses.Probe(target.Kind)
				}
				if err != nil {
					if verbose && !errors.Is(err, hunt.ErrHostDead) && !errors.Is(err, hunt.ErrRecentlyCaptured) {
						color.Red.Printf("error fetching %s: %s\n", target.URL, err)
					}
					if ctx.Err() == nil {
						tracker.Done(target.Origin)
					}
					continue
				}
				res.Origin = target.Origin
				res.Kind = target.Kind
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
	for i := 0; i < analyzers; i++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for resp := range responses {
				if ctx.Err() != nil {
					return
				}
				scanner.HandleResponse(ctx, resp, tosave)
				// If the run was cancelled mid-handling, an open-dir walk may
				// have been cut short: leave the origin unfinished.
				if ctx.Err() == nil {
					tracker.Done(resp.Origin)
				}
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

	input, err := hunt.GetUserInput(forceFeeds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "There was an error getting URLs from feeds.\n")
		os.Exit(3)
	}

	// -source overrides the per-URL feed/stdin annotation so on-demand scans can
	// record their provenance (e.g. a user submission) instead of "stdin".
	if sourceOverride != "" {
		for i := range input {
			input[i].Source = sourceOverride
		}
	}

	// -dump-targets: print the acquired target URLs and exit. Lets an external
	// orchestrator dedup against its own store (e.g. a DynamoDB lookup keyed by
	// these URLs) before deciding what to actually scan — without re-implementing
	// feed parsing. No scan, no output dir, no network probing.
	if dumpTargets {
		w := bufio.NewWriter(os.Stdout)
		for _, row := range input {
			fmt.Fprintln(w, row.URL)
		}
		w.Flush()
		os.Exit(0)
	}

	// Cross-run scan dedup: drop feed URLs scanned within the dedup window, and
	// tag every kept URL with its origin so the workers can record what we
	// actually probe. Filtering here skips the whole path-explosion for already-
	// scanned URLs — the expensive part — not just the capture.
	skipSet, err := hunt.LoadScannedURLs(scannedURLsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load -scanned-urls %q: %s (scanning all)\n", scannedURLsPath, err)
	}
	for u := range recentlyScanned {
		skipSet[u] = struct{}{}
	}
	kept := input[:0]
	skipped := 0
	for _, row := range input {
		if _, seen := skipSet[row.URL]; seen {
			skipped++
			continue
		}
		row.Origin = row.URL
		kept = append(kept, row)
	}
	input = kept
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "resume: skipped %d/%d feed URLs already scanned recently; scanning %d (-rescan-after 0 to scan all)\n",
			skipped, skipped+len(input), len(input))
	}

	urls := hunt.GenerateTrackedTargets(ctx, input, wordlist, extensions, tracker, hunt.TargetOptions{
		WordlistLevels: wordlistLevels,
		ActiveHosts:    activeHosts,
		OnPlanned:      func(n int) { plannedTotal.Store(int64(n)) },
	})

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

	// Persist the feed URLs we actually probed for cross-run scan dedup. The
	// wrapper picks this up and records them with a TTL so the next run skips
	// them. Best-effort: a write failure must not fail the scan.
	if downloadKits {
		scannedMu.Lock()
		n := len(scanned)
		err := hunt.WriteScannedURLs(filepath.Join(defaultOutputDir, "scanned-urls.txt"), scanned)
		scannedMu.Unlock()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write scanned-urls.txt: %s\n", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "scan-dedup: recorded %d probed feed URLs to scanned-urls.txt\n", n)
		}

		// Per-source effectiveness stats — distinct feed URLs probed per source,
		// plus run totals. Joined downstream with kits-captured-per-source for the
		// CloudWatch source-effectiveness dashboard. Best-effort.
		scannedMu.Lock()
		bySource := make(map[string]int, len(sourceScanned))
		for s, c := range sourceScanned {
			bySource[s] = c
		}
		scannedMu.Unlock()
		if err := hunt.WriteScanStats(filepath.Join(defaultOutputDir, "scan-stats.json"),
			bySource, scanner.Guesses.Snapshot(), int(attemptedCount.Load()), int(scanner.Found()), int(savedCount.Load()),
			int(hunt.DeadHostCount())); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write scan-stats.json: %s\n", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Done. scanned=%d found=%d saved=%d dead-hosts=%d in %s\n",
		attemptedCount.Load(), scanner.Found(), savedCount.Load(), hunt.DeadHostCount(),
		time.Since(scanStart).Round(time.Second))
}
