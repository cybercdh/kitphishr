package hunt

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/andrew-d/go-termutil"
	"github.com/cybercdh/kitphishr/internal/sources"
)

// Feed/stdin input gathering and path-explosion target generation.

/*
get a list of urls either from the user piping into this
program, or fetch the latest phishing urls from the feeds.

If forceFeeds is true, always fetch from feeds regardless of TTY
state. This is the right behaviour for scheduled/containerised runs
where there's no TTY but also no stdin pipe — without it the scanner
would read from an empty stdin and scan nothing.
*/
func GetUserInput(forceFeeds bool) ([]sources.PhishUrls, error) {
	if forceFeeds || termutil.Isatty(os.Stdin.Fd()) {
		urls, err := sources.FetchAll()
		if err != nil {
			return nil, err
		}
		return normalizeInputs(urls), nil
	}
	var urls []sources.PhishUrls
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		urls = append(urls, sources.PhishUrls{URL: sc.Text(), Source: "stdin"})
	}
	return normalizeInputs(urls), nil
}

// normalizeInputs applies NormalizeURL to every row, dropping the ones that
// cannot become a usable http(s) URL. Feeds and stdin both carry the odd
// blank line, comment, or bare "host/path" entry.
func normalizeInputs(rows []sources.PhishUrls) []sources.PhishUrls {
	out := rows[:0]
	for _, row := range rows {
		u, ok := NormalizeURL(row.URL)
		if !ok {
			continue
		}
		row.URL = u
		out = append(out, row)
	}
	return out
}

// NormalizeURL trims an input line and turns it into an absolute http(s) URL.
// A bare "host/path" entry gets an http:// scheme: a schemeless URL parses
// with an empty host, which made GenerateTargets emit "://host/path" targets
// that every request then rejected, so such lines were silently scanned as
// nothing. Blank lines, comments, and non-http schemes are rejected.
func NormalizeURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	return u.String(), true
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
func GenerateTargets(ctx context.Context, urls []sources.PhishUrls, wordlist []string, extensions []string) chan sources.PhishUrls {
	return GenerateTrackedTargets(ctx, urls, wordlist, extensions, nil, TargetOptions{})
}

// TargetOptions tunes target generation.
type TargetOptions struct {
	// WordlistLevels limits wordlist guessing to the N directories nearest
	// the feed URL (1 = only the directory holding the phishing page).
	// 0 = every directory up to the web root.
	WordlistLevels int
	// ActiveHosts bounds how many hosts are interleaved at once. Each active
	// host gets one target per round; when its queue drains the next host is
	// admitted. Bounding the set keeps each host's keep-alive connection warm
	// between probes (round-robin over tens of thousands of hosts revisits a
	// host only after its idle connection is long gone). 0 = all hosts.
	ActiveHosts int
	// OnPlanned, if set, receives the total number of targets once they are
	// all generated and before the first is emitted (for progress / ETA).
	OnPlanned func(total int)
}

// webFileExts are extensions that mark the LAST segment of a feed URL as a
// file rather than a directory. Probing "<file>/" or "<file>/<word>.zip" is
// pointless: servers answer with the file itself (PATH_INFO) or a 404.
// Deliberately web-file types only, so a directory named like a domain
// ("/secure.paypal.com") is still treated as a directory.
var webFileExts = map[string]bool{
	"php": true, "php5": true, "phtml": true, "html": true, "htm": true, "shtml": true,
	"asp": true, "aspx": true, "jsp": true, "cgi": true, "pl": true, "js": true,
	"css": true, "png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"ico": true, "txt": true, "xml": true, "json": true, "pdf": true,
	"zip": true, "rar": true, "7z": true, "gz": true, "tgz": true,
}

func looksLikeWebFile(segment string) bool {
	i := strings.LastIndexByte(segment, '.')
	if i < 0 || i == len(segment)-1 {
		return false
	}
	return webFileExts[strings.ToLower(segment[i+1:])]
}

// kindPriority orders a host's queue so the likeliest finds go first, which
// matters when a run is cut short by -timeout: the feed URL itself (often a
// direct kit link), then path / trailing-slash probes (which also reveal open
// directories), then ${path}.zip guesses, then wordlist guesses nearest the
// phishing page first.
func kindPriority(kind string) int {
	switch {
	case kind == "feed":
		return 0
	case kind == "path" || kind == "slash":
		return 1
	case strings.HasPrefix(kind, "ext-"):
		return 2
	case strings.HasPrefix(kind, "word-up"):
		n, _ := strconv.Atoi(strings.TrimPrefix(kind, "word-up"))
		return 3 + n
	}
	return 100
}

// GenerateTrackedTargets is GenerateTargets that also tells tracker how many
// targets each origin owns, so the caller can learn when a feed URL has been
// fully explored. A nil tracker disables tracking.
func GenerateTrackedTargets(ctx context.Context, urls []sources.PhishUrls, wordlist []string, extensions []string, tracker *OriginTracker, opts TargetOptions) chan sources.PhishUrls {
	out := make(chan sources.PhishUrls, 128)
	go func() {
		defer close(out)
		seen := make(map[string]bool)

		// Group all variants by host so we can round-robin emission: one
		// URL per host per round. Without this, the producer dumps 80+
		// variants for host A into the buffered targets channel before
		// any URL for host B appears, leaving 50 workers contending for
		// host A's single per-host rate limiter while the other 49 sit
		// idle. Round-robin keeps every host's queue active in parallel.
		hostQueues := make(map[string][]sources.PhishUrls)
		hostOrder := []string{}
		add := func(u, kind string, row sources.PhishUrls) {
			if seen[u] {
				return
			}
			seen[u] = true
			h := hostOf(u)
			if _, exists := hostQueues[h]; !exists {
				hostOrder = append(hostOrder, h)
			}
			hostQueues[h] = append(hostQueues[h], sources.PhishUrls{URL: u, Source: row.Source, Origin: row.Origin, Intel: row.Intel, Kind: kind})
			tracker.add(row.Origin)
		}

		for _, row := range urls {
			tracker.register(row.Origin)
			u, err := url.Parse(row.URL)
			if err != nil {
				continue
			}
			paths := strings.Split(u.Path, "/")
			wordLevel := 0 // directories given wordlist guesses so far, nearest first
			prevDir := ""
			for i := 0; i < len(paths); i++ {
				_path := paths[:len(paths)-i]
				tmp_url := u.Scheme + "://" + u.Host + strings.Join(_path, "/")
				// Only the feed URL's own last segment can be a file; every
				// shorter prefix has a child, so it is a directory.
				isFile := i == 0 && looksLikeWebFile(_path[len(_path)-1])

				kind := "path"
				if i == 0 {
					kind = "feed"
				}
				add(tmp_url, kind, row)

				if !strings.HasSuffix(tmp_url, "/") && !isFile {
					add(tmp_url+"/", "slash", row)
				}

				for _, ext := range extensions {
					guess := tmp_url + "." + ext
					if strings.HasSuffix(guess, "/."+ext) || strings.Count(guess, "/") < 3 {
						continue
					}
					add(guess, "ext-up"+strconv.Itoa(i), row)
				}

				if isFile {
					continue
				}
				dirBase := tmp_url
				if !strings.HasSuffix(dirBase, "/") {
					dirBase += "/"
				}
				// "/a/b/" and its prefix "/a/b" name the same directory.
				if strings.Count(dirBase, "/") < 3 || dirBase == prevDir {
					continue
				}
				prevDir = dirBase
				level := wordLevel
				wordLevel++
				if opts.WordlistLevels > 0 && level >= opts.WordlistLevels {
					continue
				}
				kind = "word-up" + strconv.Itoa(level)
				for _, word := range wordlist {
					for _, ext := range extensions {
						add(dirBase+word+"."+ext, kind, row)
					}
				}
			}
		}

		tracker.seal()

		total := 0
		for _, h := range hostOrder {
			q := hostQueues[h]
			sort.SliceStable(q, func(a, b int) bool { return kindPriority(q[a].Kind) < kindPriority(q[b].Kind) })
			total += len(q)
		}
		if opts.OnPlanned != nil {
			opts.OnPlanned(total)
		}

		// Round-robin emit over a window of active hosts: one URL per host
		// per round, admitting the next host as each one drains. This keeps
		// many hosts in flight in parallel while revisiting each soon enough
		// to reuse its connection.
		window := opts.ActiveHosts
		if window <= 0 || window > len(hostOrder) {
			window = len(hostOrder)
		}
		active := append([]string(nil), hostOrder[:window]...)
		next := window
		for len(active) > 0 {
			kept := active[:0]
			for _, h := range active {
				q := hostQueues[h]
				if !sendTarget(ctx, out, q[0]) {
					return
				}
				if len(q) > 1 {
					hostQueues[h] = q[1:]
					kept = append(kept, h)
					continue
				}
				delete(hostQueues, h) // drained: free it and admit the next host
				if next < len(hostOrder) {
					kept = append(kept, hostOrder[next])
					next++
				}
			}
			active = kept
		}
	}()
	return out
}

func sendTarget(ctx context.Context, ch chan<- sources.PhishUrls, t sources.PhishUrls) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- t:
		return true
	}
}
