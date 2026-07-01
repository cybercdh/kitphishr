package hunt

import (
	"bufio"
	"context"
	"net/url"
	"os"
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
	if forceFeeds {
		return sources.FetchAll()
	}
	var urls []sources.PhishUrls
	if termutil.Isatty(os.Stdin.Fd()) {
		return sources.FetchAll()
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		urls = append(urls, sources.PhishUrls{URL: sc.Text(), Source: "stdin"})
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
func GenerateTargets(ctx context.Context, urls []sources.PhishUrls, wordlist []string, extensions []string) chan sources.PhishUrls {
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
		add := func(u, source, origin string, intel *sources.SourceIntel) {
			if seen[u] {
				return
			}
			seen[u] = true
			h := hostOf(u)
			if _, exists := hostQueues[h]; !exists {
				hostOrder = append(hostOrder, h)
			}
			hostQueues[h] = append(hostQueues[h], sources.PhishUrls{URL: u, Source: source, Origin: origin, Intel: intel})
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

func sendTarget(ctx context.Context, ch chan<- sources.PhishUrls, t sources.PhishUrls) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- t:
		return true
	}
}
