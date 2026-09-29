package sources

import (
	"errors"
	"fmt"
	"time"
)

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
	var errs []error
	for _, m := range [][2]int{{y, mo}, {py, pm}} {
		feed := fmt.Sprintf(
			"https://raw.githubusercontent.com/0xDanielLopez/phishing_kits/master/%04d/%04d%02d/urls.txt",
			m[0], m[0], m[1],
		)
		rows, err := feedLines(feed, "0xdaniel-kits")
		if err != nil {
			// The current month's file may not exist yet early in the month; a
			// 404 for one of the two is normal, so only fail if both are missing.
			errs = append(errs, err)
			continue
		}
		out = append(out, rows...)
	}
	if len(errs) == 2 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}
