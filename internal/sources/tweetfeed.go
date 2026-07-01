package sources

import (
	"encoding/csv"
	"io"
	"net/http"
	"strings"
)

// getTweetFeedURLs pulls the rolling 7-day CSV from 0xDanielLopez/TweetFeed,
// which scrapes infosec tweets for IOCs. The CSV mixes types (url, domain,
// sha256, ip); we keep url-typed rows tagged #phishing or #scam.
//
// week.csv (not today.csv): today.csv resets at 00:00 UTC, so a scan cadence
// coarser than the reset window drops URLs added in the final pre-midnight
// hours. The rolling week window is gap-free; cross-run dedup absorbs repeats.
//
// License: CC0 1.0 (public domain) — reuse freely, no attribution required.
func getTweetFeedURLs() ([]PhishUrls, error) {
	const feed = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv"
	res, err := http.Get(feed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	return parseTweetFeedCSV(res.Body)
}

// parseTweetFeedCSV is split out so the filtering logic is unit-testable
// without hitting the network. Expected format (6 columns):
//
//	date, user, type, value, tags, tweet_url
//
// We yield only rows where type == "url" and tags contains "phishing".
func parseTweetFeedCSV(r io.Reader) ([]PhishUrls, error) {
	reader := csv.NewReader(r)
	reader.Comma = ','
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	data, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []PhishUrls
	for _, row := range data {
		if len(row) < 5 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(row[2]), "url") {
			continue
		}
		// #phishing or #scam — both are phishing-adjacent kit hosts. Skip
		// #malware/#ransomware (different threat class, not kit archives).
		tags := strings.ToLower(row[4])
		if !strings.Contains(tags, "phishing") && !strings.Contains(tags, "scam") {
			continue
		}
		u := strings.TrimSpace(row[3])
		if u == "" {
			continue
		}
		out = append(out, PhishUrls{URL: u, Source: "tweetfeed"})
	}
	return out, nil
}
