package sources

import (
	"encoding/json"
	"fmt"
	"io"
)

// getPhishStatsInfo pulls the newest phishing URLs from PhishStats' JSON API.
// The old phish_score.csv endpoint is gone (404); the maintained API at
// api.phishstats.info returns JSON, capped at 100 rows/page, newest-first via
// _sort=-id. We page through phishStatsPages to gather a few hundred fresh
// URLs, stopping early on a short page or error. Dedup happens downstream.
func getPhishStatsInfo() ([]PhishUrls, error) {
	const phishStatsPages = 5 // 100 rows/page → up to ~500 newest URLs

	out := make([]PhishUrls, 0)
	var lastErr error
	for page := 1; page <= phishStatsPages; page++ {
		feed := fmt.Sprintf("https://api.phishstats.info/api/phishing?_size=100&_sort=-id&_p=%d", page)
		rc, err := feedGet(feed, "application/json")
		if err != nil {
			lastErr = err
			break
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			lastErr = err
			break
		}
		// The API row is far richer than a bare URL — keep the fields that help
		// the analyzer (title/tags/score for the SLM; ip/asn/isp/abuse_contact
		// as provenance). Nullable fields (score, title, tags) decode to the
		// zero value / nil when the API sends null.
		var rows []struct {
			URL          string   `json:"url"`
			IP           string   `json:"ip"`
			ASN          string   `json:"asn"`
			ISP          string   `json:"isp"`
			CountryCode  string   `json:"countrycode"`
			AbuseContact string   `json:"abuse_contact"`
			Title        string   `json:"title"`
			Tags         string   `json:"tags"`
			Score        *float64 `json:"score"`
			Date         string   `json:"date"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			lastErr = err
			break
		}
		for _, r := range rows {
			if r.URL == "" {
				continue
			}
			out = append(out, PhishUrls{
				URL:    r.URL,
				Source: "phishstats",
				Intel: &SourceIntel{
					Feed:         "phishstats",
					Score:        r.Score,
					Title:        r.Title,
					Tags:         r.Tags,
					IP:           r.IP,
					ASN:          r.ASN,
					ISP:          r.ISP,
					CountryCode:  r.CountryCode,
					AbuseContact: r.AbuseContact,
					FirstSeen:    r.Date,
				},
			})
		}
		if len(rows) < 100 {
			break // reached the end of the feed
		}
	}
	// A first-page failure means the feed is down; a later-page failure still
	// leaves usable rows, so only surface the error when nothing came back.
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}
