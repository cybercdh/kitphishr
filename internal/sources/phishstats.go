package sources

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// getPhishStatsInfo pulls the newest phishing URLs from PhishStats' JSON API.
// The old phish_score.csv endpoint is gone (404); the maintained API at
// api.phishstats.info returns JSON, capped at 100 rows/page, newest-first via
// _sort=-id. We page through phishStatsPages to gather a few hundred fresh
// URLs, stopping early on a short page or error. Dedup happens downstream.
func getPhishStatsInfo() ([]PhishUrls, error) {
	const phishStatsPages = 5 // 100 rows/page → up to ~500 newest URLs

	client := &http.Client{Timeout: 30 * time.Second}
	out := make([]PhishUrls, 0)
	for page := 1; page <= phishStatsPages; page++ {
		feed := fmt.Sprintf("https://api.phishstats.info/api/phishing?_size=100&_sort=-id&_p=%d", page)
		req, err := http.NewRequest("GET", feed, nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", "kitphishr/1.0")
		res, err := client.Do(req)
		if err != nil {
			break
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
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
	return out, nil
}
