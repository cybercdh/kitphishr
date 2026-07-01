package sources

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// getPhishuntFeed pulls phishunt.io's live JSON feed (~300 active phishing
// URLs). It's the richest feed we consume: each row carries a pre-labelled
// brand (`company`), host infra (ip/asn/org/country/cert), and cross-source
// detection flags (google/openphish/phishtank/tweetfeed/urlscan). We map all of
// it into SourceIntel — `company`→Brand (a strong SLM brand hint), `org`→ISP,
// and the malicious_* flags→Corroboration count (a confidence/prioritisation
// signal). These are phishing SITE URLs, so normal path-explosion applies.
//
// phishunt is the upstream feeding 0xDanielLopez/phishing_kits — see
// project-0xdaniel-intel-sources. JSON endpoint is feed.json (the /feed/
// HTML page's ?format=json path 404s).
func getPhishuntFeed() ([]PhishUrls, error) {
	const feed = "https://phishunt.io/feed.json"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", feed, nil)
	if err != nil {
		return []PhishUrls{}, err
	}
	req.Header.Set("User-Agent", "kitphishr/1.0")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return []PhishUrls{}, err
	}

	var rows []struct {
		URL          string `json:"url"`
		Company      string `json:"company"`
		FirstSeen    string `json:"first_seen"`
		IP           string `json:"ip"`
		Country      string `json:"country"`
		ASN          string `json:"asn"`
		Org          string `json:"org"`
		Cert         string `json:"cert"`
		MalGoogle    bool   `json:"malicious_google"`
		MalOpenPhish bool   `json:"malicious_openphish"`
		MalPhishTank bool   `json:"malicious_phishtank"`
		MalTweetFeed bool   `json:"malicious_tweetfeed"`
		MalURLScan   bool   `json:"malicious_urlscan"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return []PhishUrls{}, err
	}

	out := make([]PhishUrls, 0, len(rows))
	for _, r := range rows {
		if r.URL == "" {
			continue
		}
		corr := 0
		for _, m := range []bool{r.MalGoogle, r.MalOpenPhish, r.MalPhishTank, r.MalTweetFeed, r.MalURLScan} {
			if m {
				corr++
			}
		}
		out = append(out, PhishUrls{
			URL:    r.URL,
			Source: "phishunt",
			Intel: &SourceIntel{
				Feed:          "phishunt",
				Brand:         r.Company,
				IP:            r.IP,
				ASN:           r.ASN,
				ISP:           r.Org,
				CountryCode:   r.Country,
				Cert:          r.Cert,
				FirstSeen:     r.FirstSeen,
				Corroboration: &corr,
			},
		})
	}
	return out, nil
}
