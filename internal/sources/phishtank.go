package sources

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func getPhishTankURLs() ([]PhishUrls, error) {
	// https, not http: the feed (and the API key in its path) used to travel in
	// the clear, where an on-path attacker could rewrite the target list.
	phishfeed := "https://data.phishtank.com/data/online-valid.json"
	apiKey := os.Getenv("PT_API_KEY")
	if apiKey != "" {
		phishfeed = fmt.Sprintf("https://data.phishtank.com/data/%s/online-valid.json", apiKey)
	}

	rc, err := feedGet(phishfeed, "application/json")
	if err != nil {
		return []PhishUrls{}, err
	}
	defer rc.Close()

	var urls []PhishUrls
	body, err := io.ReadAll(rc)
	if err != nil {
		return []PhishUrls{}, err
	}
	if err := json.Unmarshal(body, &urls); err != nil {
		return []PhishUrls{}, err
	}
	for i := range urls {
		urls[i].Source = "phishtank"
	}
	return urls, nil
}
