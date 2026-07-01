package sources

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func getPhishTankURLs() ([]PhishUrls, error) {
	phishfeed := "http://data.phishtank.com/data/online-valid.json"
	apiKey := os.Getenv("PT_API_KEY")
	if apiKey != "" {
		phishfeed = fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json", apiKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", phishfeed, nil)
	if err != nil {
		return []PhishUrls{}, err
	}
	req.Header.Set("User-Agent", "kitphishr/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer resp.Body.Close()

	var urls []PhishUrls
	body, err := io.ReadAll(resp.Body)
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
