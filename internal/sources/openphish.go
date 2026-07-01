package sources

import (
	"bufio"
	"net/http"
)

func getOpenPhishURLs() ([]PhishUrls, error) {
	phishfeed := "https://openphish.com/feed.txt"
	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	out := make([]PhishUrls, 0)
	for sc.Scan() {
		out = append(out, PhishUrls{URL: sc.Text(), Source: "openphish"})
	}
	return out, nil
}
