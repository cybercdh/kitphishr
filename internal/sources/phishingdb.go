package sources

import (
	"bufio"
	"net/http"
)

func getPhishingDatabaseLinks() ([]PhishUrls, error) {
	// Phishing.Database's currently-active full-link feed. (The old
	// phishing-links-NEW-today.txt was abandoned in Dec 2025 when the project
	// moved to domain feeds; this ACTIVE set is still maintained.)
	phishfeed := "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE/phishing-links-ACTIVE1.txt"
	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	out := make([]PhishUrls, 0)
	for sc.Scan() {
		out = append(out, PhishUrls{URL: sc.Text(), Source: "phishing.database"})
	}
	return out, nil
}
