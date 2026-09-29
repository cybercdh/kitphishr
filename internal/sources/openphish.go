package sources

func getOpenPhishURLs() ([]PhishUrls, error) {
	return feedLines("https://openphish.com/feed.txt", "openphish")
}
