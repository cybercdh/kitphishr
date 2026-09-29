package sources

func getPhishingDatabaseLinks() ([]PhishUrls, error) {
	// Phishing.Database's currently-active full-link feed. (The old
	// phishing-links-NEW-today.txt was abandoned in Dec 2025 when the project
	// moved to domain feeds; this ACTIVE set is still maintained.)
	const phishfeed = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE/phishing-links-ACTIVE1.txt"
	return feedLines(phishfeed, "phishing.database")
}
