package hunt

import (
	"bytes"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// Open-directory detection and archive-href extraction.

/*
parse the response to see if we've hit an open dir.
if we have, then look for hrefs that are zips.
*/
func ZipFromDir(resp Response) ([]string, error) {
	var zip_href []string
	data := bytes.NewReader(resp.Body)
	doc, err := goquery.NewDocumentFromReader(data)
	if err != nil {
		return nil, err
	}

	if !looksLikeOpenDir(doc, resp.ContentType) {
		return zip_href, nil
	}

	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		found_href, ok := s.Attr("href")
		if !ok {
			return
		}
		if hasArchiveExtension(found_href) {
			zip_href = append(zip_href, found_href)
		}
	})
	return zip_href, nil
}

// looksLikeOpenDir uses several heuristics to detect autoindex pages from
// Apache, nginx, Caddy, h5ai, FancyIndex, and similar reskins. The classic
// "Index of /" title catches Apache; the others need broader signals.
func looksLikeOpenDir(doc *goquery.Document, contentType string) bool {
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return false
	}
	title := strings.ToLower(doc.Find("title").Text())
	if strings.Contains(title, "index of /") {
		return true
	}
	if strings.Contains(title, "directory listing") {
		return true
	}
	// nginx default autoindex uses a <pre> with a "../" parent link and no body chrome
	hasParentLink := false
	doc.Find("a").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		h, _ := s.Attr("href")
		if h == "../" || h == ".." {
			hasParentLink = true
			return false
		}
		return true
	})
	if hasParentLink && doc.Find("pre").Length() > 0 {
		return true
	}
	// h5ai / FancyIndex tend to expose specific markers
	if doc.Find("#fancyindex").Length() > 0 || doc.Find("#h5ai").Length() > 0 {
		return true
	}
	return false
}
