package analyze

import (
	"regexp"
	"strings"
)

// Author-attribution patterns. Kit authors leave signature strings in
// source comments more often than you'd expect — "// coded by X",
// "// Author: X", PHPDoc @author tags, and legacy contact channels
// (ICQ numbers, Skype handles) embedded in headers.
//
// Patterns are conservative on captured-string length (3-30 chars) and
// strict on the preceding keyword to limit false positives. The
// false-positive filter further drops library attributions (jQuery,
// PHPMailer, etc.) and obvious placeholders.
var (
	codedByPattern     = regexp.MustCompile(`(?i)\b(?:coded|developed|made|written|created|designed)\s+by[:\s]+([a-zA-Z0-9._-]{3,30})`)
	authorTagPattern   = regexp.MustCompile(`(?i)(?:\bauthor\s*[:=]\s*|@author\s+)([a-zA-Z0-9._-]{3,30})`)
	icqHandlePattern   = regexp.MustCompile(`(?i)\bicq[:\s#]*(\d{6,10})\b`)
	skypeHandlePattern = regexp.MustCompile(`(?i)\bskype\s*[:.]\s*([a-zA-Z0-9._-]{3,30})`)
)

// commonAuthorFalsePositives is a deny-list for the "authors" field —
// strings that match our pattern but are virtually always library
// attributions or placeholders, not attacker handles.
var commonAuthorFalsePositives = map[string]bool{
	"jquery":       true,
	"bootstrap":    true,
	"phpmailer":    true,
	"tinymce":      true,
	"ckeditor":     true,
	"google":       true,
	"microsoft":    true,
	"adobe":        true,
	"facebook":     true,
	"twitter":      true,
	"the_author":   true,
	"the-author":   true,
	"this_author":  true,
	"author_name":  true,
	"author":       true,
	"yourname":     true,
	"your_name":    true,
	"someone":      true,
	"anyone":       true,
	"yourself":     true,
	"team":         true,
	"the_team":     true,
	"administrator": true,
	"admin":        true,
	"user":         true,
}

func looksLikeFalsePositiveAuthor(s string) bool {
	return commonAuthorFalsePositives[strings.ToLower(s)]
}

// scanAuthorsInto extracts author / contact indicators from content and
// merges them into the supplied accumulator maps. Empty maps must be
// pre-allocated by the caller. Captures are lower-cased for dedup so
// "Phisher" and "phisher" collapse to one entry.
func scanAuthorsInto(content []byte, authors, icqHandles, skypeHandles map[string]struct{}) {
	addAuthor := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		lower := strings.ToLower(s)
		if looksLikeFalsePositiveAuthor(lower) {
			return
		}
		authors[lower] = struct{}{}
	}
	for _, m := range codedByPattern.FindAllSubmatch(content, -1) {
		if len(m) > 1 {
			addAuthor(string(m[1]))
		}
	}
	for _, m := range authorTagPattern.FindAllSubmatch(content, -1) {
		if len(m) > 1 {
			addAuthor(string(m[1]))
		}
	}
	for _, m := range icqHandlePattern.FindAllSubmatch(content, -1) {
		if len(m) > 1 {
			icqHandles[string(m[1])] = struct{}{}
		}
	}
	for _, m := range skypeHandlePattern.FindAllSubmatch(content, -1) {
		if len(m) > 1 {
			h := strings.ToLower(strings.TrimSpace(string(m[1])))
			if h != "" && !looksLikeFalsePositiveAuthor(h) {
				skypeHandles[h] = struct{}{}
			}
		}
	}
}
