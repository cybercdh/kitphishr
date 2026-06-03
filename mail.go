package main

import (
	"regexp"
	"strings"
)

// Mail-drop extraction. Phishing kits typically have one or more
// mail() / wp_mail() / mb_send_mail() callsites whose first argument
// is the attacker's exfil mailbox. Extracting that recipient is much
// more valuable than the existing "any email in any file" emails field,
// which catches author signatures, library headers, and victim addresses
// shown in templates as well.
//
// Two patterns we resolve today:
//
//   1. Literal: mail("drop@attacker.ru", ...)
//   2. Assigned-then-passed: $to = "drop@attacker.ru"; mail($to, ...)
//
// What's deliberately out of scope for now:
//   - base64_decode / str_rot13 / chr() obfuscation of the recipient
//   - String concatenation ($to = $brand . "@" . $domain)
//   - Cross-file variable tracing (assignment in include.php, mail() in send.php)
//
// These cover most cases worth covering with regex; deeper indirection
// needs a real PHP parser, which is its own feature.
var (
	mailCallPattern = regexp.MustCompile(
		`(?i)(?:^|[^a-zA-Z0-9_$])@?(?:mb_send_mail|wp_mail|mail)\s*\(\s*([^,)]+?)\s*,`)
	strictEmailPattern = regexp.MustCompile(
		`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$`)
)

// scanMailDropsInto finds confirmed mail-exfil recipients in content
// and adds them to drops. Variable references are resolved against
// assignments in the same content (per-file scope).
func scanMailDropsInto(content []byte, drops map[string]struct{}) {
	for _, m := range mailCallPattern.FindAllSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		arg := strings.TrimSpace(string(m[1]))
		if arg == "" {
			continue
		}

		// Case 1: literal string argument.
		if val, ok := parseStringLiteral(arg); ok {
			addIfMailDrop(val, drops)
			continue
		}

		// Case 2: variable reference — resolve against same-file assignments.
		if strings.HasPrefix(arg, "$") {
			varName := variableHead(arg)
			if varName == "" {
				continue
			}
			for _, val := range findAssignments(content, varName) {
				addIfMailDrop(val, drops)
			}
		}
	}
}

// addIfMailDrop normalises and adds a candidate to drops if it looks
// like a non-placeholder email address.
func addIfMailDrop(val string, drops map[string]struct{}) {
	val = strings.ToLower(strings.TrimSpace(val))
	if val == "" {
		return
	}
	if !strictEmailPattern.MatchString(val) {
		return
	}
	if looksLikePlaceholderEmail(val) {
		return
	}
	drops[val] = struct{}{}
}

// parseStringLiteral extracts the contents of a "..." or '...' literal.
// Returns ("", false) for anything else (variables, expressions, etc.).
func parseStringLiteral(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return "", false
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return s[1 : len(s)-1], true
	}
	return "", false
}

// variableHead returns the bare variable name from something like "$to"
// or "$to[0]" or "$config['drop']" — stripping array index or method
// access so we can search for the assignment by its plain name.
func variableHead(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "$") {
		return ""
	}
	end := len(s)
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			end = i
			break
		}
	}
	if end <= 1 {
		return ""
	}
	return s[:end]
}

// findAssignments returns the set of string-literal values assigned to
// varName anywhere in content. e.g. for varName="$to" and content
// containing `$to = "drop@bad.com";`, returns ["drop@bad.com"].
func findAssignments(content []byte, varName string) []string {
	re := regexp.MustCompile(regexp.QuoteMeta(varName) + `\s*=\s*["']([^"']*)["']`)
	var out []string
	for _, m := range re.FindAllSubmatch(content, -1) {
		if len(m) > 1 {
			out = append(out, string(m[1]))
		}
	}
	return out
}
