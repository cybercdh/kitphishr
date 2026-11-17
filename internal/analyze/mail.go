package analyze

import (
	"bytes"
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
//  1. Literal: mail("drop@attacker.ru", ...)
//  2. Assigned-then-passed: $to = "drop@attacker.ru"; mail($to, ...)
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
	// PHPMailer / SMTP-style exfil. Many kits send via PHPMailer rather than
	// PHP's mail(): the recipient is ->addAddress()/->addCC()/->addBCC(), and
	// the attacker's own sending account is ->setFrom()/->Username. All are
	// attacker-controlled identities worth capturing as mail drops. First arg
	// only; resolved literal-or-variable like the mail() path.
	phpMailerRecipientPattern = regexp.MustCompile(
		`(?i)->\s*(?:addAddress|addCC|addBCC|setFrom)\s*\(\s*([^,)]+?)\s*[,)]`)
	phpMailerUserPattern = regexp.MustCompile(
		`(?i)->\s*Username\s*=\s*([^;]+?)\s*;`)
	// assignmentPattern captures every `$name = "literal"` in one pass, so a
	// file with N mail sinks is scanned for assignments once, not N times.
	assignmentPattern = regexp.MustCompile(
		`(\$[A-Za-z0-9_]+)\s*=\s*["']([^"']*)["']`)
)

// scanMailDropsInto finds confirmed mail-exfil recipients in content
// and adds them to drops. Variable references are resolved against
// assignments in the same content (per-file scope).
func scanMailDropsInto(content []byte, drops map[string]struct{}) {
	scanMailDropsLowered(content, bytes.ToLower(content), drops)
}

// scanMailDropsLowered is scanMailDropsInto with a caller-supplied lower-cased
// copy of content, used to skip each sink regex when its keyword is absent.
func scanMailDropsLowered(content, lowered []byte, drops map[string]struct{}) {
	sinks := []struct {
		keyword string
		re      *regexp.Regexp
	}{
		{"mail", mailCallPattern},          // mail() / wp_mail() / mb_send_mail()
		{"->", phpMailerRecipientPattern},  // ->addAddress/addCC/addBCC/setFrom(...)
		{"username", phpMailerUserPattern}, // ->Username = ...
	}
	var assigns map[string][]string // built lazily on the first $var argument
	resolved := make(map[string]struct{})
	for _, sink := range sinks {
		if !bytes.Contains(lowered, []byte(sink.keyword)) {
			continue
		}
		for _, m := range sink.re.FindAllSubmatch(content, -1) {
			if len(m) < 2 {
				continue
			}
			arg := strings.TrimSpace(string(m[1]))
			// The same sink argument repeated N times resolves identically;
			// resolve it once per file.
			if _, done := resolved[arg]; done {
				continue
			}
			resolved[arg] = struct{}{}
			if assigns == nil && strings.HasPrefix(arg, "$") {
				assigns = collectAssignments(content)
			}
			resolveMailArg(assigns, arg, drops)
		}
	}
}

// resolveMailArg turns a captured first-argument expression into a mail drop:
// a "..."/'...' literal directly, or a $var resolved against same-file string
// assignments (e.g. `$to = "drop@bad.com"; mail($to, ...)` or PHPMailer's
// `$m->addAddress($to)`).
func resolveMailArg(assigns map[string][]string, arg string, drops map[string]struct{}) {
	if arg == "" {
		return
	}
	if val, ok := parseStringLiteral(arg); ok {
		addIfMailDrop(val, drops)
		return
	}
	if strings.HasPrefix(arg, "$") {
		varName := variableHead(arg)
		if varName == "" {
			return
		}
		for _, val := range assigns[varName] {
			addIfMailDrop(val, drops)
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

// collectAssignments maps every variable name to the string-literal values
// assigned to it in content. e.g. `$to = "drop@bad.com";` yields
// {"$to": ["drop@bad.com"]}.
func collectAssignments(content []byte) map[string][]string {
	out := make(map[string][]string)
	seen := make(map[[2]string]struct{})
	for _, m := range assignmentPattern.FindAllSubmatch(content, -1) {
		k := [2]string{string(m[1]), string(m[2])}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out[k[0]] = append(out[k[0]], k[1])
	}
	return out
}
