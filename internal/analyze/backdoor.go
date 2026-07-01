package analyze

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Backdoor detection. A meaningful share of phishing kits ship with a
// hardcoded backdoor — RCE the kit author left in so they can reclaim any
// deployment a "customer" stands up. The canonical shape is a dangerous
// sink fed directly by a request superglobal, dressed up as something
// benign, e.g.:
//
//	if (isset($_GET['useragent'])) { ...; system($_GET['useragent']); exit; }
//
// reads like a bot-blocker, but `system($_GET[...])` is unauthenticated
// remote command execution.
//
// This is a regex pass (no PHP parser, no taint analysis), so it favours
// precision: each rule targets a pattern that is essentially never benign
// in kit code. We accept missing the cleverly-indirected cases (variable
// laundering across includes, char()/concatenation-built sink names) —
// deeper coverage is the SLM analyser's job. What we emit here is the cheap,
// high-confidence, zero-cost signal: has_backdoor + per-hit file/line/kind.
//
// maxBackdoorHits caps output for a pathological kit (e.g. a webshell
// collection) so one archive can't produce an unbounded record.
const maxBackdoorHits = 100

// evidenceMaxLen bounds the snippet we keep per hit. Enough to show the
// callsite in a paid-tier detail view; the free tier surfaces only the
// has_backdoor flag + count.
const evidenceMaxLen = 200

// BackdoorHit is a single suspected backdoor callsite.
type BackdoorHit struct {
	File     string `json:"file"`
	Kind     string `json:"kind"`
	Line     int    `json:"line,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type backdoorRule struct {
	kind string
	re   *regexp.Regexp
}

// Each rule's `kind` is a stable identifier surfaced in the record, so the
// catalog can label/filter by backdoor class.
var backdoorRules = []backdoorRule{
	// Dangerous command/code sink fed directly by a request superglobal —
	// the classic disguised RCE. [^;{}] keeps the match inside one statement
	// so we don't bridge an unrelated sink and a later superglobal.
	{"rce_sink_superglobal", regexp.MustCompile(
		`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval|assert|create_function|call_user_func(?:_array)?)\s*\(\s*[^;{}]{0,160}?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b`)},

	// Variable-function call straight off a superglobal: $_REQUEST['a']($_REQUEST['b']).
	// The kit picks both the function and its argument from the request.
	{"dynamic_call_superglobal", regexp.MustCompile(
		`(?i)\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\(`)},

	// eval()/assert() wrapping a decode/inflate chain — the standard
	// obfuscated webshell loader, regardless of where the payload comes from.
	{"eval_obfuscated", regexp.MustCompile(
		`(?i)\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|pack)\s*\(`)},

	// preg_replace with the deprecated /e modifier — evaluates the
	// replacement as PHP, a well-worn code-exec primitive. RE2 has no
	// backreferences, so we match a simple quoted pattern arg ending in a
	// delimiter + modifier run containing `e` + closing quote.
	{"preg_replace_e", regexp.MustCompile(
		`(?i)preg_replace\s*\(\s*['"][^'"]{1,300}[/#~!|}\]][a-z]{0,6}e[a-z]{0,6}['"]`)},
}

// scanBackdoors runs the backdoor rules over one file's content and records
// any hits against the accumulator, deduped per file+line+kind.
func (a *analyzer) scanBackdoors(name string, content []byte) {
	if len(a.backdoors) >= maxBackdoorHits {
		return
	}
	for _, rule := range backdoorRules {
		for _, loc := range rule.re.FindAllIndex(content, -1) {
			line, ev := lineAndSnippet(content, loc[0])
			key := fmt.Sprintf("%s\x00%d\x00%s", name, line, rule.kind)
			if _, seen := a.backdoorSeen[key]; seen {
				continue
			}
			a.backdoorSeen[key] = struct{}{}
			a.backdoors = append(a.backdoors, BackdoorHit{
				File: name, Kind: rule.kind, Line: line, Evidence: ev,
			})
			if len(a.backdoors) >= maxBackdoorHits {
				return
			}
		}
	}
}

// lineAndSnippet returns the 1-based line number of byte offset idx and the
// surrounding source line, trimmed and sanitised for safe display.
func lineAndSnippet(content []byte, idx int) (int, string) {
	if idx < 0 || idx > len(content) {
		idx = 0
	}
	line := 1 + strings.Count(string(content[:idx]), "\n")

	start := idx
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	end := idx
	for end < len(content) && content[end] != '\n' {
		end++
	}
	return line, sanitiseEvidence(content[start:end])
}

// sanitiseEvidence collapses whitespace/control bytes and caps length so a
// snippet can't smuggle terminal escapes or blow up the record.
func sanitiseEvidence(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, string(b))
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) > evidenceMaxLen {
		s = s[:evidenceMaxLen] + "…"
	}
	return s
}

// finaliseBackdoors sorts the hits deterministically and reports them.
func finaliseBackdoors(a *analyzer) []BackdoorHit {
	if len(a.backdoors) == 0 {
		return nil
	}
	sort.Slice(a.backdoors, func(i, j int) bool {
		x, y := a.backdoors[i], a.backdoors[j]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		return x.Kind < y.Kind
	})
	return a.backdoors
}
