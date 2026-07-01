package analyze

import (
	"testing"
)

func TestAuthors_CodedByPatterns(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"// coded by mr_phisher\n", "mr_phisher"},
		{"// developed by John_Doe\n", "john_doe"},
		{"// made by AnonHacker\n", "anonhacker"},
		{"// written by Phisher_2024\n", "phisher_2024"},
		{"/* designed by   evil-actor.7 */\n", "evil-actor.7"},
	}
	for _, c := range cases {
		acc := newAnalyzer(nil)
		acc.scan([]byte(c.content))
		if _, ok := acc.authors[c.want]; !ok {
			t.Errorf("input %q: expected author %q in %v", c.content, c.want, sortedKeys(acc.authors))
		}
	}
}

func TestAuthors_TagPatterns(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"// Author: phisher_x\n", "phisher_x"},
		{" * @author scammer_99\n", "scammer_99"},
		{"# author = darkmaster\n", "darkmaster"},
	}
	for _, c := range cases {
		acc := newAnalyzer(nil)
		acc.scan([]byte(c.content))
		if _, ok := acc.authors[c.want]; !ok {
			t.Errorf("input %q: expected author %q in %v", c.content, c.want, sortedKeys(acc.authors))
		}
	}
}

func TestAuthors_ICQ(t *testing.T) {
	const content = `
// Contact me:
// ICQ: 1234567890
// icq #654321
`
	acc := newAnalyzer(nil)
	acc.scan([]byte(content))
	if _, ok := acc.icqs["1234567890"]; !ok {
		t.Errorf("missing 1234567890 in %v", sortedKeys(acc.icqs))
	}
	if _, ok := acc.icqs["654321"]; !ok {
		t.Errorf("missing 654321 in %v", sortedKeys(acc.icqs))
	}
}

func TestAuthors_Skype(t *testing.T) {
	const content = `
// Skype: phisher.contact
// Skype.bad-actor_99
`
	acc := newAnalyzer(nil)
	acc.scan([]byte(content))
	if _, ok := acc.skypes["phisher.contact"]; !ok {
		t.Errorf("missing phisher.contact in %v", sortedKeys(acc.skypes))
	}
	if _, ok := acc.skypes["bad-actor_99"]; !ok {
		t.Errorf("missing bad-actor_99 in %v", sortedKeys(acc.skypes))
	}
}

func TestAuthors_FalsePositiveFilter(t *testing.T) {
	const libAttribution = `
// jQuery JavaScript Library v3.6.0
// Made by jQuery Foundation, Inc.
// Author: jQuery
// @author Adobe
`
	acc := newAnalyzer(nil)
	acc.scan([]byte(libAttribution))
	for _, fp := range []string{"jquery", "adobe", "microsoft", "google"} {
		if _, ok := acc.authors[fp]; ok {
			t.Errorf("known FP %q should have been filtered out", fp)
		}
	}
}

func TestAuthors_FinaliseIntoResult(t *testing.T) {
	const kit = `<?php
// coded by mr_phisher
// ICQ: 1234567890
// Skype: phisher.contact
// Author: mr_phisher
?>`
	acc := newAnalyzer(nil)
	acc.scan([]byte(kit))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Authors) != 1 || result.Authors[0] != "mr_phisher" {
		t.Errorf("expected authors=[mr_phisher], got %v", result.Authors)
	}
	if len(result.ICQHandles) != 1 || result.ICQHandles[0] != "1234567890" {
		t.Errorf("expected icq=[1234567890], got %v", result.ICQHandles)
	}
	if len(result.SkypeHandles) != 1 || result.SkypeHandles[0] != "phisher.contact" {
		t.Errorf("expected skype=[phisher.contact], got %v", result.SkypeHandles)
	}
}
