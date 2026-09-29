package hunt

import (
	"testing"

	"github.com/cybercdh/kitphishr/internal/sources"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"http://example.com/a/b", "http://example.com/a/b", true},
		{"  https://example.com/kit.zip \n", "https://example.com/kit.zip", true},
		{"example.com/login/", "http://example.com/login/", true},
		{"example.com", "http://example.com", true},
		{"127.0.0.1:8080/a/b/", "http://127.0.0.1:8080/a/b/", true},
		{"", "", false},
		{"   ", "", false},
		{"# a comment", "", false},
		{"ftp://example.com/kit.zip", "", false},
		{"http://", "", false},
		{"://example.com/a", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeURL(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("NormalizeURL(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestGenerateTargets_SchemelessInputProducesUsableTargets(t *testing.T) {
	rows := normalizeInputs([]sources.PhishUrls{{URL: "example.com/foo/bar"}})
	if len(rows) != 1 || rows[0].URL != "http://example.com/foo/bar" {
		t.Fatalf("normalizeInputs: got %+v", rows)
	}
}
