package hunt

import (
	"context"
	"testing"

	"github.com/cybercdh/kitphishr/internal/sources"
)

func collect(t *testing.T, in []sources.PhishUrls, words []string, opts TargetOptions) []sources.PhishUrls {
	t.Helper()
	var out []sources.PhishUrls
	for tgt := range GenerateTrackedTargets(context.Background(), in, words, []string{"zip"}, nil, opts) {
		out = append(out, tgt)
	}
	return out
}

func kindsByURL(ts []sources.PhishUrls) map[string]string {
	m := map[string]string{}
	for _, t := range ts {
		m[t.URL] = t.Kind
	}
	return m
}

func TestTargetKindsAndLevels(t *testing.T) {
	got := kindsByURL(collect(t, []sources.PhishUrls{{URL: "http://h.example/a/b/login.php"}}, []string{"kit"}, TargetOptions{}))
	want := map[string]string{
		"http://h.example/a/b/login.php":     "feed",
		"http://h.example/a/b/login.php.zip": "ext-up0",
		"http://h.example/a/b":               "path",
		"http://h.example/a/b/":              "slash",
		"http://h.example/a/b.zip":           "ext-up1",
		"http://h.example/a/b/kit.zip":       "word-up0", // nearest real directory
		"http://h.example/a/kit.zip":         "word-up1",
		"http://h.example/kit.zip":           "word-up2",
	}
	for u, k := range want {
		if got[u] != k {
			t.Errorf("%s: kind %q, want %q", u, got[u], k)
		}
	}
	for _, bad := range []string{"http://h.example/a/b/login.php/", "http://h.example/a/b/login.php/kit.zip"} {
		if _, ok := got[bad]; ok {
			t.Errorf("generated pointless probe under a file: %s", bad)
		}
	}
}

// A directory named like a domain must not be mistaken for a file.
func TestDomainLikeDirectoryStillGuessed(t *testing.T) {
	got := kindsByURL(collect(t, []sources.PhishUrls{{URL: "http://h.example/secure.paypal.com"}}, []string{"kit"}, TargetOptions{}))
	if got["http://h.example/secure.paypal.com/kit.zip"] != "word-up0" {
		t.Fatalf("domain-like dir not guessed: %v", got)
	}
}

// A trailing-slash feed URL and its slashless prefix are one directory.
func TestTrailingSlashDirCountedOnce(t *testing.T) {
	got := kindsByURL(collect(t, []sources.PhishUrls{{URL: "http://h.example/a/b/"}}, []string{"kit"}, TargetOptions{}))
	if got["http://h.example/a/b/kit.zip"] != "word-up0" || got["http://h.example/a/kit.zip"] != "word-up1" {
		t.Fatalf("levels wrong: %v", got)
	}
}

func TestWordlistLevelsLimit(t *testing.T) {
	got := kindsByURL(collect(t, []sources.PhishUrls{{URL: "http://h.example/a/b/login.php"}}, []string{"kit"}, TargetOptions{WordlistLevels: 1}))
	if got["http://h.example/a/b/kit.zip"] != "word-up0" {
		t.Fatal("nearest directory guess missing")
	}
	for _, u := range []string{"http://h.example/a/kit.zip", "http://h.example/kit.zip"} {
		if _, ok := got[u]; ok {
			t.Errorf("guess beyond -wordlist-levels 1: %s", u)
		}
	}
}

// Within a host, the feed URL goes first and wordlist guesses last, nearest
// directory first.
func TestHostQueuePriorityOrder(t *testing.T) {
	ts := collect(t, []sources.PhishUrls{{URL: "http://h.example/a/b/login.php"}}, []string{"kit", "panel"}, TargetOptions{})
	if ts[0].Kind != "feed" {
		t.Fatalf("first target %q, want feed", ts[0].Kind)
	}
	last := -1
	for _, tg := range ts {
		p := kindPriority(tg.Kind)
		if p < last {
			t.Fatalf("priority went backwards at %s (%s)", tg.URL, tg.Kind)
		}
		last = p
	}
}
