package sources

import (
	"strings"
	"testing"
)

func TestParseTweetFeedCSV(t *testing.T) {
	const sample = `2026-06-03 00:00:00,urldna_bot,domain,evil.example.com,#phishing #scam,https://x.com/urldna_bot/status/1
2026-06-03 00:00:00,urldna_bot,url,https://evil.example.com/login,#phishing #scam,https://x.com/urldna_bot/status/1
2026-06-03 01:17:00,user_a,sha256,abc123def,#APT,https://x.com/user_a/status/2
2026-06-03 02:18:00,user_b,url,http://malware-not-phish.example.org,#malware,https://x.com/user_b/status/3
2026-06-03 02:18:00,user_c,url,http://multi.example.net/page,#malware #phishing #campaign,https://x.com/user_c/status/4
2026-06-03 02:18:00,user_d,ip,192.0.2.42,#phishing,https://x.com/user_d/status/5
`
	out, err := parseTweetFeedCSV(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	wantURLs := []string{
		"https://evil.example.com/login",
		"http://multi.example.net/page",
	}
	if len(out) != len(wantURLs) {
		t.Fatalf("expected %d urls, got %d: %v", len(wantURLs), len(out), out)
	}
	for i, w := range wantURLs {
		if out[i].URL != w {
			t.Errorf("row %d: got %q, want %q", i, out[i].URL, w)
		}
		if out[i].Source != "tweetfeed" {
			t.Errorf("row %d: source = %q, want tweetfeed", i, out[i].Source)
		}
	}
}
