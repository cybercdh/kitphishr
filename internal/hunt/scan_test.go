package hunt

import "testing"

func TestResolveHref(t *testing.T) {
	cases := []struct {
		base, href, want string
	}{
		{"http://x.com/dir/", "kit.zip", "http://x.com/dir/kit.zip"},
		{"http://x.com/dir/", "/files/kit.zip", "http://x.com/files/kit.zip"},
		{"http://x.com/dir", "kit.zip", "http://x.com/kit.zip"},
		{"http://x.com/dir/page.html", "kit.zip", "http://x.com/dir/kit.zip"},
		{"http://x.com/dir/", "https://other.com/kit.zip", "https://other.com/kit.zip"},
		{"http://x.com/dir/", "../up/kit.zip", "http://x.com/up/kit.zip"},
		{"http://x.com/dir/", "kit.zip?v=1", "http://x.com/dir/kit.zip?v=1"},
	}
	for _, c := range cases {
		got, ok := resolveHref(c.base, c.href)
		if !ok {
			t.Errorf("resolveHref(%q, %q) returned ok=false", c.base, c.href)
			continue
		}
		if got != c.want {
			t.Errorf("resolveHref(%q, %q) = %q, want %q", c.base, c.href, got, c.want)
		}
	}
}

func TestScannerClaim_DedupsWithinRun(t *testing.T) {
	s := NewScanner(nil, nil, false, false)

	if !s.claim("http://x.com/kit.zip") {
		t.Error("first claim should succeed")
	}
	if s.claim("http://x.com/kit.zip") {
		t.Error("second claim of same URL should fail")
	}
	if !s.claim("http://x.com/other.zip") {
		t.Error("claim of different URL should succeed")
	}
}
