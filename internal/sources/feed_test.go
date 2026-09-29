package sources

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFeedLines_OKParsesAndSkipsNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != feedUserAgent {
			t.Errorf("User-Agent = %q, want %q", ua, feedUserAgent)
		}
		w.Write([]byte("http://a.example/x\n\n# comment\n  http://b.example/y  \r\n"))
	}))
	defer srv.Close()

	rows, err := feedLines(srv.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	if rows[0].URL != "http://a.example/x" || rows[1].URL != "http://b.example/y" || rows[1].Source != "test" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestFeedGet_NonOKIsAnError(t *testing.T) {
	for _, code := range []int{403, 404, 429, 500, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte("<html>Access denied</html>\n"))
		}))
		rows, err := feedLines(srv.URL, "test")
		srv.Close()
		if err == nil {
			t.Errorf("status %d: expected error, got %d rows", code, len(rows))
			continue
		}
		if !strings.Contains(err.Error(), "unexpected status") {
			t.Errorf("status %d: unexpected error text %q", code, err)
		}
		if len(rows) != 0 {
			t.Errorf("status %d: error page was parsed into %d URLs", code, len(rows))
		}
	}
}

func TestFetchAll_AllFeedsFailingReturnsError(t *testing.T) {
	saved := Registry
	defer func() { Registry = saved }()
	Registry = []Source{{
		Name: "broken", Enabled: true,
		Fetch: func() ([]PhishUrls, error) { return nil, http.ErrHandlerTimeout },
	}}
	if _, err := FetchAll(); err != ErrAllFeedsFailed {
		t.Fatalf("err = %v, want ErrAllFeedsFailed", err)
	}
}

func TestFetchAll_OneFailingFeedIsSkipped(t *testing.T) {
	saved := Registry
	defer func() { Registry = saved }()
	Registry = []Source{
		{Name: "broken", Enabled: true, Fetch: func() ([]PhishUrls, error) { return nil, http.ErrHandlerTimeout }},
		{Name: "good", Enabled: true, Fetch: func() ([]PhishUrls, error) {
			return []PhishUrls{{URL: "http://x.example/", Source: "good"}}, nil
		}},
	}
	rows, err := FetchAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Source != "good" {
		t.Fatalf("rows = %+v", rows)
	}
}
