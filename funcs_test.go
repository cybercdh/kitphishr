package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestGenerateTargets_PathTraversalAndZipGuess(t *testing.T) {
	ctx := context.Background()
	in := []PhishUrls{{URL: "http://example.com/foo/bar/login.php", Source: "stdin"}}
	ch := GenerateTargets(ctx, in)

	var got []string
	for u := range ch {
		got = append(got, u.URL)
		if u.Source != "stdin" {
			t.Errorf("source not propagated: %+v", u)
		}
	}
	sort.Strings(got)

	want := []string{
		"http://example.com",
		"http://example.com/",
		"http://example.com/foo",
		"http://example.com/foo/",
		"http://example.com/foo.zip",
		"http://example.com/foo/bar",
		"http://example.com/foo/bar/",
		"http://example.com/foo/bar.zip",
		"http://example.com/foo/bar/login.php",
		"http://example.com/foo/bar/login.php/",
		"http://example.com/foo/bar/login.php.zip",
	}
	sort.Strings(want)
	if !equalStringSlices(got, want) {
		t.Errorf("targets mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestGenerateTargets_SkipsRootZip(t *testing.T) {
	ctx := context.Background()
	in := []PhishUrls{{URL: "http://example.com/", Source: "x"}}
	ch := GenerateTargets(ctx, in)

	for u := range ch {
		if strings.HasSuffix(u.URL, "/.zip") {
			t.Errorf("should not emit root /.zip: %s", u.URL)
		}
		if u.URL == "http://example.com.zip" {
			t.Errorf("should not emit bare-host .zip: %s", u.URL)
		}
	}
}

func TestGenerateTargets_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	in := []PhishUrls{{URL: "http://example.com/a/b/c", Source: "x"}}
	ch := GenerateTargets(ctx, in)
	cancel()
	// drain — should close on its own without hanging
	for range ch {
	}
}

func TestZipFromDir_ApacheIndex(t *testing.T) {
	body := `<html><head><title>Index of /uploads</title></head><body>
		<a href="../">../</a>
		<a href="kit.zip">kit.zip</a>
		<a href="readme.txt">readme.txt</a>
	</body></html>`
	resp := Response{Body: []byte(body), ContentType: "text/html"}
	hrefs, err := ZipFromDir(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(hrefs) != 1 || hrefs[0] != "kit.zip" {
		t.Errorf("expected [kit.zip], got %v", hrefs)
	}
}

func TestZipFromDir_NginxAutoindex(t *testing.T) {
	body := `<html><head><title>uploads/</title></head><body>
		<h1>Index of /uploads/</h1>
		<hr><pre>
		<a href="../">../</a>
		<a href="files.zip">files.zip</a>                    01-Jan-2024 12:00       1234
		</pre><hr>
	</body></html>`
	resp := Response{Body: []byte(body), ContentType: "text/html; charset=utf-8"}
	hrefs, err := ZipFromDir(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(hrefs) != 1 || hrefs[0] != "files.zip" {
		t.Errorf("expected [files.zip], got %v", hrefs)
	}
}

func TestZipFromDir_NotAnOpenDir(t *testing.T) {
	body := `<html><head><title>Welcome</title></head><body>
		<a href="kit.zip">download our app</a>
	</body></html>`
	resp := Response{Body: []byte(body), ContentType: "text/html"}
	hrefs, err := ZipFromDir(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(hrefs) != 0 {
		t.Errorf("expected no hrefs from non-open-dir page, got %v", hrefs)
	}
}

func TestZipFromDir_NonHTMLContentType(t *testing.T) {
	resp := Response{Body: []byte("<html><title>Index of /</title></html>"), ContentType: "application/json"}
	hrefs, err := ZipFromDir(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(hrefs) != 0 {
		t.Errorf("expected no hrefs from non-HTML content type, got %v", hrefs)
	}
}

func TestProbeLooksArchiveShaped(t *testing.T) {
	cases := []struct {
		name string
		r    Response
		want bool
	}{
		{"ok zip", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/zip"}, true},
		{"ok octet-stream", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/octet-stream"}, true},
		{"ok x-zip", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/x-zip-compressed"}, true},
		{"not 200", Response{StatusCode: 404, ContentLength: 1000, ContentType: "application/zip"}, false},
		{"zero length", Response{StatusCode: 200, ContentLength: 0, ContentType: "application/zip"}, false},
		{"too big", Response{StatusCode: 200, ContentLength: MAX_DOWNLOAD_SIZE + 1, ContentType: "application/zip"}, false},
		{"html", Response{StatusCode: 200, ContentLength: 1000, ContentType: "text/html"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := probeLooksArchiveShaped(c.r); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestExtensionFromURL(t *testing.T) {
	cases := map[string]string{
		"http://x.com/foo.zip":     ".zip",
		"http://x.com/foo.tar.gz":  ".gz",
		"http://x.com/foo":         ".zip",
		"http://x.com/foo.weirdextlong": ".zip",
		"http://x.com/path/":       ".zip",
	}
	for in, want := range cases {
		if got := extensionFromURL(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestIndex_AppendAndDedup(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.jsonl")
	idx, err := NewIndex(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	rec1 := IndexRecord{Timestamp: "t1", URL: "http://a/kit.zip", SHA256: "abc", Size: 10, SavedPath: filepath.Join(dir, "abc.zip")}
	if err := idx.Record(rec1); err != nil {
		t.Fatal(err)
	}
	if p := idx.SeenPath("abc"); p == "" {
		t.Errorf("expected sha to be memoised, got empty")
	}
	if p := idx.SeenPath("xyz"); p != "" {
		t.Errorf("unseen sha should return empty, got %q", p)
	}
}

func TestIndex_LoadExistingFile(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.jsonl")

	pre := IndexRecord{Timestamp: "t1", URL: "http://a/kit.zip", SHA256: "abc", Size: 10, SavedPath: filepath.Join(dir, "abc.zip")}
	data, _ := json.Marshal(pre)
	if err := os.WriteFile(indexPath, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	idx, err := NewIndex(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	if p := idx.SeenPath("abc"); p == "" {
		t.Errorf("pre-existing sha should load from file, got empty")
	}
}

// --- integration: fake server end-to-end ---

func TestIntegration_FetchAndSaveZip(t *testing.T) {
	zipBody := []byte("PK\x03\x04 fake zip content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kit.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(zipBody)))
			if r.Method == http.MethodHead {
				return
			}
			w.Write(zipBody)
		case "/notazip.zip":
			// Server lies: serves HTML for a .zip URL — HEAD-then-GET should reject this.
			w.Header().Set("Content-Type", "text/html")
			body := "<html>nope</html>"
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			if r.Method == http.MethodHead {
				return
			}
			w.Write([]byte(body))
		case "/open/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Index of /open/</title></head><body><a href="../">../</a><a href="archive.zip">archive.zip</a></body></html>`))
		case "/open/archive.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(zipBody)))
			if r.Method == http.MethodHead {
				return
			}
			w.Write(zipBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Use a small UA stand-in — the package-level `ua` var is set by flag parsing in main,
	// which doesn't run in tests, so we set it explicitly here.
	ua = defaultUserAgent

	ctx := context.Background()
	client := MakeClient(10)
	limiter := newHostRateLimiter(50, 50) // permissive in tests

	t.Run("direct zip fetch", func(t *testing.T) {
		resp, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: srv.URL + "/kit.zip", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		if !bytes.Equal(resp.Body, zipBody) {
			t.Errorf("body mismatch")
		}
		if resp.Source != "test" {
			t.Errorf("source not propagated through fetch: %q", resp.Source)
		}
	})

	t.Run("HEAD rejects non-zip masquerading as .zip", func(t *testing.T) {
		resp, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: srv.URL + "/notazip.zip", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Body) != 0 {
			t.Errorf("expected empty body (probe should have rejected), got %d bytes", len(resp.Body))
		}
	})

	t.Run("open dir surfaces zip href", func(t *testing.T) {
		resp, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: srv.URL + "/open/", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		hrefs, err := ZipFromDir(resp)
		if err != nil {
			t.Fatal(err)
		}
		if len(hrefs) != 1 || hrefs[0] != "archive.zip" {
			t.Errorf("expected [archive.zip], got %v", hrefs)
		}
	})

	t.Run("redirect-followed dir uses final URL for href resolution", func(t *testing.T) {
		// Reproduces the Python http.server / nginx case: GET /uploads -> 301 -> /uploads/.
		// Before the fix, resp.URL stayed as /uploads (no trailing slash), and resolving
		// a relative href "kit.zip" against /uploads (per RFC 3986) stripped the last
		// segment and produced /kit.zip at the root instead of /uploads/kit.zip.
		redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/uploads":
				http.Redirect(w, r, "/uploads/", http.StatusMovedPermanently)
			case "/uploads/":
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`<html><head><title>Index of /uploads/</title></head><body><a href="../">../</a><a href="kit.zip">kit.zip</a></body></html>`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer redirSrv.Close()

		resp, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: redirSrv.URL + "/uploads", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(resp.URL, "/uploads/") {
			t.Errorf("expected resp.URL to be the post-redirect URL ending in /uploads/, got %q", resp.URL)
		}
	})

	t.Run("save and dedup", func(t *testing.T) {
		dir := t.TempDir()
		idx, err := NewIndex(filepath.Join(dir, "index.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		resp, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: srv.URL + "/kit.zip", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		path1, dedup1, err := resp.SaveResponse(idx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if dedup1 {
			t.Errorf("first save should not be a dedup hit")
		}
		if path1 == "" {
			t.Errorf("expected non-empty saved path")
		}

		// fetch again from the open-dir path — same body, different URL
		resp2, err := AttemptTarget(ctx, client, limiter, PhishUrls{URL: srv.URL + "/open/archive.zip", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		path2, dedup2, err := resp2.SaveResponse(idx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if !dedup2 {
			t.Errorf("second save (same body) should be a dedup hit")
		}
		if path2 != path1 {
			t.Errorf("dedup hit should return same path: got %q, want %q", path2, path1)
		}

		// verify the index file has two lines
		data, err := os.ReadFile(filepath.Join(dir, "index.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Count(bytes.TrimRight(data, "\n"), []byte("\n")) + 1
		if lines != 2 {
			t.Errorf("expected 2 index lines, got %d. content:\n%s", lines, data)
		}
	})
}

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

func TestClaimKitURL_DedupsWithinRun(t *testing.T) {
	// Reset package-level map for test isolation.
	seenKitURLsMu.Lock()
	seenKitURLs = make(map[string]struct{})
	seenKitURLsMu.Unlock()

	if !claimKitURL("http://x.com/kit.zip") {
		t.Error("first claim should succeed")
	}
	if claimKitURL("http://x.com/kit.zip") {
		t.Error("second claim of same URL should fail")
	}
	if !claimKitURL("http://x.com/other.zip") {
		t.Error("claim of different URL should succeed")
	}
}

// --- helpers ---

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
