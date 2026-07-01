package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybercdh/kitphishr/internal/sources"
)

func TestGenerateTargets_PathTraversalAndZipGuess(t *testing.T) {
	ctx := context.Background()
	in := []sources.PhishUrls{{URL: "http://example.com/foo/bar/login.php", Source: "stdin"}}
	ch := GenerateTargets(ctx, in, nil, []string{"zip"})

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
	in := []sources.PhishUrls{{URL: "http://example.com/", Source: "x"}}
	ch := GenerateTargets(ctx, in, nil, []string{"zip"})

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
	in := []sources.PhishUrls{{URL: "http://example.com/a/b/c", Source: "x"}}
	ch := GenerateTargets(ctx, in, nil, []string{"zip"})
	cancel()
	// drain — should close on its own without hanging
	for range ch {
	}
}

func TestGenerateTargets_Wordlist(t *testing.T) {
	ctx := context.Background()
	in := []sources.PhishUrls{{URL: "http://example.com/foo/", Source: "stdin"}}
	ch := GenerateTargets(ctx, in, []string{"kit", "panel"}, []string{"zip"})

	got := map[string]bool{}
	for u := range ch {
		got[u.URL] = true
	}

	wantPresent := []string{
		"http://example.com/foo/kit.zip",
		"http://example.com/foo/panel.zip",
		"http://example.com/kit.zip",
		"http://example.com/panel.zip",
	}
	for _, w := range wantPresent {
		if !got[w] {
			t.Errorf("expected wordlist URL %q in output", w)
		}
	}
}

func TestGenerateTargets_MultipleExtensions(t *testing.T) {
	ctx := context.Background()
	in := []sources.PhishUrls{{URL: "http://example.com/foo/", Source: "stdin"}}
	ch := GenerateTargets(ctx, in, []string{"kit"}, []string{"zip", "tar.gz", "rar"})

	got := map[string]bool{}
	for u := range ch {
		got[u.URL] = true
	}

	for _, ext := range []string{"zip", "tar.gz", "rar"} {
		want := "http://example.com/foo/kit." + ext
		if !got[want] {
			t.Errorf("expected wordlist URL %q in output", want)
		}
		// also the ${path}.${ext} guess
		want2 := "http://example.com/foo." + ext
		if !got[want2] {
			t.Errorf("expected extension guess %q in output", want2)
		}
	}
}

func TestGenerateTargets_EmptyWordlistOnlyDoesPathGuesses(t *testing.T) {
	ctx := context.Background()
	in := []sources.PhishUrls{{URL: "http://example.com/foo/", Source: "stdin"}}
	ch := GenerateTargets(ctx, in, nil, []string{"zip"})

	for u := range ch {
		// wordlist-style URLs should not appear when wordlist is empty
		for _, w := range kitArchiveNames {
			if strings.HasSuffix(u.URL, "/"+w+".zip") {
				t.Errorf("empty wordlist should not produce wordlist URL: %s", u.URL)
			}
		}
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

func TestShouldFetchAfterProbe(t *testing.T) {
	cases := []struct {
		name string
		r    Response
		want bool
	}{
		// archive-shaped HEADs → fetch
		{"zip", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/zip"}, true},
		{"octet-stream", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/octet-stream"}, true},
		{"x-rar", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/x-rar-compressed"}, true},
		{"x-7z", Response{StatusCode: 200, ContentLength: 1000, ContentType: "application/x-7z-compressed"}, true},
		// inconclusive / HEAD-blocked → fetch anyway (the cases that used to lose kits)
		{"chunked zip (no content-length)", Response{StatusCode: 200, ContentLength: -1, ContentType: "application/zip"}, true},
		{"archive type, zero length", Response{StatusCode: 200, ContentLength: 0, ContentType: "application/zip"}, true},
		{"no content-type", Response{StatusCode: 200, ContentLength: 1000, ContentType: ""}, true},
		{"blank content-type", Response{StatusCode: 200, ContentLength: -1, ContentType: "   "}, true},
		{"HEAD not allowed (405)", Response{StatusCode: 405, ContentLength: -1, ContentType: ""}, true},
		{"forbidden HEAD (403)", Response{StatusCode: 403, ContentLength: 0, ContentType: "text/html"}, true},
		// confident disqualifications → skip the GET
		{"200 html landing page", Response{StatusCode: 200, ContentLength: 1000, ContentType: "text/html"}, false},
		{"200 image", Response{StatusCode: 200, ContentLength: 1000, ContentType: "image/png"}, false},
		{"advertised oversize", Response{StatusCode: 200, ContentLength: MAX_DOWNLOAD_SIZE + 1, ContentType: "application/zip"}, false},
		{"gone (404) — not fetchable", Response{StatusCode: 404, ContentLength: 0, ContentType: "text/html"}, false},
		{"unresolved redirect (301)", Response{StatusCode: 301, ContentLength: 162, ContentType: "text/html"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldFetchAfterProbe(c.r); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestHasArchiveExtension(t *testing.T) {
	cases := map[string]bool{
		"kit.zip":            true,
		"kit.ZIP":            true,
		"kit.tar.gz":         true,
		"kit.tgz":            true,
		"kit.tar.bz2":        true,
		"kit.rar":            true,
		"kit.7z":             true,
		"kit.zip?v=1":        true,
		"login.php":          false,
		"readme.txt":         false,
		"foo":                false,
		"kit.zipper":         false,
	}
	for in, want := range cases {
		if got := hasArchiveExtension(in); got != want {
			t.Errorf("hasArchiveExtension(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestZipFromDir_FindsMultipleArchiveExtensions(t *testing.T) {
	body := `<html><head><title>Index of /uploads</title></head><body>
		<a href="../">../</a>
		<a href="kit.zip">kit.zip</a>
		<a href="panel.tar.gz">panel.tar.gz</a>
		<a href="dump.rar">dump.rar</a>
		<a href="files.7z">files.7z</a>
		<a href="readme.txt">readme.txt</a>
	</body></html>`
	resp := Response{Body: []byte(body), ContentType: "text/html"}
	hrefs, err := ZipFromDir(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(hrefs) != 4 {
		t.Errorf("expected 4 archive hrefs, got %d: %v", len(hrefs), hrefs)
	}
}

func TestParseExtensions(t *testing.T) {
	cases := map[string][]string{
		"zip":             {"zip"},
		"zip,tar.gz,rar":  {"zip", "tar.gz", "rar"},
		".zip,.tar.gz":    {"zip", "tar.gz"},
		"  zip , tar.gz ": {"zip", "tar.gz"},
		"":                {"zip"},
		",,,":             {"zip"},
	}
	for in, want := range cases {
		got := ParseExtensions(in)
		if !equalStringSlices(got, want) {
			t.Errorf("ParseExtensions(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLoadKnownHashes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "known.txt")
	good := "abcdef0123456789" + "abcdef0123456789" + "abcdef0123456789" + "abcdef0123456789"
	upper := "ABCDEF0123456789" + "ABCDEF0123456789" + "ABCDEF0123456789" + "ABCDEF0123456789"
	content := "# header\n\n" + good + "\n   " + upper + "   \nnotahash\n" + good[:63] + "\nzzzz" + good[4:] + "\n"
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := LoadKnownHashes(p)
	if err != nil {
		t.Fatal(err)
	}
	// Both good and upper should land (upper is normalised to lower); the
	// short, bad-char, and "notahash" entries should be skipped.
	if len(out) != 2 {
		t.Fatalf("expected 2 hashes, got %d: %v", len(out), out)
	}
	for _, h := range out {
		if h != good { // upper normalises to good's value
			t.Errorf("unexpected hash: %s", h)
		}
	}
}

func TestLoadKnownHashes_EmptyPath(t *testing.T) {
	out, err := LoadKnownHashes("")
	if err != nil || out != nil {
		t.Errorf("empty path should return (nil, nil), got (%v, %v)", out, err)
	}
}

func TestIndex_SeedHashes(t *testing.T) {
	dir := t.TempDir()
	idx, err := NewIndex(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	hashes := []string{"a", "b", "c"}
	added := idx.SeedHashes(hashes)
	if added != 3 {
		t.Errorf("first seed should add 3, got %d", added)
	}
	// Re-seeding should add 0 (already present).
	if again := idx.SeedHashes(hashes); again != 0 {
		t.Errorf("re-seed should add 0, got %d", again)
	}
	for _, h := range hashes {
		if idx.SeenPath(h) == "" {
			t.Errorf("seeded sha %q should be SeenPath-detectable", h)
		}
	}
}

func TestLoadWordlist_DefaultWhenEmpty(t *testing.T) {
	w, err := LoadWordlist("")
	if err != nil {
		t.Fatal(err)
	}
	if len(w) == 0 {
		t.Error("expected non-empty default wordlist")
	}
	// sanity-check it includes one of the obvious entries
	found := false
	for _, x := range w {
		if x == "kit" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected default wordlist to include 'kit'")
	}
}

func TestLoadWordlist_FromFile(t *testing.T) {
	dir := t.TempDir()
	wlPath := filepath.Join(dir, "wordlist.txt")
	content := "# comment line\nkit\n\npanel\n   \nadmin\n"
	if err := os.WriteFile(wlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	w, err := LoadWordlist(wlPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kit", "panel", "admin"}
	if !equalStringSlices(w, want) {
		t.Errorf("got %v, want %v", w, want)
	}
}

func TestExtensionFromURL(t *testing.T) {
	cases := map[string]string{
		"http://x.com/foo.zip":          ".zip",
		"http://x.com/foo.tar.gz":       ".tar.gz",
		"http://x.com/foo.tar.bz2":      ".tar.bz2",
		"http://x.com/foo.rar":          ".rar",
		"http://x.com/foo.7z":           ".7z",
		"http://x.com/foo":              ".zip",
		"http://x.com/foo.weirdextlong": ".zip",
		"http://x.com/path/":            ".zip",
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
	client := MakeClient(10, false)
	limiter := newHostRateLimiter(50, 50) // permissive in tests

	t.Run("direct zip fetch", func(t *testing.T) {
		intel := &sources.SourceIntel{Feed: "test", Title: "Coinbase login", ASN: "AS1234"}
		resp, err := AttemptTarget(ctx, client, limiter, sources.PhishUrls{URL: srv.URL + "/kit.zip", Source: "test", Intel: intel})
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
		if resp.Intel == nil || resp.Intel.Title != "Coinbase login" {
			t.Errorf("intel not propagated through fetch: %+v", resp.Intel)
		}
	})

	t.Run("HEAD rejects non-zip masquerading as .zip", func(t *testing.T) {
		resp, err := AttemptTarget(ctx, client, limiter, sources.PhishUrls{URL: srv.URL + "/notazip.zip", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Body) != 0 {
			t.Errorf("expected empty body (probe should have rejected), got %d bytes", len(resp.Body))
		}
	})

	t.Run("open dir surfaces zip href", func(t *testing.T) {
		resp, err := AttemptTarget(ctx, client, limiter, sources.PhishUrls{URL: srv.URL + "/open/", Source: "test"})
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

		resp, err := AttemptTarget(ctx, client, limiter, sources.PhishUrls{URL: redirSrv.URL + "/uploads", Source: "test"})
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

		resp, err := AttemptTarget(ctx, client, limiter, sources.PhishUrls{URL: srv.URL + "/kit.zip", Source: "test"})
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
		resp2, err := AttemptTarget(ctx, client, limiter, sources.PhishUrls{URL: srv.URL + "/open/archive.zip", Source: "test"})
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

func TestGenerateTargets_InterleavesAcrossHosts(t *testing.T) {
	ctx := context.Background()
	in := []sources.PhishUrls{
		{URL: "http://a.example/path1", Source: "x"},
		{URL: "http://b.example/path2", Source: "x"},
		{URL: "http://c.example/path3", Source: "x"},
	}
	ch := GenerateTargets(ctx, in, nil, []string{"zip"})

	// Collect the first 6 URLs emitted (2 per host worth). With proper
	// round-robin interleaving, the first 3 should cover all 3 hosts.
	var firstThree []string
	count := 0
	for u := range ch {
		if count < 3 {
			firstThree = append(firstThree, hostOf(u.URL))
		}
		count++
		if count >= 6 {
			// drain the rest so the producer goroutine finishes
			go func() {
				for range ch {
				}
			}()
			break
		}
	}

	// First 3 URLs must touch all 3 hosts, not just one.
	seenHosts := make(map[string]bool)
	for _, h := range firstThree {
		seenHosts[h] = true
	}
	if len(seenHosts) != 3 {
		t.Errorf("expected first 3 emitted URLs to cover 3 distinct hosts, got %v (hosts: %v)", firstThree, seenHosts)
	}
}

func TestHostRateLimiter_UnlimitedWhenRPSZero(t *testing.T) {
	limiter := newHostRateLimiter(0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 1000 consecutive Wait calls should return near-instantly when unlimited.
	start := time.Now()
	for range 1000 {
		if err := limiter.Wait(ctx, "example.com"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("unlimited limiter too slow: 1000 waits took %v", elapsed)
	}
}

func TestDeadHostShortCircuit(t *testing.T) {
	// Reset the shared dead-host set so this test is hermetic regardless
	// of run order with other tests that touch real hostnames.
	deadHostSet = sync.Map{}

	ua = defaultUserAgent
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := MakeClient(5, false)
	limiter := newHostRateLimiter(50, 50)

	// RFC 6761 reserves the .invalid TLD as guaranteed-NXDOMAIN.
	target := sources.PhishUrls{URL: "http://kitphishr-deadhost-test.invalid/kit.zip", Source: "test"}

	// First call: should fail and mark host dead.
	if _, err := AttemptTarget(ctx, client, limiter, target); err == nil {
		t.Fatal("expected error from .invalid host, got nil")
	}
	if !isHostMarkedDead("kitphishr-deadhost-test.invalid") {
		t.Error("host should be marked dead after first unreachable error")
	}

	// Second call: should short-circuit instantly with ErrHostDead.
	start := time.Now()
	_, err := AttemptTarget(ctx, client, limiter, target)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrHostDead) {
		t.Errorf("expected ErrHostDead, got %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("short-circuit too slow: %v (should be near-instant)", elapsed)
	}
}

func TestIsUnreachableErr(t *testing.T) {
	if !isUnreachableErr(&net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}) {
		t.Error("DNS error should be classified unreachable")
	}
	if isUnreachableErr(nil) {
		t.Error("nil should not be unreachable")
	}
	if isUnreachableErr(errors.New("random transient blip")) {
		t.Error("plain string error should not classify as unreachable")
	}
}

func TestRetryable_DoesNotRetryUnreachable(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}
	if retryable(0, dnsErr) {
		t.Error("DNS NXDOMAIN should not be retryable")
	}
}

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

func TestValidZipBody(t *testing.T) {
	// A real zip with one file entry.
	var real bytes.Buffer
	zw := zip.NewWriter(&real)
	w, err := zw.Create("kit/index.php")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("<?php // phish ?>")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// A structurally valid but entry-less zip (bare end-of-central-directory).
	var empty bytes.Buffer
	if err := zip.NewWriter(&empty).Close(); err != nil {
		t.Fatal(err)
	}

	// A zip whose only entry is a directory.
	var dirOnly bytes.Buffer
	zw = zip.NewWriter(&dirOnly)
	if _, err := zw.Create("kit/"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body []byte
		want bool
	}{
		{"real zip", real.Bytes(), true},
		{"empty body", nil, false},
		// The ipfs.best-practice.se gateway answers every *.zip path with
		// 200 + application/zip and a tiny constant text body like this.
		{"gateway error text", []byte("invalid ipfs path: invalid path"), false},
		{"html error page", []byte("<html><body>404</body></html>"), false},
		{"entry-less zip", empty.Bytes(), false},
		{"directory-only zip", dirOnly.Bytes(), false},
		{"truncated zip", real.Bytes()[:20], false},
	}
	for _, tc := range cases {
		if got := validZipBody(tc.body); got != tc.want {
			t.Errorf("%s: validZipBody = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestValidArchiveBody(t *testing.T) {
	// A real zip with one file entry (reuses the validZipBody path).
	var realZip bytes.Buffer
	zw := zip.NewWriter(&realZip)
	w, err := zw.Create("kit/index.php")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("<?php // phish ?>")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body []byte
		want bool
	}{
		{"real zip", realZip.Bytes(), true},
		{"rar v4/v5 magic", []byte("Rar!\x1a\x07\x00somerardata"), true},
		{"7z magic", []byte("7z\xBC\xAF\x27\x1Cmore7zdata"), true},
		{"gzip magic (.gz/.tgz/.tar.gz)", []byte("\x1f\x8b\x08\x00gzippeddata"), true},
		{"html error page", []byte("<html><body>404</body></html>"), false},
		{"octet-stream stub text", []byte("invalid path: not found"), false},
		{"empty body", nil, false},
		{"too short for magic", []byte("Rar"), false},
	}
	for _, tc := range cases {
		if got := validArchiveBody(tc.body); got != tc.want {
			t.Errorf("%s: validArchiveBody = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHasCaptureExtension(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://host/root.zip", true},
		{"https://host/htdocs.rar", true},
		{"https://host/kit.7z", true},
		{"https://host/kit.tar.gz", true}, // covered by the .gz suffix
		{"https://host/kit.tgz", true},
		{"https://host/kit.gz", true},
		{"https://host/kit.zip?ver=2", true}, // query stripped
		{"https://host/KIT.ZIP", true},       // case-insensitive
		{"https://host/kit.bz2", false},      // analyzer not wired → not captured
		{"https://host/kit.tar.xz", false},
		{"https://host/index.php", false},
		{"https://host/", false},
	}
	for _, tc := range cases {
		if got := hasCaptureExtension(tc.url); got != tc.want {
			t.Errorf("hasCaptureExtension(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestWriteCaptureJSON(t *testing.T) {
	dir := t.TempDir()
	rec := IndexRecord{
		Timestamp:   "2026-06-10T12:00:00Z",
		URL:         "https://example.com/kit.zip",
		SHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Size:        1234,
		ContentType: "application/zip",
		Source:      "feed",
		Intel:       &sources.SourceIntel{Feed: "phishstats", Title: "PayPal", Tags: "database", AbuseContact: "abuse@example.com"},
		SavedPath:   dir + "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zip",
	}
	writeCaptureJSON(rec, dir)

	b, err := os.ReadFile(dir + "/" + rec.SHA256 + ".capture.json")
	if err != nil {
		t.Fatalf("capture.json not written: %s", err)
	}
	var got IndexRecord
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("capture.json not valid JSON: %s", err)
	}
	if got.URL != rec.URL || got.SHA256 != rec.SHA256 || got.Size != rec.Size || got.Source != rec.Source {
		t.Errorf("capture metadata mismatch: %+v", got)
	}
	// feed intel is provenance and must survive into capture.json
	if got.Intel == nil || got.Intel.Title != "PayPal" || got.Intel.AbuseContact != "abuse@example.com" {
		t.Errorf("source intel not preserved in capture.json: %+v", got.Intel)
	}
	// saved_path must be the bare filename — the analyzer uses it to find the
	// sibling archive object; a local directory path would be wrong downstream.
	if got.SavedPath != rec.SHA256+".zip" {
		t.Errorf("saved_path = %q, want bare basename %q", got.SavedPath, rec.SHA256+".zip")
	}
	// no analysis fields may sneak in: capture.json is meta-only by contract.
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	for _, k := range []string{"brands", "authors", "file_names", "files_scanned"} {
		if _, ok := raw[k]; ok {
			t.Errorf("capture.json must not contain analysis field %q", k)
		}
	}
}
