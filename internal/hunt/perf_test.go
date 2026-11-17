package hunt

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A non-archive URL serving a large non-HTML body must not be downloaded:
// HandleResponse never looks at it.
func TestFetchSkipsNonHTMLNonArchiveBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Write(bytes.Repeat([]byte("A"), 8<<20))
	}))
	defer srv.Close()
	resp, err := fetchOnce(context.Background(), MakeClient(10, false), srv.URL+"/movie")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || len(resp.Body) != 0 {
		t.Fatalf("status=%d body=%d, want 200 and no body", resp.StatusCode, len(resp.Body))
	}
}

// HTML is read (for open-dir detection) but capped.
func TestFetchCapsHTMLBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(bytes.Repeat([]byte("<p>x</p>"), (maxHTMLBodySize/8)+1000))
	}))
	defer srv.Close()
	resp, err := fetchOnce(context.Background(), MakeClient(10, false), srv.URL+"/page")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != maxHTMLBodySize {
		t.Fatalf("body=%d, want capped at %d", len(resp.Body), maxHTMLBodySize)
	}
}

// A redirect from a plain path to an archive must still get the full body,
// since HandleResponse captures by the FINAL url.
func TestFetchRedirectToArchiveReadsFullBody(t *testing.T) {
	kit := bytes.Repeat([]byte("Z"), 6<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" {
			http.Redirect(w, r, "/kit.zip", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(kit)
	}))
	defer srv.Close()
	resp, err := fetchOnce(context.Background(), MakeClient(10, false), srv.URL+"/download")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != len(kit) {
		t.Fatalf("body=%d, want %d", len(resp.Body), len(kit))
	}
}

// A host that accepts connections but never answers is retired after
// hostStrikeLimit stalls, and further targets short-circuit.
func TestStallingHostIsRetired(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold open, never respond
		}
	}()
	client := MakeClient(10, false)
	client.Transport.(*http.Transport).ResponseHeaderTimeout = 100 * time.Millisecond
	host := l.Addr().String()
	for i := 0; i < hostStrikeLimit; i++ {
		if _, err := fetchOnce(context.Background(), client, "http://"+host+"/x"); err == nil {
			t.Fatal("expected a timeout")
		}
	}
	if !isHostMarkedDead(host) {
		t.Fatalf("host not retired after %d stalls", hostStrikeLimit)
	}
}

// One answered request resets the stall count.
func TestAliveResetsStrikes(t *testing.T) {
	host := "strike-reset.example:80"
	for i := 0; i < hostStrikeLimit-1; i++ {
		recordStall(host)
	}
	recordAlive(host)
	recordStall(host)
	if isHostMarkedDead(host) {
		t.Fatal("host retired despite an intervening success")
	}
}
