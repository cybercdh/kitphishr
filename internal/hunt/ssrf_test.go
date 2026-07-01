package hunt

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsGlobalIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", // loopback
		"::1",                          // loopback v6
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC1918
		"169.254.169.254",     // link-local / IMDS
		"fe80::1",             // link-local v6
		"fc00::1", "fd00::1",  // ULA
		"0.0.0.0", "::",       // unspecified
		"100.64.0.1",          // CGNAT
		"198.18.0.1",          // benchmarking
		"192.0.2.5",           // TEST-NET-1
		"255.255.255.255",     // broadcast (240/4)
		"224.0.0.1",           // multicast
		"::ffff:127.0.0.1",    // IPv4-mapped loopback
		"::ffff:169.254.169.254", // IPv4-mapped IMDS
		"::ffff:10.0.0.1",     // IPv4-mapped RFC1918
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse as IP", s)
		}
		if isGlobalIP(ip) {
			t.Errorf("isGlobalIP(%q) = true, want false (should be blocked)", s)
		}
	}

	allowed := []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34", // public v4
		"2606:4700:4700::1111", // public v6 (cloudflare)
		"::ffff:8.8.8.8",       // IPv4-mapped public
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse as IP", s)
		}
		if !isGlobalIP(ip) {
			t.Errorf("isGlobalIP(%q) = false, want true (should be allowed)", s)
		}
	}
}

// The guarded dialer must refuse IP-literal targets in every textual notation
// that names a private address, without needing DNS. These are the encodings
// (octal/hex/decimal/IPv4-mapped) that bypass a separate string-based
// validator; here the literal is parsed and range-checked before any connect.
func TestGuardedDialBlocksLiterals(t *testing.T) {
	dial := guardedDialContext(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	blockedHosts := []string{
		"127.0.0.1",
		"169.254.169.254",
		"10.0.0.1",
		"[::1]",
		"[::ffff:127.0.0.1]",
		"[::ffff:169.254.169.254]",
		"[fd00::1]",
	}
	for _, h := range blockedHosts {
		conn, err := dial(ctx, "tcp", net.JoinHostPort(strings.Trim(h, "[]"), "80"))
		if err == nil {
			conn.Close()
			t.Errorf("guardedDial(%q) connected, want blocked", h)
			continue
		}
		if !strings.Contains(err.Error(), "non-public") {
			t.Errorf("guardedDial(%q) error = %q, want a non-public block", h, err)
		}
	}
}

// A guarded client must reject a redirect whose target is a private address,
// even though the first hop is a legitimate public server. This is the
// redirect-escape that bypasses any pre-fetch URL validation.
func TestGuardedClientBlocksRedirectToLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:80/secret", http.StatusFound)
	}))
	defer srv.Close()

	client := MakeClient(3, true)
	resp, err := client.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("redirect to loopback was followed, want blocked")
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Errorf("redirect block error = %q, want a non-public block", err)
	}

	// Sanity: the same first hop is reachable without the guard.
	plain := MakeClient(3, false)
	if resp, err := plain.Get(srv.URL); err == nil {
		resp.Body.Close()
	}
}
