package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// SSRF guard.
//
// When enabled (-block-internal), every outbound connection — the initial
// request AND every redirect hop, since net/http calls DialContext for each —
// resolves the target host, rejects any non-globally-routable address, and
// then dials a vetted IP directly. Resolving and connecting happen in the same
// step against the same address, so there is no window for a second resolution
// to return a different (private) IP (DNS rebinding / TOCTOU), and no chance of
// a separate validator disagreeing with the resolver that the dialer actually
// uses (the libc-vs-Go octal-notation divergence class). The check is on the
// resolved IP, so textual tricks — octal/hex/decimal IPv4, IPv4-mapped IPv6,
// percent-encoding — cannot smuggle a private target past it.

// extraBlockedCIDRs are non-global ranges the net.IP stdlib helpers don't
// already cover (loopback/private/link-local/multicast/unspecified are handled
// by the helpers in isGlobalIP).
var extraBlockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",  // RFC 6598 carrier-grade NAT
		"192.0.0.0/24",   // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",   // TEST-NET-1
		"198.18.0.0/15",  // RFC 2544 benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24", // TEST-NET-3
		"240.0.0.0/4",    // reserved / future use (incl. 255.255.255.255 broadcast)
		"::/128",         // unspecified (also caught by IsUnspecified)
		"64:ff9b::/96",   // NAT64 — embeds an IPv4 that may itself be private
		"2001:db8::/32",  // documentation
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isGlobalIP reports whether ip is safe to connect to from a public scan —
// i.e. globally routable, not pointing back at our own infrastructure.
func isGlobalIP(ip net.IP) bool {
	// Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so the v4 ranges below apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || // 127.0.0.0/8, ::1
		ip.IsPrivate() || // RFC1918 + fc00::/7 ULA
		ip.IsLinkLocalUnicast() || // 169.254.0.0/16 (IMDS), fe80::/10
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() { // 0.0.0.0, ::
		return false
	}
	for _, n := range extraBlockedCIDRs {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// guardedDialContext returns a DialContext that resolves addr's host, drops any
// non-global address, and connects directly to a vetted IP (pinning the
// resolution it validated). Returned errors deliberately don't leak which
// internal range was hit.
func guardedDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// If addr is already an IP literal, validate it without a lookup.
		if literal := net.ParseIP(host); literal != nil {
			if !isGlobalIP(literal) {
				return nil, fmt.Errorf("blocked: target resolves to a non-public address")
			}
			return d.DialContext(ctx, network, net.JoinHostPort(literal.String(), port))
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ipa := range ips {
			if !isGlobalIP(ipa.IP) {
				lastErr = fmt.Errorf("blocked: target resolves to a non-public address")
				continue
			}
			conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
			if derr != nil {
				lastErr = derr
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no dialable address for host")
		}
		return nil, lastErr
	}
}
