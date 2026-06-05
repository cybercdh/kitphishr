package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const sampleMicrosoftKitPHP = `<?php
// Microsoft Office 365 themed phish.
$page_title = "Sign in to your Microsoft account";
$post_to = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
$logo = "https://aadcdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg";
$service = "Outlook";
// Office 365 / Microsoft 365 branding everywhere
echo "<title>Microsoft Outlook</title>";
?>
`

const samplePayPalKitPHP = `<?php
$brand = "PayPal";
$post_url = "https://paypal.com/signin";
echo "Welcome back to PayPal";
echo "Sign in to PayPal";
?>
`

const sampleAmbiguousFile = `<?php
// Single mention of microsoft in a comment — should NOT classify
// (under the 2-hit threshold)
echo "powered by foo";
?>
`

func TestBrandClassification_SingleBrand(t *testing.T) {
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(sampleMicrosoftKitPHP))

	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) == 0 {
		t.Fatal("expected at least one brand classified")
	}
	if result.Brands[0].Name != "Microsoft" {
		t.Errorf("expected primary brand Microsoft, got %q (hits=%d)", result.Brands[0].Name, result.Brands[0].Hits)
	}
	if result.Brands[0].Hits < minBrandHits {
		t.Errorf("hit count below threshold: %d", result.Brands[0].Hits)
	}
}

func TestBrandClassification_DifferentBrand(t *testing.T) {
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(samplePayPalKitPHP))

	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) == 0 || result.Brands[0].Name != "PayPal" {
		t.Errorf("expected primary brand PayPal, got %+v", result.Brands)
	}
}

func TestBrandClassification_ThresholdSuppression(t *testing.T) {
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(sampleAmbiguousFile))

	result := finalise(AnalyzeResult{}, acc)
	for _, b := range result.Brands {
		if b.Hits < minBrandHits {
			t.Errorf("brand %q reported with %d hits (below threshold)", b.Name, b.Hits)
		}
	}
	// In particular, a single "microsoft" mention should not classify
	for _, b := range result.Brands {
		if b.Name == "Microsoft" {
			t.Errorf("Microsoft should not have classified from a single mention; got %d hits", b.Hits)
		}
	}
}

func TestBrandClassification_DisabledWhenNoSignatures(t *testing.T) {
	acc := newAnalyzer(nil)
	acc.scan([]byte(sampleMicrosoftKitPHP))

	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) != 0 {
		t.Errorf("expected no brand classification with nil signatures, got %+v", result.Brands)
	}
}

func TestBrandClassification_HitsAggregateAcrossFiles(t *testing.T) {
	// Each file contributes hits; total across files should reach the threshold
	// even if no single file does.
	const halfHits = `<?php $url = "https://paypal.com"; ?>` // 1 hit per file
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(halfHits))
	acc.scan([]byte(halfHits))

	result := finalise(AnalyzeResult{}, acc)
	found := false
	for _, b := range result.Brands {
		if b.Name == "PayPal" {
			found = true
			if b.Hits != 2 {
				t.Errorf("expected 2 PayPal hits across files, got %d", b.Hits)
			}
		}
	}
	if !found {
		t.Error("expected PayPal classification from cross-file aggregation")
	}
}

func TestBrandClassification_OrderedByHitsDesc(t *testing.T) {
	const mixed = `<?php
		$msft1 = "outlook"; $msft2 = "office 365"; $msft3 = "microsoft"; $msft4 = "hotmail";
		$pp1 = "paypal"; $pp2 = "paypal";
	?>`
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(mixed))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) < 2 {
		t.Fatalf("expected at least 2 brands, got %+v", result.Brands)
	}
	if result.Brands[0].Hits < result.Brands[1].Hits {
		t.Errorf("brands not sorted by hits desc: %+v", result.Brands)
	}
}

func TestLoadBrandSignatures_DefaultWhenEmpty(t *testing.T) {
	b, err := LoadBrandSignatures("")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty default brand list")
	}
}

func TestBrandClassification_Orange(t *testing.T) {
	const orangeKit = `<?php
$page = "Espace Client Orange";
$endpoint = "https://espace-orange.fr/login";
echo "<title>Mon Compte Orange</title>";
echo "Connectez-vous a votre espace orange";
// see orange.fr/portail for terms
?>`
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(orangeKit))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) == 0 || result.Brands[0].Name != "Orange" {
		t.Errorf("expected primary brand Orange, got %+v", result.Brands)
	}
}

func TestBrandClassification_HSBC(t *testing.T) {
	const hsbcKit = `<?php
$bank = "HSBC";
$post_url = "https://hsbc.co.uk/personal-banking/online-banking";
echo "Welcome to HSBC Online Banking";
echo "<title>HSBC Personal Banking - Sign in</title>";
?>`
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(hsbcKit))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) == 0 || result.Brands[0].Name != "HSBC" {
		t.Errorf("expected primary brand HSBC, got %+v", result.Brands)
	}
}

func TestBrandClassification_HMRC(t *testing.T) {
	const hmrcKit = `<?php
echo "<title>HM Revenue & Customs: Refund Notification</title>";
$portal = "https://www.gateway.tax.service.gov.uk/login";
$info = "Visit hmrc.gov.uk for more information.";
?>`
	acc := newAnalyzer(defaultBrandSignatures)
	acc.scan([]byte(hmrcKit))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) == 0 || result.Brands[0].Name != "HMRC" {
		t.Errorf("expected primary brand HMRC, got %+v", result.Brands)
	}
}

// Regression: a generic kit re-skinned as Netflix used to come out
// attributed to Google because the kit shipped Google Fonts /
// reCAPTCHA / googleapis.com URLs that scored higher than Netflix's
// narrow URL keyword set. The archive filename (set by the kit author)
// must outweigh incidental third-party brand mentions.
func TestBrandClassification_ArchiveNameWinsCloseCall(t *testing.T) {
	// Content is entirely Google: 5+ google keyword hits, zero Netflix.
	const googleHeavyKit = `<?php
$recaptcha = "https://www.google.com/recaptcha/api.js";
$fonts = "https://fonts.googleapis.com/css?family=Roboto";
$oauth = "https://accounts.google.com/o/oauth2/auth";
$api = "https://googleapis.com/oauth2/v1/userinfo";
$login_link = "https://myaccount.google.com/security";
echo "Sign in with Gmail";
?>`
	acc := newAnalyzer(defaultBrandSignatures)
	acc.recordArchiveName("NETFLIX_2K24.zip")
	acc.recordFile("NETFLIX_2K24/index.php")
	acc.scan([]byte(googleHeavyKit))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) < 2 {
		t.Fatalf("expected both Netflix and Google detected, got %+v", result.Brands)
	}
	if result.Brands[0].Name != "Netflix" {
		t.Errorf("expected primary brand Netflix (filename signal), got %q (full ordering: %+v)",
			result.Brands[0].Name, result.Brands)
	}
}

// Sanity-check the inverse: when content is overwhelmingly one brand
// and the filename only weakly mentions another, content should still
// win. Prevents the tie-breaker from being too eager.
func TestBrandClassification_ArchiveNameDoesNotOverturnStrongContent(t *testing.T) {
	// Microsoft content with 15+ hits.
	heavyMicrosoft := sampleMicrosoftKitPHP + sampleMicrosoftKitPHP + sampleMicrosoftKitPHP
	acc := newAnalyzer(defaultBrandSignatures)
	acc.recordArchiveName("paypal_creds.zip")
	acc.scan([]byte(heavyMicrosoft))
	result := finalise(AnalyzeResult{}, acc)
	if len(result.Brands) == 0 || result.Brands[0].Name != "Microsoft" {
		t.Errorf("expected primary brand Microsoft (strong content beats weak filename), got %+v",
			result.Brands)
	}
}

func TestLoadBrandSignatures_FromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "brands.json")
	custom := []BrandSignature{
		{Name: "MyBank", Keywords: []string{"mybank.com", "MyBank Online"}},
	}
	data, _ := json.Marshal(custom)
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBrandSignatures(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1 || b[0].Name != "MyBank" {
		t.Errorf("unexpected loaded brands: %+v", b)
	}
	// keywords should be lowercased
	if b[0].Keywords[1] != "mybank online" {
		t.Errorf("keywords not lowercased: %v", b[0].Keywords)
	}
}
