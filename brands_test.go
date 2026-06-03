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
