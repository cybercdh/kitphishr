package main

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// BrandSignature describes a phishing target. Keywords are case-insensitive
// substrings; any occurrence in scanned content contributes one hit toward
// that brand. A brand needs at least minBrandHits across the whole kit to
// be reported, which suppresses incidental single mentions.
type BrandSignature struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
}

// BrandHit is the per-kit roll-up emitted in AnalyzeResult.
type BrandHit struct {
	Name string `json:"name"`
	Hits int    `json:"hits"`
}

const minBrandHits = 2

// defaultBrandSignatures lists the most common phishing targets. Keywords
// favour specific URLs and distinctive phrases over short brand names to
// keep false positives low. Users can override the list entirely via
// -brands <path> with a JSON file in the same shape.
var defaultBrandSignatures = []BrandSignature{
	{Name: "Microsoft", Keywords: []string{"microsoft", "outlook", "office365", "office 365", "live.com", "microsoftonline", "hotmail", "office.com"}},
	{Name: "Apple", Keywords: []string{"icloud", "apple id", "appleid", "itunes connect", "apple.com/account"}},
	{Name: "Google", Keywords: []string{"google account", "gmail", "googleapis.com", "myaccount.google", "accounts.google"}},
	{Name: "Amazon", Keywords: []string{"amazon.com", "amazon.co", "amazonaws", "amzn.to"}},
	{Name: "PayPal", Keywords: []string{"paypal"}},
	{Name: "Facebook", Keywords: []string{"facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com"}},
	{Name: "Chase", Keywords: []string{"chase.com", "jpmorgan", "chase bank"}},
	{Name: "Bank of America", Keywords: []string{"bank of america", "bofa.com", "bankofamerica"}},
	{Name: "Wells Fargo", Keywords: []string{"wells fargo", "wellsfargo"}},
	{Name: "Netflix", Keywords: []string{"netflix.com", "netflix.net"}},
	{Name: "LinkedIn", Keywords: []string{"linkedin.com"}},
	{Name: "DHL", Keywords: []string{"dhl.com", "dhl express", "dhl tracking"}},
	{Name: "FedEx", Keywords: []string{"fedex.com", "fedex tracking"}},
	{Name: "UPS", Keywords: []string{"ups.com/track", "united parcel service", "ups tracking"}},
	{Name: "USPS", Keywords: []string{"usps.com", "usps tracking"}},
	{Name: "Adobe", Keywords: []string{"adobe.com", "adobe sign", "adobeid"}},
	{Name: "DocuSign", Keywords: []string{"docusign"}},
	{Name: "Coinbase", Keywords: []string{"coinbase"}},
	{Name: "Binance", Keywords: []string{"binance"}},
	{Name: "Steam", Keywords: []string{"steampowered", "steamcommunity"}},
}

// LoadBrandSignatures reads a JSON file of [{name, keywords}] entries.
// An empty path returns the built-in default.
func LoadBrandSignatures(path string) ([]BrandSignature, error) {
	if path == "" {
		return defaultBrandSignatures, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var brands []BrandSignature
	if err := json.Unmarshal(data, &brands); err != nil {
		return nil, err
	}
	// pre-lowercase keywords once so scanBrands doesn't have to
	for i := range brands {
		for j := range brands[i].Keywords {
			brands[i].Keywords[j] = strings.ToLower(brands[i].Keywords[j])
		}
	}
	return brands, nil
}

// scanBrandsInto increments hits for each brand whose keyword appears in
// the lowercased content. Caller is responsible for lowercasing once per
// file rather than per-brand to amortise the cost.
func scanBrandsInto(lowered []byte, brands []BrandSignature, hits map[string]int) {
	for _, b := range brands {
		for _, kw := range b.Keywords {
			if n := bytes.Count(lowered, []byte(kw)); n > 0 {
				hits[b.Name] += n
			}
		}
	}
}

// finaliseBrandHits applies the minimum-hits threshold and sorts the
// surviving brands by hit count descending (then by name for stable order).
func finaliseBrandHits(hits map[string]int) []BrandHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]BrandHit, 0, len(hits))
	for name, n := range hits {
		if n >= minBrandHits {
			out = append(out, BrandHit{Name: name, Hits: n})
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Name < out[j].Name
	})
	return out
}
