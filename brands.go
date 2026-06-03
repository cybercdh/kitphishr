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
//
// Ordering is roughly by phishing volume (productivity/cloud accounts
// first, banks and telecoms next, then specialised categories). Coverage
// is intentionally mixed US + UK + EU since real-world phishing feeds
// span all three.
var defaultBrandSignatures = []BrandSignature{
	// Productivity / email / cloud accounts
	{Name: "Microsoft", Keywords: []string{"microsoft", "outlook", "office365", "office 365", "live.com", "microsoftonline", "hotmail", "office.com"}},
	{Name: "Apple", Keywords: []string{"icloud", "apple id", "appleid", "itunes connect", "apple.com/account"}},
	{Name: "Google", Keywords: []string{"google account", "gmail", "googleapis.com", "myaccount.google", "accounts.google"}},
	{Name: "Yahoo", Keywords: []string{"yahoo.com", "yahoo mail", "yahoo.fr", "yahoo.co.uk"}},
	{Name: "ProtonMail", Keywords: []string{"protonmail.com", "proton.me"}},

	// Payments / e-commerce
	{Name: "PayPal", Keywords: []string{"paypal"}},
	{Name: "Amazon", Keywords: []string{"amazon.com", "amazon.co", "amazonaws", "amzn.to"}},
	{Name: "eBay", Keywords: []string{"ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr"}},

	// Social
	{Name: "Facebook", Keywords: []string{"facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com"}},
	{Name: "X", Keywords: []string{"twitter.com", "x.com/i/flow", "abs.twimg.com"}},
	{Name: "LinkedIn", Keywords: []string{"linkedin.com"}},

	// Banks — US
	{Name: "Chase", Keywords: []string{"chase.com", "jpmorgan", "chase bank"}},
	{Name: "Bank of America", Keywords: []string{"bank of america", "bofa.com", "bankofamerica"}},
	{Name: "Wells Fargo", Keywords: []string{"wells fargo", "wellsfargo"}},

	// Banks — UK / EU
	{Name: "HSBC", Keywords: []string{"hsbc.com", "hsbc.co.uk", "hsbc.fr", "hsbc online", "hsbc personal"}},
	{Name: "Barclays", Keywords: []string{"barclays.co.uk", "barclays.com", "barclaycard"}},
	{Name: "Lloyds", Keywords: []string{"lloydsbank.com", "lloyds bank", "lloyds banking"}},
	{Name: "NatWest", Keywords: []string{"natwest.com", "natwest online"}},
	{Name: "Santander", Keywords: []string{"santander.com", "santander.co.uk", "santander.es", "santander.de"}},
	{Name: "BNP Paribas", Keywords: []string{"bnpparibas.com", "bnpparibas.fr", "bnp paribas"}},
	{Name: "Deutsche Bank", Keywords: []string{"deutsche-bank.de", "deutsche bank online"}},
	{Name: "ING", Keywords: []string{"ing.com", "ing.nl", "ing.de", "ingdirect"}},

	// Telecoms — UK / EU
	{Name: "Orange", Keywords: []string{"orange.fr", "orange.es", "orange.pl", "orange bank", "orange money", "espace orange", "mon compte orange", "client orange"}},
	{Name: "Vodafone", Keywords: []string{"vodafone.com", "vodafone.co.uk", "vodafone.de", "vodafone.it", "vodafone.es", "myvodafone"}},
	{Name: "EE", Keywords: []string{"ee.co.uk", "ee mobile", "my ee account"}},

	// Tax / government
	{Name: "HMRC", Keywords: []string{"hmrc.gov.uk", "hm revenue", "gateway.tax.service.gov.uk"}},
	{Name: "IRS", Keywords: []string{"irs.gov", "internal revenue service"}},

	// Streaming / consumer
	{Name: "Netflix", Keywords: []string{"netflix.com", "netflix.net"}},
	{Name: "Spotify", Keywords: []string{"spotify.com"}},
	{Name: "Steam", Keywords: []string{"steampowered", "steamcommunity"}},

	// Shipping / postal
	{Name: "DHL", Keywords: []string{"dhl.com", "dhl express", "dhl tracking"}},
	{Name: "FedEx", Keywords: []string{"fedex.com", "fedex tracking"}},
	{Name: "UPS", Keywords: []string{"ups.com/track", "united parcel service", "ups tracking"}},
	{Name: "USPS", Keywords: []string{"usps.com", "usps tracking"}},
	{Name: "Royal Mail", Keywords: []string{"royalmail.com", "royal mail tracking", "royal mail delivery"}},
	{Name: "La Poste", Keywords: []string{"laposte.fr", "la poste"}},
	{Name: "Deutsche Post", Keywords: []string{"deutschepost.de", "deutsche post"}},

	// Productivity / B2B
	{Name: "Adobe", Keywords: []string{"adobe.com", "adobe sign", "adobeid"}},
	{Name: "DocuSign", Keywords: []string{"docusign"}},

	// Crypto exchanges
	{Name: "Coinbase", Keywords: []string{"coinbase"}},
	{Name: "Binance", Keywords: []string{"binance"}},
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
