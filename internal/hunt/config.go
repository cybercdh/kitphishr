package hunt

import "github.com/cybercdh/kitphishr/internal/analyze"

// MAX_DOWNLOAD_SIZE caps how many bytes of a fetched archive the hunt engine
// will read/save. A response body beyond this is rejected as oversize.
const MAX_DOWNLOAD_SIZE = 104857600 // 100mb

// maxHTMLBodySize caps how much of an HTML (non-archive) response is read.
// HTML is only parsed as a possible open-directory listing; real autoindex
// pages are well under this even with thousands of entries.
const maxHTMLBodySize = 4 << 20 // 4mb

// Options holds the run-time settings the hunt engine reads while scanning.
// main() fills a single Config instance from the parsed flags before the
// workers start; these are set-once-at-startup values, so a package-level
// Config keeps the fetch/save call chains free of config-threading noise.
type Options struct {
	UserAgent string // User-Agent header sent on every probe/fetch (-u)

	// EmitKitJSON / EmitCaptureJSON control the per-kit sidecar files written
	// on save (-kit-json / -capture-json). KitJSONBrands is the brand-signature
	// set used by the on-save analysis when EmitKitJSON is on (loaded once).
	EmitKitJSON     bool
	EmitCaptureJSON bool
	KitJSONBrands   []analyze.BrandSignature

	// OnHostDead, if set, is called once for each host newly found
	// unreachable this run (used to persist dead hosts across runs).
	OnHostDead func(host string)
	// SkipURL, if set, reports archive URLs not worth downloading again
	// (saved by a recent run).
	SkipURL func(url string) bool
}

// Config is the active hunt configuration for this process. main() assigns it
// once after flag parsing; the fetch/save code reads it.
var Config Options

// DeadHostCount reports how many distinct unreachable hosts the engine has
// short-circuited this run. Exposed for progress/summary reporting in main.
func DeadHostCount() uint64 {
	return deadHostCount.Load()
}
