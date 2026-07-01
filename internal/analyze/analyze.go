package analyze

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	termutil "github.com/andrew-d/go-termutil"
)

const (
	// per-file read cap during analysis. 10MB is generous for source files
	// and protects against decompression-bomb-style inputs.
	maxAnalyzeFileSize = 10 * 1024 * 1024
	// per-kit file-count cap — guards against malicious zips containing
	// huge numbers of small files.
	maxAnalyzeFiles = 50000
	// Nested-archive recursion: kits often ship a .zip inside the .zip (a
	// second-stage payload, a bundled sub-kit). Recurse into them so their IOCs
	// + filenames (incl. dropper extensions for malware classification) are
	// analysed too. Bounded depth + a per-nested-zip size cap guard zip bombs;
	// the global maxAnalyzeFiles/maxAnalyzeFileSize caps still apply throughout.
	maxNestedDepth   = 3
	maxNestedZipSize = 100 * 1024 * 1024
)

// relevantExtensions limits which files inside a kit we bother to scan.
// Kit logic lives in PHP (and historically Perl/CGI); exfiltration
// strings sometimes also appear in HTML/JS/text configs.
var relevantExtensions = map[string]bool{
	".php": true, ".phtml": true, ".php5": true, ".php7": true,
	".inc":  true,
	".html": true, ".htm": true,
	".js":  true,
	".txt": true,
	".eml": true,
	".pl":  true, ".cgi": true, ".py": true,
}

// Indicator regexes. Conservative on false positives — better to surface
// a few extra strings than to silently drop a real exfil channel.
var (
	emailIndicatorPattern = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b`)
	telegramBotPattern    = regexp.MustCompile(`\b\d{8,12}:[A-Za-z0-9_-]{30,45}\b`)
	telegramChatIDPattern = regexp.MustCompile(`chat_id\s*[=:]\s*["']?(-?\d{6,12})["']?`)
	discordWebhookPattern = regexp.MustCompile(`https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[A-Za-z0-9_-]+`)
)

// AnalyzeResult is the JSONL record emitted for each kit analysed.
type AnalyzeResult struct {
	Path            string        `json:"path"`
	SHA256          string        `json:"sha256,omitempty"`
	Size            int64         `json:"size,omitempty"`
	FilesScanned    int           `json:"files_scanned"`
	FileNames       []string      `json:"file_names,omitempty"`
	Brands          []BrandHit    `json:"brands,omitempty"`
	Authors         []string      `json:"authors,omitempty"`
	ICQHandles      []string      `json:"icq_handles,omitempty"`
	SkypeHandles    []string      `json:"skype_handles,omitempty"`
	MailDrops       []string      `json:"mail_drops,omitempty"`
	Emails          []string      `json:"emails,omitempty"`
	TelegramBots    []string      `json:"telegram_bots,omitempty"`
	TelegramChatIDs []string      `json:"telegram_chat_ids,omitempty"`
	DiscordWebhooks []string      `json:"discord_webhooks,omitempty"`
	HasBackdoor     bool          `json:"has_backdoor,omitempty"`
	Backdoors       []BackdoorHit `json:"backdoors,omitempty"`
	Errors          []string      `json:"errors,omitempty"`
}

// runAnalyze is the entry point for `kitphishr analyze`.
func Run(args []string) {
	fset := flag.NewFlagSet("analyze", flag.ExitOnError)
	outputPath := fset.String("o", "-", "output destination (- for stdout)")
	brandsPath := fset.String("brands", "", "path to a JSON file of brand signatures (built-in default if empty)")
	fset.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: kitphishr analyze [flags] <zip-or-dir>...\n")
		fmt.Fprintf(os.Stderr, "       (or pipe a newline-separated list of paths on stdin)\n\n")
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		os.Exit(2)
	}

	targets := fset.Args()
	if len(targets) == 0 && !termutil.Isatty(os.Stdin.Fd()) {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	}
	if len(targets) == 0 {
		fset.Usage()
		os.Exit(2)
	}

	brands, err := LoadBrandSignatures(*brandsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load brand signatures %q: %s\n", *brandsPath, err)
		os.Exit(1)
	}

	var out *os.File = os.Stdout
	if *outputPath != "-" {
		f, err := os.Create(*outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open output %q: %s\n", *outputPath, err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	for _, t := range targets {
		result := AnalyzePath(t, brands)
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write result for %s: %s\n", t, err)
		}
	}
}

// AnalyzePath dispatches on file/dir/zip and returns the aggregated result.
// Exported for use by tests.
func AnalyzePath(path string, brands []BrandSignature) AnalyzeResult {
	r := AnalyzeResult{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	}
	if info.IsDir() {
		return analyzeDir(path, r, brands)
	}
	r.Size = info.Size()
	if sum, err := hashFile(path); err == nil {
		r.SHA256 = sum
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return analyzeZip(path, r, brands)
	}
	// treat as a single file
	acc := newAnalyzer(brands)
	if err := scanFile(path, filepath.Base(path), acc); err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
	r.FilesScanned = 1
	return finalise(r, acc)
}

func analyzeZip(path string, r AnalyzeResult, brands []BrandSignature) AnalyzeResult {
	zr, err := zip.OpenReader(path)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("open zip: %s", err))
		return r
	}
	defer zr.Close()

	acc := newAnalyzer(brands)
	acc.recordArchiveName(filepath.Base(path))
	scanned := 0
	scanZipEntries(zr.File, acc, "", 0, &scanned, &r)
	r.FilesScanned = scanned
	return finalise(r, acc)
}

// scanZipEntries walks a zip's entries into acc, recursing into nested .zip
// members up to maxNestedDepth. `prefix` namespaces nested paths (a!/b.php) so
// the recorded file list reflects the nesting. `scanned` is shared across all
// levels so the global file-count cap bounds the whole tree.
func scanZipEntries(files []*zip.File, acc *analyzer, prefix string, depth int, scanned *int, r *AnalyzeResult) {
	for _, f := range files {
		if *scanned >= maxAnalyzeFiles {
			r.Errors = append(r.Errors, fmt.Sprintf("file count exceeded %d, stopping early", maxAnalyzeFiles))
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		name := prefix + f.Name
		// Record EVERY file (incl. images / fonts / non-PHP, and nested-archive
		// members). The full list is a fingerprint of the kit's shape and feeds
		// dropper/malware classification downstream.
		acc.recordFile(name)

		// Nested archive: recurse into it (bounded). A bad/oversized nested zip
		// just falls through to the normal per-file handling below.
		if depth < maxNestedDepth &&
			strings.HasSuffix(strings.ToLower(f.Name), ".zip") &&
			f.UncompressedSize64 <= maxNestedZipSize {
			if nf := openNestedZip(f); nf != nil {
				scanZipEntries(nf, acc, name+"!/", depth+1, scanned, r)
				continue
			}
		}

		if !relevantPath(f.Name) {
			continue
		}
		if f.UncompressedSize64 > maxAnalyzeFileSize {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxAnalyzeFileSize+1))
		rc.Close()
		if err != nil {
			continue
		}
		if int64(len(data)) > maxAnalyzeFileSize {
			continue
		}
		acc.scanNamed(name, data)
		acc.scanBackdoors(name, data)
		*scanned++
	}
}

// openNestedZip reads a zip member fully into memory and reopens it as a zip.
// Returns nil if it isn't a valid zip or can't be read (caller falls back to
// treating it as an ordinary file).
func openNestedZip(f *zip.File) []*zip.File {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(rc, maxNestedZipSize+1))
	rc.Close()
	if err != nil || int64(len(data)) > maxNestedZipSize {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	return zr.File
}

func analyzeDir(path string, r AnalyzeResult, brands []BrandSignature) AnalyzeResult {
	acc := newAnalyzer(brands)
	scanned := 0
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if scanned >= maxAnalyzeFiles {
			return filepath.SkipAll
		}
		// Store path relative to the kit root so it doesn't leak local
		// filesystem layout (e.g. /Users/cdh/kits/abc/index.php -> abc/index.php).
		name := p
		if rel, relErr := filepath.Rel(path, p); relErr == nil && rel != "" {
			name = rel
		}
		acc.recordFile(name)
		if !relevantPath(p) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxAnalyzeFileSize {
			return nil
		}
		if err := scanFile(p, name, acc); err == nil {
			scanned++
		}
		return nil
	})
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
	r.FilesScanned = scanned
	return finalise(r, acc)
}

// --- accumulator ---

type analyzer struct {
	emails    map[string]struct{}
	tgBots    map[string]struct{}
	tgChats   map[string]struct{}
	discords  map[string]struct{}
	authors   map[string]struct{}
	icqs      map[string]struct{}
	skypes    map[string]struct{}
	mailDrops map[string]struct{}
	fileNames map[string]struct{}
	brands    []BrandSignature
	// Brand scores are tracked in TWO buckets so the tie-breaker can
	// distinguish "this brand is here in the actual content" (a real
	// phish signal) from "this brand is hinted by the kit author's
	// labels" (a softer signal, easily faked by a repurposed archive).
	// brandHits is the total emitted as BrandHit.Hits; brandContentHits
	// is the subset that came from file CONTENT, not paths/archive name.
	brandHits        map[string]int
	brandContentHits map[string]int
	// archiveName is the basename of the .zip the kit came in as (or "")
	// for a directory walk.
	archiveName string
	// Suspected backdoor callsites, deduped per file+line+kind. See backdoor.go.
	backdoors    []BackdoorHit
	backdoorSeen map[string]struct{}
}

func newAnalyzer(brands []BrandSignature) *analyzer {
	return &analyzer{
		emails:           make(map[string]struct{}),
		tgBots:           make(map[string]struct{}),
		tgChats:          make(map[string]struct{}),
		discords:         make(map[string]struct{}),
		authors:          make(map[string]struct{}),
		icqs:             make(map[string]struct{}),
		skypes:           make(map[string]struct{}),
		mailDrops:        make(map[string]struct{}),
		fileNames:        make(map[string]struct{}),
		brands:           brands,
		brandHits:        make(map[string]int),
		brandContentHits: make(map[string]int),
		backdoorSeen:     make(map[string]struct{}),
	}
}

// recordFile registers a file path encountered inside a kit. Stored
// separately from the indicator scans so we capture EVERY file (even
// non-relevant ones like images / fonts) for the file-listing index.
// The path is ALSO scored against brand signatures with weight 3 — a
// file named `netflix-login.php` is a much stronger brand signal than
// the word "netflix" appearing in a generic JS library's comments.
func (a *analyzer) recordFile(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	a.fileNames[name] = struct{}{}
	if len(a.brands) > 0 {
		scanBrandsForName(name, a.brands, a.brandHits, 3)
	}
}

// recordArchiveName captures the .zip filename for both the tie-breaker
// in finaliseBrandHits and a heavy (weight 10) one-shot brand score —
// the archive label is what the kit author *says* their target is.
func (a *analyzer) recordArchiveName(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	a.archiveName = name
	if len(a.brands) > 0 {
		scanBrandsForName(name, a.brands, a.brandHits, 10)
	}
}

// scan is the unnamed entry point (kept for tests / single-buffer callers);
// content from an unknown path is treated as non-vendored.
func (a *analyzer) scan(content []byte) {
	a.scanNamed("", content)
}

// scanNamed extracts indicators from one file's content. High-specificity and
// sink-based scans (telegram/discord tokens, mail-exfil recipients) run on EVERY
// file — including vendored libraries — so a disguised exfil channel squirreled
// into e.g. PHPMailer/language/*.php is still caught. The broad bare-string
// scans (any-email, author/ICQ/Skype handles, brand-in-content) are skipped for
// vendored library files, whose translator emails / maintainer names / incidental
// brand mentions are pure false positives, not kit IOCs.
func (a *analyzer) scanNamed(name string, content []byte) {
	for _, m := range telegramBotPattern.FindAll(content, -1) {
		a.tgBots[string(m)] = struct{}{}
	}
	for _, m := range telegramChatIDPattern.FindAllSubmatch(content, -1) {
		if len(m) > 1 {
			a.tgChats[string(m[1])] = struct{}{}
		}
	}
	for _, m := range discordWebhookPattern.FindAll(content, -1) {
		a.discords[string(m)] = struct{}{}
	}
	scanMailDropsInto(content, a.mailDrops)

	if isVendoredPath(name) {
		return // skip the noisy bare-string scans for vendored library files
	}

	for _, m := range emailIndicatorPattern.FindAll(content, -1) {
		e := strings.ToLower(string(m))
		if !looksLikePlaceholderEmail(e) {
			a.emails[e] = struct{}{}
		}
	}
	scanAuthorsInto(content, a.authors, a.icqs, a.skypes)
	if len(a.brands) > 0 {
		lowered := bytes.ToLower(content)
		scanBrandsInto(lowered, a.brands, a.brandHits, 1)
		scanBrandsInto(lowered, a.brands, a.brandContentHits, 1)
	}
}

// vendorMarkers are path segments of bundled third-party libraries. Their
// contents are not kit IOCs (translator emails, maintainer names, etc.); only
// the kit's OWN files are scanned for bare-string indicators. Keep in sync with
// bedrock_analyze.py::_VENDOR_MARKERS (the SLM file-selection skip list).
var vendorMarkers = []string{
	"/phpmailer/", "/vendor/", "/node_modules/",
	"/swiftmailer/", "/phpunit/", "/composer/",
}

// isVendoredPath reports whether name lives under a bundled-library directory.
func isVendoredPath(name string) bool {
	p := "/" + strings.ToLower(filepath.ToSlash(name))
	for _, m := range vendorMarkers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

// looksLikePlaceholderEmail filters obvious tutorial/template addresses.
// Conservative — we do NOT filter real provider domains (gmail, yahoo,
// outlook, etc.) because those are exactly where attacker exfil lands.
// Also no local-part filters: "someone" and "name" appear in tutorials but
// also appear in real attacker handles, so filtering on those creates
// false negatives. We only catch obviously-fake DOMAIN combinations.
var placeholderEmailFragments = []string{
	"@example.com", "@example.org", "@example.net",
	"@your-domain", "@yourdomain.com",
	"@domain.com", "@domain.tld",
	"@localhost",
	"test@test", "user@user",
	"foo@bar", "foo@foo",
	"email@email",
}

func looksLikePlaceholderEmail(e string) bool {
	for _, p := range placeholderEmailFragments {
		if strings.Contains(e, p) {
			return true
		}
	}
	return false
}

// --- helpers ---

func scanFile(path, name string, acc *analyzer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAnalyzeFileSize+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxAnalyzeFileSize {
		return nil
	}
	acc.scanNamed(name, data)
	acc.scanBackdoors(name, data)
	return nil
}

func relevantPath(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return relevantExtensions[ext]
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func finalise(r AnalyzeResult, a *analyzer) AnalyzeResult {
	r.Brands = finaliseBrandHits(a.brandHits)
	r.Brands = applyArchiveNameTiebreaker(r.Brands, a.archiveName, a.brandContentHits)
	r.Authors = sortedKeys(a.authors)
	r.ICQHandles = sortedKeys(a.icqs)
	r.SkypeHandles = sortedKeys(a.skypes)
	r.MailDrops = sortedKeys(a.mailDrops)
	r.Emails = sortedKeys(a.emails)
	r.TelegramBots = sortedKeys(a.tgBots)
	r.TelegramChatIDs = sortedKeys(a.tgChats)
	r.DiscordWebhooks = sortedKeys(a.discords)
	r.FileNames = sortedKeys(a.fileNames)
	r.Backdoors = finaliseBackdoors(a)
	r.HasBackdoor = len(r.Backdoors) > 0
	return r
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
