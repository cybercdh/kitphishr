package main

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
	Path            string     `json:"path"`
	SHA256          string     `json:"sha256,omitempty"`
	Size            int64      `json:"size,omitempty"`
	FilesScanned    int        `json:"files_scanned"`
	Brands          []BrandHit `json:"brands,omitempty"`
	Authors         []string   `json:"authors,omitempty"`
	ICQHandles      []string   `json:"icq_handles,omitempty"`
	SkypeHandles    []string   `json:"skype_handles,omitempty"`
	Emails          []string   `json:"emails,omitempty"`
	TelegramBots    []string   `json:"telegram_bots,omitempty"`
	TelegramChatIDs []string   `json:"telegram_chat_ids,omitempty"`
	DiscordWebhooks []string   `json:"discord_webhooks,omitempty"`
	Errors          []string   `json:"errors,omitempty"`
}

// runAnalyze is the entry point for `kitphishr analyze`.
func runAnalyze(args []string) {
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
	if err := scanFile(path, acc); err != nil {
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
	scanned := 0
	for _, f := range zr.File {
		if scanned >= maxAnalyzeFiles {
			r.Errors = append(r.Errors, fmt.Sprintf("file count exceeded %d, stopping early", maxAnalyzeFiles))
			break
		}
		if f.FileInfo().IsDir() {
			continue
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
		acc.scan(data)
		scanned++
	}
	r.FilesScanned = scanned
	return finalise(r, acc)
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
		if err := scanFile(p, acc); err == nil {
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
	brands    []BrandSignature
	brandHits map[string]int
}

func newAnalyzer(brands []BrandSignature) *analyzer {
	return &analyzer{
		emails:    make(map[string]struct{}),
		tgBots:    make(map[string]struct{}),
		tgChats:   make(map[string]struct{}),
		discords:  make(map[string]struct{}),
		authors:   make(map[string]struct{}),
		icqs:      make(map[string]struct{}),
		skypes:    make(map[string]struct{}),
		brands:    brands,
		brandHits: make(map[string]int),
	}
}

func (a *analyzer) scan(content []byte) {
	for _, m := range emailIndicatorPattern.FindAll(content, -1) {
		e := strings.ToLower(string(m))
		if !looksLikePlaceholderEmail(e) {
			a.emails[e] = struct{}{}
		}
	}
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
	scanAuthorsInto(content, a.authors, a.icqs, a.skypes)
	if len(a.brands) > 0 {
		scanBrandsInto(bytes.ToLower(content), a.brands, a.brandHits)
	}
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

func scanFile(path string, acc *analyzer) error {
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
	acc.scan(data)
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
	r.Authors = sortedKeys(a.authors)
	r.ICQHandles = sortedKeys(a.icqs)
	r.SkypeHandles = sortedKeys(a.skypes)
	r.Emails = sortedKeys(a.emails)
	r.TelegramBots = sortedKeys(a.tgBots)
	r.TelegramChatIDs = sortedKeys(a.tgChats)
	r.DiscordWebhooks = sortedKeys(a.discords)
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
