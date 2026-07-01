package hunt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/cybercdh/kitphishr/internal/analyze"
)

// Persisting captured kits and writing capture/kit JSON sidecars.

// SaveResponse hashes the body, deduplicates against the index, and writes
// the kit to disk under <outputDir>/<sha256><ext>. Returns the saved path
// and whether the save was a deduplicated hit (no new file written).
func (r Response) SaveResponse(idx *Index, outputDir string) (savedPath string, deduplicated bool, err error) {
	if len(r.Body) < 1 {
		return "", false, errors.New("empty body")
	}

	sum := sha256.Sum256(r.Body)
	sha := hex.EncodeToString(sum[:])

	rec := IndexRecord{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		URL:         r.URL,
		SHA256:      sha,
		Size:        len(r.Body),
		ContentType: r.ContentType,
		Source:      r.Source,
		Intel:       r.Intel,
	}

	if existing := idx.SeenPath(sha); existing != "" {
		rec.SavedPath = existing
		rec.Deduplicated = true
		if err := idx.Record(rec); err != nil {
			return "", true, err
		}
		return existing, true, nil
	}

	ext := extensionFromURL(r.URL)
	target := path.Join(outputDir, sha+ext)

	// guard against the (extremely unlikely) race where two workers compute
	// the same sha simultaneously: O_EXCL means the second one bails.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		if os.IsExist(err) {
			rec.SavedPath = target
			rec.Deduplicated = true
			if err := idx.Record(rec); err != nil {
				return "", true, err
			}
			return target, true, nil
		}
		return "", false, err
	}
	if _, err := f.Write(r.Body); err != nil {
		f.Close()
		return "", false, err
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}

	rec.SavedPath = target
	if err := idx.Record(rec); err != nil {
		return target, false, err
	}
	if Config.EmitKitJSON {
		writeKitJSON(rec, target, outputDir)
	}
	if Config.EmitCaptureJSON {
		writeCaptureJSON(rec, outputDir)
	}
	return target, false, nil
}

// writeCaptureJSON writes a per-kit <sha>.capture.json next to a freshly-saved
// kit: the capture metadata only, no analysis. A downstream analyzer (the
// per-kit Lambda) joins this with the archive itself to produce the
// <sha>.kit.json the ingestion pipeline consumes — keeping analysis CPU out of
// the scan task. saved_path is reduced to its basename: the local directory is
// meaningless downstream, but the filename tells the analyzer which sibling
// object is the archive. Best-effort — errors are logged, never fatal.
func writeCaptureJSON(rec IndexRecord, outputDir string) {
	rec.SavedPath = path.Base(rec.SavedPath)
	out, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture-json: encode %s: %s\n", rec.SHA256, err)
		return
	}
	capPath := path.Join(outputDir, rec.SHA256+".capture.json")
	if err := os.WriteFile(capPath, out, 0640); err != nil {
		fmt.Fprintf(os.Stderr, "capture-json: write %s: %s\n", capPath, err)
	}
}

// writeKitJSON analyses a freshly-saved kit and writes a per-kit
// <sha>.kit.json next to it: the capture metadata (from the index record)
// merged with the kitphishr-analyze output. This is the at-capture record the
// event-driven ingestion pipeline consumes. Best-effort — errors are logged to
// stderr, never fatal to the scan.
func writeKitJSON(rec IndexRecord, savedPath, outputDir string) {
	ar := analyze.AnalyzePath(savedPath, Config.KitJSONBrands)
	b, err := json.Marshal(ar)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: marshal %s: %s\n", rec.SHA256, err)
		return
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: remap %s: %s\n", rec.SHA256, err)
		return
	}
	// the analyser's local path is meaningless downstream; capture metadata wins.
	delete(m, "path")
	m["sha256"] = rec.SHA256
	m["ts"] = rec.Timestamp
	m["url"] = rec.URL
	if rec.Source != "" {
		m["source"] = rec.Source
	}
	if rec.ContentType != "" {
		m["content_type"] = rec.ContentType
	}
	if rec.Size > 0 {
		m["size"] = rec.Size
	}
	out, err := json.Marshal(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: encode %s: %s\n", rec.SHA256, err)
		return
	}
	kitPath := path.Join(outputDir, rec.SHA256+".kit.json")
	if err := os.WriteFile(kitPath, out, 0640); err != nil {
		fmt.Fprintf(os.Stderr, "kit-json: write %s: %s\n", kitPath, err)
	}
}
