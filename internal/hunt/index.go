package hunt

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/cybercdh/kitphishr/internal/sources"
)

// Capture records and the SHA256-keyed dedup index.

type Response struct {
	StatusCode    int
	Body          []byte
	URL           string
	ContentLength int64
	ContentType   string
	Source        string
	Intel         *sources.SourceIntel
}

type IndexRecord struct {
	Timestamp    string               `json:"ts"`
	URL          string               `json:"url"`
	SHA256       string               `json:"sha256"`
	Size         int                  `json:"size"`
	ContentType  string               `json:"content_type,omitempty"`
	Source       string               `json:"source,omitempty"`
	Intel        *sources.SourceIntel `json:"intel,omitempty"`
	SavedPath    string               `json:"saved_path,omitempty"`
	Deduplicated bool                 `json:"deduplicated,omitempty"`
}

type Index struct {
	mu     sync.Mutex
	file   *os.File
	hashes map[string]string // sha256 -> saved_path
}

func NewIndex(path string) (*Index, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	idx := &Index{file: f, hashes: make(map[string]string)}
	if err := idx.loadExisting(); err != nil {
		f.Close()
		return nil, err
	}
	return idx, nil
}

func (i *Index) loadExisting() error {
	if _, err := i.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(i.file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec IndexRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.SHA256 != "" && rec.SavedPath != "" && !rec.Deduplicated {
			i.hashes[rec.SHA256] = rec.SavedPath
		}
	}
	if _, err := i.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// SeedHashes pre-populates the dedup map with sha256s known from prior
// runs (typically read from a Lambda-published derived/known-hashes.txt).
// Doesn't overwrite an existing entry (loaded index records win since they
// have the real saved path). The sentinel value identifies these as
// known-from-elsewhere so future readers can distinguish.
const knownHashSentinel = "known-from-prior-run"

func (i *Index) SeedHashes(hashes []string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	added := 0
	for _, h := range hashes {
		if _, ok := i.hashes[h]; ok {
			continue
		}
		i.hashes[h] = knownHashSentinel
		added++
	}
	return added
}

// SeenPath returns the saved path for a previously-recorded sha256, or "" if unseen.
func (i *Index) SeenPath(sha string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hashes[sha]
}

// Record appends a new record to the index. If the record is a fresh save
// (not deduplicated), it also memoises the sha256 -> path mapping so future
// hits dedup against it.
func (i *Index) Record(rec IndexRecord) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := i.file.Write(data); err != nil {
		return err
	}
	if !rec.Deduplicated && rec.SHA256 != "" && rec.SavedPath != "" {
		i.hashes[rec.SHA256] = rec.SavedPath
	}
	return nil
}

func (i *Index) Close() error {
	if i == nil || i.file == nil {
		return nil
	}
	return i.file.Close()
}
