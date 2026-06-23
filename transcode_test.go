package main

import (
	"archive/zip"
	"io"
	"path/filepath"
	"testing"
)

// readZip returns name->content for every file entry in a zip.
func readZip(t *testing.T, path string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open zip %s: %v", path, err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

// testdata/sample.7z holds a.php ("<?php echo \"hi\"; ?>") and sub/b.txt
// ("hello world"). RAR can't be synthesised in-tree (proprietary encoder), so
// the rar decode path is exercised by the shared zip-writer logic here plus
// local/integration runs against real captured .rar kits.
func TestTranscode7z(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.zip")
	if err := transcodeToZip("testdata/sample.7z", out); err != nil {
		t.Fatalf("transcodeToZip(7z): %v", err)
	}
	got := readZip(t, out)
	if got["a.php"] != `<?php echo "hi"; ?>` {
		t.Errorf("a.php = %q", got["a.php"])
	}
	if got["sub/b.txt"] != "hello world" {
		t.Errorf("sub/b.txt = %q", got["sub/b.txt"])
	}
}

func TestTranscodeRejectsNonArchive(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.zip")
	// A zip is not rar/7z → unsupported (the analyzer only transcodes rar/7z;
	// zips already go straight down the existing path).
	if err := transcodeToZip("testdata/sample_zip_input.zip", out); err != errUnsupportedArchive {
		t.Errorf("zip input: got %v, want errUnsupportedArchive", err)
	}
	if err := transcodeToZip("testdata/does-not-exist", out); err == nil {
		t.Errorf("missing file: want error, got nil")
	}
}

func TestArchiveMagicDetection(t *testing.T) {
	if !isRarMagic([]byte("Rar!\x1a\x07\x00")) {
		t.Error("rar v4 magic not detected")
	}
	if !isRarMagic([]byte("Rar!\x1a\x07\x01\x00")) {
		t.Error("rar v5 magic not detected")
	}
	if !is7zMagic([]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		t.Error("7z magic not detected")
	}
	if isRarMagic([]byte("PK\x03\x04")) || is7zMagic([]byte("PK\x03\x04")) {
		t.Error("zip misdetected as rar/7z")
	}
	if isRarMagic([]byte("Rar")) {
		t.Error("short buffer must not match")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		`kit\index.php`:    "kit/index.php",
		`/abs/path.php`:    "abs/path.php",
		`../../escape.php`: "escape.php",
		`a/./b/../c.txt`:   "a/b/c.txt",
		`normal/file.js`:   "normal/file.js",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
