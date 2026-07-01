package analyze

import (
	"archive/zip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/nwaples/rardecode/v2"
)

// The rest of the pipeline is zip-only: `kitphishr analyze` opens zips (and the
// analyzer Lambda's SLM file-selection reads zip entries). Feeds increasingly
// deliver .rar/.7z kits we used to drop as "not_zip". transcode reads those with
// PURE-GO decoders (no unrar/7z binary — so it cross-compiles for the arm64
// analyzer Lambda, whose final image stage is COPY-only) and re-emits an
// equivalent zip the existing tooling can consume.
const (
	// /tmp on the analyzer Lambda is 2 GiB; cap well under it so a decompression
	// bomb can't fill the disk. Matches the spirit of MAX_DOWNLOAD_SIZE.
	maxTranscodeTotalBytes = int64(1_500_000_000)
	maxTranscodeEntries    = 50_000
)

var errUnsupportedArchive = errors.New("not a rar or 7z archive")

// runTranscode implements `kitphishr transcode <in.rar|in.7z> <out.zip>`.
func RunTranscode(args []string) {
	fset := flag.NewFlagSet("transcode", flag.ExitOnError)
	fset.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: kitphishr transcode <in.rar|in.7z> <out.zip>\n")
	}
	_ = fset.Parse(args)
	if fset.NArg() != 2 {
		fset.Usage()
		os.Exit(2)
	}
	if err := transcodeToZip(fset.Arg(0), fset.Arg(1)); err != nil {
		fmt.Fprintf(os.Stderr, "transcode: %s\n", err)
		os.Exit(1)
	}
}

// transcodeToZip detects rar/7z by magic bytes and writes <out> as a zip with
// the same files. On any error the partial output is removed so a caller never
// sees a half-written zip. Returns errUnsupportedArchive if <in> is neither.
func transcodeToZip(in, out string) (err error) {
	magic, err := readMagic(in)
	if err != nil {
		return err
	}
	switch {
	case isRarMagic(magic), is7zMagic(magic):
	default:
		return errUnsupportedArchive
	}

	zf, err := os.Create(out)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(zf)
	defer func() {
		cerr := zw.Close()
		fcerr := zf.Close()
		if err == nil {
			err = cerr
		}
		if err == nil {
			err = fcerr
		}
		if err != nil {
			os.Remove(out)
		}
	}()

	if isRarMagic(magic) {
		return transcodeRar(in, zw)
	}
	return transcode7z(in, zw)
}

func readMagic(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 8)
	n, _ := io.ReadFull(f, buf)
	return buf[:n], nil
}

func isRarMagic(b []byte) bool {
	// "Rar!\x1a\x07" — shared prefix of RAR v4 and v5.
	return len(b) >= 6 && b[0] == 0x52 && b[1] == 0x61 && b[2] == 0x72 &&
		b[3] == 0x21 && b[4] == 0x1A && b[5] == 0x07
}

func is7zMagic(b []byte) bool {
	// "7z\xBC\xAF\x27\x1C"
	return len(b) >= 6 && b[0] == 0x37 && b[1] == 0x7A && b[2] == 0xBC &&
		b[3] == 0xAF && b[4] == 0x27 && b[5] == 0x1C
}

func transcodeRar(in string, zw *zip.Writer) error {
	rc, err := rardecode.OpenReader(in)
	if err != nil {
		return err
	}
	defer rc.Close()

	var total int64
	entries := 0
	for {
		hdr, err := rc.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.IsDir {
			continue
		}
		n, err := copyEntry(zw, hdr.Name, rc, maxTranscodeTotalBytes-total)
		total += n
		if err != nil {
			return err
		}
		entries++
		if entries > maxTranscodeEntries {
			return fmt.Errorf("archive exceeds %d entries", maxTranscodeEntries)
		}
		if total > maxTranscodeTotalBytes {
			return fmt.Errorf("archive exceeds %d bytes uncompressed", maxTranscodeTotalBytes)
		}
	}
}

func transcode7z(in string, zw *zip.Writer) error {
	r, err := sevenzip.OpenReader(in)
	if err != nil {
		return err
	}
	defer r.Close()

	var total int64
	entries := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		n, err := copyEntry(zw, f.Name, rc, maxTranscodeTotalBytes-total)
		rc.Close()
		total += n
		if err != nil {
			return err
		}
		entries++
		if entries > maxTranscodeEntries {
			return fmt.Errorf("archive exceeds %d entries", maxTranscodeEntries)
		}
		if total > maxTranscodeTotalBytes {
			return fmt.Errorf("archive exceeds %d bytes uncompressed", maxTranscodeTotalBytes)
		}
	}
	return nil
}

// copyEntry creates one zip entry and copies up to limit+1 bytes into it (the
// +1 lets the caller's running total detect an over-cap archive). Returns the
// number of bytes written.
func copyEntry(zw *zip.Writer, name string, src io.Reader, limit int64) (int64, error) {
	clean := sanitizeName(name)
	if clean == "" {
		return 0, nil
	}
	w, err := zw.Create(clean)
	if err != nil {
		return 0, err
	}
	if limit < 0 {
		limit = 0
	}
	return io.Copy(w, io.LimitReader(src, limit+1))
}

// sanitizeName normalises an archive member name to a clean forward-slash zip
// path: backslashes to slashes, leading slashes and . / .. segments dropped so
// the emitted zip is well-formed and stays inside the tree.
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	parts := make([]string, 0, 8)
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		parts = append(parts, seg)
	}
	return strings.Join(parts, "/")
}
