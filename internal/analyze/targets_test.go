package analyze

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCollectTargets_ExpandsGlobArgs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"b.zip", "a.zip", "index.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := collectTargets([]string{filepath.Join(dir, "*.zip"), "missing-*.zip"}, nil)
	want := []string{filepath.Join(dir, "a.zip"), filepath.Join(dir, "b.zip"), "missing-*.zip"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCollectTargets_Stdin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k.zip"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	in := "kits/a.zip\n\n  kits/b.zip  \r\n" + filepath.Join(dir, "*.zip") + "\n"
	got := collectTargets(nil, strings.NewReader(in))
	want := []string{"kits/a.zip", "kits/b.zip", filepath.Join(dir, "k.zip")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
