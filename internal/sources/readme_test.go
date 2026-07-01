package sources

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// updateREADME regenerates the README sources block instead of asserting on it:
//
//	go test ./internal/sources/ -run TestREADMESourcesInSync -update
var updateREADME = flag.Bool("update", false, "rewrite the README sources block from the Registry")

// readmePath is the repo-root README, relative to this package directory.
const readmePath = "../../README.md"

func TestREADMESourcesInSync(t *testing.T) {
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	content := string(data)

	start := strings.Index(content, READMEStartMarker)
	end := strings.Index(content, READMEEndMarker)
	if start < 0 || end < 0 || end < start {
		t.Fatalf("README is missing the sources markers %q / %q", READMEStartMarker, READMEEndMarker)
	}

	want := "\n" + RenderMarkdown()
	got := content[start+len(READMEStartMarker) : end]

	if *updateREADME {
		updated := content[:start+len(READMEStartMarker)] + want + content[end:]
		if err := os.WriteFile(readmePath, []byte(updated), 0644); err != nil {
			t.Fatalf("write README: %v", err)
		}
		t.Log("README sources block regenerated")
		return
	}

	if got != want {
		t.Errorf("README sources table is out of sync with the Registry.\n"+
			"Run: go test ./internal/sources/ -run TestREADMESourcesInSync -update\n\n"+
			"have:\n%s\nwant:\n%s", got, want)
	}
}
