package analyze

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// collectTargets turns CLI args (or, if there are none, stdin lines) into the
// list of paths to analyse.
//
// PowerShell and cmd.exe don't expand wildcards for native programs, so on
// Windows `kitphishr analyze kits\*.zip` arrives as the literal "kits\*.zip".
// We expand glob patterns ourselves. On Unix the shell has normally done it
// already, so the paths contain no metacharacters and pass through unchanged.
func collectTargets(args []string, stdin io.Reader) []string {
	var out []string
	if len(args) > 0 {
		for _, a := range args {
			out = append(out, expandGlob(a)...)
		}
		return out
	}
	if stdin == nil {
		return nil
	}
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, expandGlob(line)...)
		}
	}
	return out
}

// expandGlob expands a wildcard pattern into matching paths (sorted). A path
// without metacharacters, or a pattern matching nothing, is returned as-is so
// the analyser reports a clear "not found" error for it.
func expandGlob(p string) []string {
	if !strings.ContainsAny(p, "*?[") {
		return []string{p}
	}
	if _, err := os.Stat(p); err == nil {
		return []string{p} // a real file whose name contains a metacharacter
	}
	matches, err := filepath.Glob(p)
	if err != nil || len(matches) == 0 {
		return []string{p}
	}
	sort.Strings(matches)
	return matches
}
