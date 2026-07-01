package sources

import (
	"fmt"
	"strings"
)

// README markers delimiting the generated sources table. TestREADMESourcesInSync
// keeps the text between them equal to RenderMarkdown(); run the test with
// -update to regenerate after changing the Registry.
const (
	READMEStartMarker = "<!-- sources:start -->"
	READMEEndMarker   = "<!-- sources:end -->"
)

// RenderMarkdown renders the enabled feeds as a Markdown table for the README's
// sources section. The Registry is the single source of truth: this output is
// what the README must contain between the sources markers. The feed name
// doubles as the provenance tag recorded on captured kits (the `source` field).
func RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("| Feed | License | Commercial use |\n")
	b.WriteString("|------|---------|----------------|\n")
	for _, s := range Enabled() {
		commercial := "❌"
		if s.CommercialSafe {
			commercial = "✅"
		}
		fmt.Fprintf(&b, "| [`%s`](%s) | %s | %s |\n", s.Name, s.Homepage, s.License, commercial)
	}
	return b.String()
}
