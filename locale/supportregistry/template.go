package supportregistry

import (
	"strings"
	"text/template"
)

// ApplyTemplate runs Go text/template substitution on text with params.
//
// Behavior on errors (template parse failure OR missing parameter): we
// return the original text unchanged rather than erroring out. The
// registry's contract is "always return a usable string" — a malformed
// template is a developer bug, not a user-facing error condition, and
// surfacing the raw "{{.X}}" in a UI is strictly better than crashing
// the request.
//
// missingkey="zero" tells text/template to substitute the zero value
// (empty string) for missing keys rather than printing "<no value>".
//
// Exported so sub-package implementations of Registry (e.g.
// dynamicregistry) can share the same template-handling contract
// without copying the logic.
func ApplyTemplate(text string, params map[string]any) string {
	tmpl, err := template.New("").Option("missingkey=zero").Parse(text)
	if err != nil {
		return text
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return text
	}
	return buf.String()
}
