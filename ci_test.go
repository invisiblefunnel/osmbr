package osmbr_test

// Guards the fuzzing CI configuration against drifting away from the fuzz
// targets in this package. The weekly workflow lists its targets explicitly, one
// job each, so a target added without a matrix entry would never be fuzzed and
// nothing else would notice.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fuzzTargetRE matches a fuzz target's declaration.
var fuzzTargetRE = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(\w+ \*testing\.F\) \{`)

// declaredFuzzTargets returns every fuzz target declared in this package.
func declaredFuzzTargets(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range fuzzTargetRE.FindAllStringSubmatch(string(src), -1) {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		t.Fatal("found no fuzz targets, so this test is not checking anything")
	}
	slices.Sort(out)
	return out
}

// TestFuzzWorkflowListsEveryTarget checks the weekly workflow's matrix against
// the targets that actually exist.
func TestFuzzWorkflowListsEveryTarget(t *testing.T) {
	const workflow = ".github/workflows/fuzz.yml"
	src, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("reading %s: %v", workflow, err)
	}

	// The matrix is a plain list of names, so the entries are recognised by
	// shape rather than by parsing YAML: a dash, then a target name.
	var listed []string
	for _, line := range strings.Split(string(src), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "- Fuzz"); ok {
			listed = append(listed, "Fuzz"+name)
		}
	}
	slices.Sort(listed)

	declared := declaredFuzzTargets(t)
	for _, want := range declared {
		if !slices.Contains(listed, want) {
			t.Errorf("%s does not fuzz %s; add it to the matrix", workflow, want)
		}
	}
	for _, got := range listed {
		if !slices.Contains(declared, got) {
			t.Errorf("%s fuzzes %s, which no longer exists", workflow, got)
		}
	}
}
