package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requiredArchiveFiles are the files a downloaded release MUST contain. install.ps1 is
// the load-bearing entry: the README's Quick start instructs the user to run it after
// downloading a release, but it was omitted from the goreleaser archive for four
// releases (v2.1.0 through v2.5.0), so the project's own recommended install path was
// impossible to follow without separately cloning the repository. Nothing caught it
// because no test asserted that a documented artifact actually ships.
var requiredArchiveFiles = []string{
	"README.md",
	"LICENSE",
	"SECURITY.md",
	"config.example.json",
	"install.ps1",
}

// repoRoot walks up from the test's package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root (no go.mod found walking up)")
	return ""
}

// archiveFilesBlock extracts the `files:` list belonging to the `archives:` section.
// Deliberately text-based rather than YAML-parsed: this test must not add a dependency
// to assert a property of the build configuration.
func archiveFilesBlock(t *testing.T, cfg string) []string {
	t.Helper()
	lines := strings.Split(cfg, "\n")

	inArchives := false
	inFiles := false
	var entries []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// A non-indented, non-comment line starts a new top-level section.
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(trimmed, "#") {
			if inArchives && inFiles {
				break // left the archives section entirely
			}
			inArchives = strings.HasPrefix(trimmed, "archives:")
			inFiles = false
			continue
		}
		if !inArchives {
			continue
		}
		if strings.HasPrefix(trimmed, "files:") {
			inFiles = true
			continue
		}
		if inFiles {
			if !strings.HasPrefix(trimmed, "- ") {
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					inFiles = false // a sibling key ended the list
				}
				continue
			}
			entries = append(entries, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
		}
	}
	return entries
}

func TestReleaseArchiveShipsDocumentedFiles(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yaml: %v", err)
	}

	got := archiveFilesBlock(t, string(raw))
	if len(got) == 0 {
		t.Fatal("could not parse any entries from the archives files: list")
	}

	have := make(map[string]bool, len(got))
	for _, f := range got {
		have[f] = true
	}
	for _, want := range requiredArchiveFiles {
		if !have[want] {
			t.Errorf("release archive does not ship %q — the docs reference it, so a release downloader cannot follow them. Got: %v", want, got)
		}
	}
}

// TestRequiredArchiveFilesExistInRepo closes the other half of the loop: listing a file
// in the archive that is not in the repository would fail the release build, not the
// tests, and only after a tag had already been pushed.
func TestRequiredArchiveFilesExistInRepo(t *testing.T) {
	root := repoRoot(t)
	for _, f := range requiredArchiveFiles {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Errorf("%q is required in the release archive but is missing from the repo: %v", f, err)
		}
	}
}
