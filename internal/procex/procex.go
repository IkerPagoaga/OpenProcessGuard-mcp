package procex

import (
	"fmt"
	"os"
	"strings"
)

// VerifyPath checks that the given path points to a readable procexp executable.
func VerifyPath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path points to a directory, not an executable")
	}

	lower := strings.ToLower(info.Name())
	if !strings.Contains(lower, "procexp") {
		return fmt.Errorf("file %q does not look like a ProcessExplorer executable (expected name to contain 'procexp')", info.Name())
	}

	return nil
}
