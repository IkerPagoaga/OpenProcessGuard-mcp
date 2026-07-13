//go:build !windows

package handlers

import "errors"

// processHandleCount is Windows-only (GetProcessHandleCount). On other
// platforms — this package also compiles on Linux for the -race dev/CI lane —
// it reports unsupported, so get_process_detail simply omits open_handles.
func processHandleCount(pid int32) (int32, error) {
	return 0, errors.ErrUnsupported
}
