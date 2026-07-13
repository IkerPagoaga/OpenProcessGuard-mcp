//go:build windows

package handlers

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetProcessHandleCount has no wrapper in x/sys/windows, so it is resolved
// lazily from kernel32. NewLazySystemDLL loads ONLY from System32 (never the
// application directory or PATH), so this cannot be redirected by DLL planting.
var (
	modkernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHandleCount = modkernel32.NewProc("GetProcessHandleCount")
)

// processHandleCount returns the number of open kernel handles held by pid.
// gopsutil's Process.NumFDs is not implemented on Windows (it always returned
// 0), so the GetProcessHandleCount API is the honest source for the
// get_process_detail open_handles field. PROCESS_QUERY_LIMITED_INFORMATION is
// the least right that works, and succeeds against most elevated/protected
// processes when the server itself runs elevated.
func processHandleCount(pid int32) (int32, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)

	var n uint32
	r1, _, callErr := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&n)))
	if r1 == 0 {
		return 0, callErr
	}
	return int32(n), nil
}
