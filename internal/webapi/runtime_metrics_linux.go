//go:build linux

package webapi

import (
	"os"
	"strconv"
	"strings"
)

func readProcessMetrics() processMetrics {
	var result processMetrics
	if content, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(content))
		if len(fields) >= 2 {
			if residentPages, parseErr := strconv.ParseUint(fields[1], 10, 64); parseErr == nil {
				pageSize := uint64(os.Getpagesize())
				if pageSize != 0 && residentPages <= ^uint64(0)/pageSize {
					value := residentPages * pageSize
					result.RSSBytes = &value
				}
			}
		}
	}
	if directory, err := os.Open("/proc/self/fd"); err == nil {
		if names, readErr := directory.Readdirnames(-1); readErr == nil {
			// The descriptor used to enumerate /proc/self/fd is present in its
			// own snapshot and is not part of the steady-state process count.
			count := len(names)
			if count > 0 {
				count--
			}
			value := uint64(count)
			result.OpenFileDescriptors = &value
		}
		_ = directory.Close()
	}
	return result
}
