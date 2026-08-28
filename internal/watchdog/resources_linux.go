//go:build linux

package watchdog

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func systemResourceHealth(databasePath string, policy Policy) (bool, string, map[string]any) {
	details := map[string]any{}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(databasePath), &filesystem); err != nil {
		return false, "DISK_STAT_FAILED", details
	}
	available := int64(filesystem.Bavail) * int64(filesystem.Bsize)
	total := int64(filesystem.Blocks) * int64(filesystem.Bsize)
	details["disk_available_bytes"] = available
	details["disk_total_bytes"] = total
	if available < policy.MinimumDiskFreeBytes || total > 0 && available*100/total < int64(policy.MinimumDiskFreePercent) {
		return false, "DISK_PRESSURE", details
	}
	memory, err := readKeyValues("/proc/meminfo")
	if err != nil {
		return false, "MEMORY_STAT_FAILED", details
	}
	memoryAvailable, memoryTotal := memory["MemAvailable"]*1024, memory["MemTotal"]*1024
	details["memory_available_bytes"] = memoryAvailable
	details["memory_total_bytes"] = memoryTotal
	if memoryAvailable < policy.MinimumMemoryAvailableBytes || memoryTotal > 0 && memoryAvailable*100/memoryTotal < int64(policy.MinimumMemoryAvailablePercent) {
		return false, "MEMORY_PRESSURE", details
	}
	fileNR, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return false, "FD_STAT_FAILED", details
	}
	fields := strings.Fields(string(fileNR))
	if len(fields) != 3 {
		return false, "FD_STAT_INVALID", details
	}
	allocated, err1 := strconv.ParseInt(fields[0], 10, 64)
	maximum, err2 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil || maximum <= 0 {
		return false, "FD_STAT_INVALID", details
	}
	details["file_handles_allocated"] = allocated
	details["file_handles_max"] = maximum
	if allocated*100/maximum >= 90 {
		return false, "FD_PRESSURE", details
	}
	return true, "", details
}

func readKeyValues(filename string) (map[string]int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := map[string]int64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr == nil {
			values[strings.TrimSuffix(fields[0], ":")] = value
		}
	}
	return values, scanner.Err()
}
