//go:build !linux

package watchdog

func systemResourceHealth(string, Policy) (bool, string, map[string]any) {
	return false, "LINUX_RESOURCE_PROBE_REQUIRED", map[string]any{}
}
