//go:build !linux

package webapi

func readProcessMetrics() processMetrics {
	return processMetrics{}
}
