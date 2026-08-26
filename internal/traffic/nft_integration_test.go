//go:build linux

package traffic

import (
	"context"
	"os"
	"testing"

	"gateway-vpn/internal/platformexec"
)

// The acceptance harness runs this inside a disposable privileged network
// namespace after creating the exact owned table and named counters.
func TestNFTReaderAgainstKernelNFTables(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_NFT_TRAFFIC_INTEGRATION") != "1" {
		t.Skip("kernel nftables traffic integration is not enabled")
	}
	snapshot, err := (NFTReader{Executor: platformexec.OSExecutor{}, NFT: "/usr/sbin/nft"}).ReadTrafficCounters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UploadBytes != 12345 || snapshot.DownloadBytes != 67890 || snapshot.ServiceUploadBytes != 111 || snapshot.ServiceDownloadBytes != 222 || snapshot.FirewallGeneration == 0 || !validBootID(snapshot.BootID) {
		t.Fatalf("kernel nftables snapshot = %+v", snapshot)
	}
}
