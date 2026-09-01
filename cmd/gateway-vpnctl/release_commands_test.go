package main

import (
	"runtime"
	"testing"
)

func TestPrivateKeyCommandsRejectNonLinuxHost(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux rejection is covered on development hosts")
	}
	cases := []struct {
		name string
		run  func() int
	}{
		{"keygen", func() int {
			return runReleaseKeygen([]string{"--private-key", "C:/secure/private.pem", "--public-key", "C:/secure/public.pem"})
		}},
		{"key verify", func() int {
			return runReleaseKeyVerify([]string{"--private-key", "C:/secure/private.pem", "--public-key", "C:/secure/public.pem"})
		}},
		{"key backup", func() int {
			return runReleaseKeyBackup([]string{"--private-key", "C:/secure/private.pem", "--public-key", "C:/secure/public.pem", "--backup-private-key", "D:/secure/private.pem", "--backup-public-key", "D:/secure/public.pem"})
		}},
		{"encrypted key create", func() int {
			return runReleaseKeyfileCreate([]string{"--key-file", "C:/secure/production.gvkey", "--passphrase-file", "C:/secure/passphrase"})
		}},
		{"encrypted key verify", func() int {
			return runReleaseKeyfileVerify([]string{"--key-file", "C:/secure/production.gvkey", "--passphrase-file", "C:/secure/passphrase"})
		}},
		{"encrypted key backup", func() int {
			return runReleaseKeyfileBackup([]string{"--key-file", "C:/secure/production.gvkey", "--backup-key-file", "D:/secure/production.gvkey", "--passphrase-file", "C:/secure/passphrase"})
		}},
		{"encrypted key unlock", func() int {
			return runReleaseKeyfileUnlock([]string{"--key-file", "C:/secure/production.gvkey", "--private-key", "C:/temporary/private.pem", "--public-key", "C:/temporary/public.pem", "--passphrase-file", "C:/secure/passphrase"})
		}},
		{"Gateway sign", func() int {
			return runReleaseSign([]string{"--release-dir", "C:/release", "--private-key", "C:/secure/private.pem"})
		}},
		{"VPS sign", func() int {
			return runVPSReleaseSign([]string{"--release-dir", "C:/release", "--private-key", "C:/secure/private.pem"})
		}},
		{"channel sign", func() int {
			return runChannelSign([]string{"--release-version", "1.0.0", "--source-commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--private-key", "C:/secure/private.pem", "--output-dir", "C:/release", "--artifact", "gateway=C:/release/gateway.tar.gz"})
		}},
		{"Mihomo channel sign", func() int {
			return runMihomoChannelSign([]string{"--channel", "stable", "--release-dir", "C:/release", "--artifact", "C:/release/gateway-vpn-gateway-1.0.1-linux-amd64.tar.gz", "--source-commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--urgency", "recommended", "--summary", "Approved Mihomo maintenance release.", "--compatible-gateway-version", "1.0.0", "--private-key", "C:/secure/private.pem", "--output-dir", "C:/release"})
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if code := item.run(); code != 1 {
				t.Fatalf("private-key command code=%d want=1", code)
			}
		})
	}
}
