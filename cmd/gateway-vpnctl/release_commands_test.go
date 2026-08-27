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
		{"Gateway sign", func() int {
			return runReleaseSign([]string{"--release-dir", "C:/release", "--private-key", "C:/secure/private.pem"})
		}},
		{"VPS sign", func() int {
			return runVPSReleaseSign([]string{"--release-dir", "C:/release", "--private-key", "C:/secure/private.pem"})
		}},
		{"channel sign", func() int {
			return runChannelSign([]string{"--release-version", "1.0.0", "--source-commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--private-key", "C:/secure/private.pem", "--output-dir", "C:/release", "--artifact", "gateway=C:/release/gateway.tar.gz"})
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
