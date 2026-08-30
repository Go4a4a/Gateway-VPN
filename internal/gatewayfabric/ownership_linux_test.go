//go:build linux

package gatewayfabric

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayApplierRequiresExactRootOwnershipBeforeHostMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact root ownership assertions require a privileged Linux test")
	}

	cases := []struct {
		name   string
		mutate func(t *testing.T, fixture gatewayApplierFixture)
		want   string
	}{
		{
			name: "transaction directory mode",
			mutate: func(t *testing.T, fixture gatewayApplierFixture) {
				t.Helper()
				if err := os.Chmod(fixture.applier.Paths.TransactionRoot, 0o750); err != nil {
					t.Fatal(err)
				}
			},
			want: "transaction directory is unsafe",
		},
		{
			name: "secret directory mode",
			mutate: func(t *testing.T, fixture gatewayApplierFixture) {
				t.Helper()
				if err := os.Chmod(fixture.applier.Paths.SecretRoot, 0o750); err != nil {
					t.Fatal(err)
				}
			},
			want: "root-owned directory is unsafe",
		},
		{
			name: "transaction directory owner",
			mutate: func(t *testing.T, fixture gatewayApplierFixture) {
				t.Helper()
				if err := os.Chown(fixture.applier.Paths.TransactionRoot, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			},
			want: "root-owned directory is unsafe",
		},
		{
			name: "secret directory owner",
			mutate: func(t *testing.T, fixture gatewayApplierFixture) {
				t.Helper()
				if err := os.Chown(fixture.applier.Paths.SecretRoot, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			},
			want: "root-owned directory is unsafe",
		},
		{
			name: "private key mode",
			mutate: func(t *testing.T, fixture gatewayApplierFixture) {
				t.Helper()
				if err := os.Chmod(filepath.Join(fixture.applier.Paths.SecretRoot, "link-a.key"), 0o640); err != nil {
					t.Fatal(err)
				}
			},
			want: "private key ownership is unsafe",
		},
		{
			name: "private key owner",
			mutate: func(t *testing.T, fixture gatewayApplierFixture) {
				t.Helper()
				if err := os.Chown(filepath.Join(fixture.applier.Paths.SecretRoot, "link-a.key"), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			},
			want: "private key ownership is unsafe",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayApplierFixture(t)
			fixture.applier.Paths.RequireRootOwnership = true
			test.mutate(t, fixture)

			err := fixture.applier.Apply(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe ownership result = %v, want %q", err, test.want)
			}
			if len(fixture.executor.requests) != 0 {
				t.Fatalf("unsafe ownership reached host mutation: %+v", fixture.executor.requests)
			}
		})
	}
}

func TestGatewayApplierAcceptsExactRootOwnershipAndDirectSecretFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact root ownership assertions require a privileged Linux test")
	}
	fixture := newGatewayApplierFixture(t)
	fixture.applier.Paths.RequireRootOwnership = true

	if err := fixture.applier.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, exists := fixture.executor.interfaces["gvm1"]; !exists {
		t.Fatal("exact root ownership did not reach the expected host projection")
	}

	if _, err := fixture.applier.secretPath("/var/lib/gateway-vpn/secrets/management/nested/link-a.key"); err == nil {
		t.Fatal("nested Management Fabric secret reference was accepted")
	}
}
