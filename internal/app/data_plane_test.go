package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
)

func TestInitializeDataPlaneWiresRefreshWorkerCandidateRuntimeAndTransactions(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(root, "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "mihomo-secret")
	if err := os.WriteFile(secret, []byte("test-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.System.StateDir = root
	configuration.System.Database = filepath.Join(root, "state.db")
	configuration.Mihomo.APISecretFile = secret
	broker, err := networkapply.NewBrokerClient("/run/gateway-vpn/test-broker.sock")
	if err != nil {
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	modems := modem.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	paths := pathmatrix.NewRepository(database)
	targets := bypass.NewRepository(database)
	matchers := subscription.NewMatcherRepository(database)
	components, err := initializeDataPlane(ctx, database, configuration, subscriptions, modems, paths, targets, matchers, state.NewRepository(database), broker)
	if err != nil {
		t.Fatalf("initializeDataPlane() error = %v", err)
	}
	if components.Refresh == nil || components.RefreshWorker == nil || components.Transactions == nil || components.Reconciler == nil || components.Routing == nil || components.WireGuard == nil || components.PathProbe == nil || components.HealthRunner == nil || components.DirectRunner == nil || components.ProbeScheduler == nil || components.ModemRunner == nil || components.Discoveries == nil || components.RefreshWorker.Coordinator != components.Refresh || components.HealthRunner.Runtime != components.PathProbe || components.HealthRunner.Paths != paths {
		t.Fatalf("data-plane components = %+v", components)
	}
}

func TestReadBoundedSecretRejectsSymlinkAndEmbeddedNewline(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("one\ntwo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedSecret(secret, 1024); err == nil {
		t.Fatal("readBoundedSecret(embedded newline) error = nil")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readBoundedSecret(link, 1024); err == nil {
		t.Fatal("readBoundedSecret(symlink) error = nil")
	}
}
