package fixtures

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/bypass"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/networkplan"
	"gateway-vpn/internal/subscription"
)

func TestRequiredFixtureInventory(t *testing.T) {
	paths := []string{
		"mihomo/minimal-valid.yaml", "mihomo/invalid.yaml", "mihomo/expected-api-schema.json",
		"subscriptions/clash-minimal.yaml", "subscriptions/uri-list.txt", "subscriptions/base64-subscription.txt",
		"subscriptions/node-names-bypass-cyrillic.yaml", "subscriptions/node-names-lte-whitelist.yaml", "subscriptions/node-names-no-match.yaml", "subscriptions/malicious-and-oversized-cases",
		"bypass-targets/required-and-optional.json", "bypass-targets/target-outage-matrix.json", "bypass-targets/invalid-and-ssrf-cases.json",
		"modems/two-distinct-subnets.json", "modems/identity-replug-events.json", "modems/ambiguous-identity.json", "modems/subnet-conflict.json",
		"path-matrix/mixed-qualified-failed.json", "path-matrix/active-modem-unplug.json", "path-matrix/reconnect-delayed-failback.json", "path-matrix/large-scheduler-matrix.json",
		"nftables/boot-blocked.nft", "nftables/two-modems-policy-routing.nft", "nftables/path-active-modem-a.nft", "nftables/path-active-modem-b.nft", "nftables/path-direct-modem-a.nft", "nftables/expected-ruleset.json", "nftables/validate-kernel.sh", "nftables/validate-traffic-reader.sh",
		"netns/topology.md", "netns/addresses.env",
		"database/clean-v1.db", "database/wal-truncated-recoverable", "database/wal-invalid-checksum-recoverable", "database/page-corrupted.db", "database/partial-main-write.db",
	}
	for _, name := range paths {
		if _, err := os.Lstat(filepath.Clean(name)); err != nil {
			t.Errorf("required fixture %s: %v", name, err)
		}
	}
}

func TestSubscriptionFixturesExerciseFormatsMatchersAndRejections(t *testing.T) {
	valid := []string{
		"subscriptions/clash-minimal.yaml", "subscriptions/uri-list.txt", "subscriptions/base64-subscription.txt",
		"subscriptions/node-names-bypass-cyrillic.yaml", "subscriptions/node-names-lte-whitelist.yaml", "subscriptions/node-names-no-match.yaml",
	}
	for _, name := range valid {
		t.Run(filepath.Base(name), func(t *testing.T) {
			result, err := subscription.Import(mustRead(t, name))
			if err != nil || len(result.Nodes) == 0 {
				t.Fatalf("Import(%s) = %+v, %v", name, result, err)
			}
			classified, err := subscription.Classify(result.Nodes, subscription.DefaultMatchers(), nil)
			if err != nil || len(classified) != len(result.Nodes) {
				t.Fatalf("Classify(%s) = %+v, %v", name, classified, err)
			}
			if strings.Contains(name, "no-match") {
				for _, item := range classified {
					if !item.Candidate || item.CandidateSource != "NO_NAME_MATCH_FALLBACK_ALL" {
						t.Fatalf("no-match fallback = %+v", classified)
					}
				}
			} else if strings.Contains(name, "node-names-") {
				matched, filtered := 0, 0
				for _, item := range classified {
					if item.CandidateSource == "NAME_MATCH" {
						matched++
					}
					if item.CandidateSource == "NAME_FILTERED" {
						filtered++
					}
				}
				if matched == 0 || filtered == 0 {
					t.Fatalf("named candidate fixture did not separate pools: %+v", classified)
				}
			}
		})
	}
	entries, err := os.ReadDir("subscriptions/malicious-and-oversized-cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if _, err := subscription.Import(mustRead(t, filepath.Join("subscriptions/malicious-and-oversized-cases", entry.Name()))); err == nil {
			t.Fatalf("malicious fixture %s was accepted", entry.Name())
		}
	}
	if _, err := subscription.Import(bytes.Repeat([]byte{'x'}, subscription.MaxPayloadBytes+1)); err == nil {
		t.Fatal("generated oversized fixture was accepted")
	}
	if _, err := subscription.Import([]byte{'p', 'r', 'o', 'x', 'i', 'e', 's', ':', '\n', 0xff}); err == nil {
		t.Fatal("generated invalid UTF-8 fixture was accepted")
	}
}

func TestBypassTargetFixturesUseProductionValidation(t *testing.T) {
	var valid struct {
		FormatVersion int `json:"format_version"`
		Targets       []struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			Kind           string `json:"kind"`
			Value          string `json:"value"`
			Required       bool   `json:"required"`
			TimeoutSeconds int    `json:"timeout_seconds"`
			SuccessMode    string `json:"success_mode"`
			ExpectedStatus string `json:"expected_status"`
			ExpectedBody   string `json:"expected_body_substring"`
		} `json:"targets"`
	}
	decodeStrict(t, "bypass-targets/required-and-optional.json", &valid)
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := bypass.NewRepository(database)
	for _, target := range valid.Targets {
		_, err := repository.Create(ctx, bypass.CreateInput{
			ID: target.ID, Name: target.Name, Kind: target.Kind, Value: target.Value, Required: target.Required,
			Timeout: time.Duration(target.TimeoutSeconds) * time.Second, SuccessMode: target.SuccessMode,
			ExpectedStatus: target.ExpectedStatus, ExpectedBodySubstring: target.ExpectedBody,
		})
		if err != nil {
			t.Fatalf("valid target %s: %v", target.ID, err)
		}
	}
	var invalid struct {
		FormatVersion int `json:"format_version"`
		Cases         []struct {
			Name     string `json:"name"`
			Value    string `json:"value"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	decodeStrict(t, "bypass-targets/invalid-and-ssrf-cases.json", &invalid)
	for _, item := range invalid.Cases {
		if _, err := bypass.NormalizeTarget(bypass.KindURL, item.Value); err == nil {
			t.Fatalf("invalid/SSRF fixture %s was accepted", item.Name)
		}
	}
}

func TestModemFixturesDriveNetworkPlanAndStableIdentity(t *testing.T) {
	valid := readNetworkFixture(t, "modems/two-distinct-subnets.json")
	plan, err := networkplan.Build(valid)
	if err != nil || len(plan.Routes) != 4 || len(plan.Rules) != 2 {
		t.Fatalf("two-modem plan = %+v, %v", plan, err)
	}
	if _, err := networkplan.Build(readNetworkFixture(t, "modems/subnet-conflict.json")); err == nil {
		t.Fatal("overlapping modem subnets fixture was accepted")
	}

	var replug struct {
		FormatVersion int    `json:"format_version"`
		SaltHex       string `json:"identity_salt_hex"`
		Events        []struct {
			Action        string `json:"action"`
			InterfaceName string `json:"interface_name"`
			VendorID      string `json:"vendor_id"`
			ProductID     string `json:"product_id"`
			USBSerial     string `json:"usb_serial"`
			PermanentMAC  string `json:"permanent_mac"`
			USBTopology   string `json:"usb_topology"`
		} `json:"events"`
		ExpectedSameIdentity bool `json:"expected_same_identity"`
	}
	decodeStrict(t, "modems/identity-replug-events.json", &replug)
	salt, err := hex.DecodeString(replug.SaltHex)
	if err != nil {
		t.Fatal(err)
	}
	first := replug.Events[0]
	last := replug.Events[len(replug.Events)-1]
	firstCandidates, err := hilink.Discover(context.Background(), fixtureProbe{devices: []hilink.RawDevice{{InterfaceName: first.InterfaceName, VendorID: first.VendorID, ProductID: first.ProductID, USBSerial: first.USBSerial, PermanentMAC: first.PermanentMAC, USBTopology: first.USBTopology}}}, hilink.Options{IdentitySalt: salt})
	if err != nil {
		t.Fatal(err)
	}
	lastCandidates, err := hilink.Discover(context.Background(), fixtureProbe{devices: []hilink.RawDevice{{InterfaceName: last.InterfaceName, VendorID: last.VendorID, ProductID: last.ProductID, USBSerial: last.USBSerial, PermanentMAC: last.PermanentMAC, USBTopology: last.USBTopology}}}, hilink.Options{IdentitySalt: salt})
	if err != nil || len(firstCandidates) != 1 || len(lastCandidates) != 1 || firstCandidates[0].IdentityHash != lastCandidates[0].IdentityHash {
		t.Fatalf("replug identity = %+v / %+v, %v", firstCandidates, lastCandidates, err)
	}

	var ambiguous struct {
		FormatVersion int `json:"format_version"`
		Devices       []struct {
			InterfaceName string `json:"interface_name"`
			VendorID      string `json:"vendor_id"`
			ProductID     string `json:"product_id"`
			USBSerial     string `json:"usb_serial"`
		} `json:"devices"`
		ExpectedState string `json:"expected_state"`
	}
	decodeStrict(t, "modems/ambiguous-identity.json", &ambiguous)
	devices := make([]hilink.RawDevice, 0, len(ambiguous.Devices))
	for _, device := range ambiguous.Devices {
		devices = append(devices, hilink.RawDevice{InterfaceName: device.InterfaceName, VendorID: device.VendorID, ProductID: device.ProductID, USBSerial: device.USBSerial})
	}
	candidates, err := hilink.Discover(context.Background(), fixtureProbe{devices: devices}, hilink.Options{IdentitySalt: salt})
	if err != nil {
		t.Fatal(err)
	}
	matches := hilink.MatchAdopted(candidates, nil)
	if len(matches) != 2 || matches[0].State != hilink.DiscoveryAmbiguous || matches[1].State != hilink.DiscoveryAmbiguous {
		t.Fatalf("ambiguous fixture matches = %+v", matches)
	}
}

func TestNFTFixturesMatchProductionRendererAndHashes(t *testing.T) {
	var manifest struct {
		FormatVersion int               `json:"format_version"`
		GeneratedBy   string            `json:"generated_by"`
		SHA256        map[string]string `json:"sha256"`
		Required      []string          `json:"required_markers"`
		Forbidden     []string          `json:"forbidden_markers"`
	}
	decodeStrict(t, "nftables/expected-ruleset.json", &manifest)
	if manifest.FormatVersion != 1 || len(manifest.SHA256) != 5 {
		t.Fatalf("nft manifest = %+v", manifest)
	}
	for name, expected := range manifest.SHA256 {
		content := mustRead(t, filepath.Join("nftables", name))
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != expected {
			t.Errorf("nft fixture %s hash mismatch", name)
		}
	}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt", APIPort: 8443, WireGuardListenPort: 51821})
	if err != nil {
		t.Fatal(err)
	}
	boot := string(mustRead(t, "nftables/boot-blocked.nft"))
	if boot != ruleset.Text {
		t.Fatal("boot-blocked.nft differs from production renderer")
	}
	for _, marker := range manifest.Required {
		if !strings.Contains(boot, marker) {
			t.Errorf("boot fixture missing %q", marker)
		}
	}
	for _, marker := range manifest.Forbidden {
		if strings.Contains(boot, marker) {
			t.Errorf("boot fixture contains forbidden %q", marker)
		}
	}
}

func TestDatabaseFixturesCoverMigrationWALAndMainPageCorruption(t *testing.T) {
	ctx := context.Background()
	clean, err := databasepkg.OpenImmutable(ctx, "database/clean-v1.db")
	if err != nil {
		t.Fatal(err)
	}
	version, versionErr := databasepkg.ReadSchemaVersion(ctx, clean)
	integrityErr := databasepkg.IntegrityCheck(ctx, clean)
	clean.Close()
	if versionErr != nil || integrityErr != nil || version != 1 {
		t.Fatalf("clean-v1 schema/integrity = %d, %v, %v", version, versionErr, integrityErr)
	}
	migrationPath := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(migrationPath, mustRead(t, "database/clean-v1.db"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: migrationPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, migrated); err != nil {
		migrated.Close()
		t.Fatal(err)
	}
	version, err = databasepkg.ReadSchemaVersion(ctx, migrated)
	latest, latestErr := databasepkg.LatestSchemaVersion()
	integrityErr = databasepkg.IntegrityCheck(ctx, migrated)
	migrated.Close()
	if err != nil || latestErr != nil || integrityErr != nil || version != latest {
		t.Fatalf("clean-v1 migration = version %d/%d, %v, %v, %v", version, latest, err, latestErr, integrityErr)
	}
	for _, name := range []string{"database/page-corrupted.db", "database/partial-main-write.db"} {
		database, err := databasepkg.OpenImmutable(ctx, name)
		if err == nil {
			err = databasepkg.IntegrityCheck(ctx, database)
			database.Close()
		}
		if err == nil {
			t.Errorf("corrupt main database fixture %s passed integrity", name)
		}
	}
	for _, name := range []string{"database/wal-truncated-recoverable", "database/wal-invalid-checksum-recoverable"} {
		target := t.TempDir()
		for _, file := range []string{"state.db", "state.db-wal"} {
			if err := os.WriteFile(filepath.Join(target, file), mustRead(t, filepath.Join(name, file)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		database, err := databasepkg.OpenReadOnly(ctx, filepath.Join(target, "state.db"))
		if err != nil {
			t.Fatalf("open recoverable %s: %v", name, err)
		}
		integrityErr := databasepkg.IntegrityCheck(ctx, database)
		var events int
		countErr := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type LIKE 'WAL_FIXTURE_%'").Scan(&events)
		database.Close()
		if integrityErr != nil || countErr != nil || events < 1 || events > 3 {
			t.Fatalf("recoverable %s integrity/events = %v, %v, %d", name, integrityErr, countErr, events)
		}
	}
}

func readNetworkFixture(t *testing.T, name string) networkplan.Input {
	t.Helper()
	var fixture struct {
		FormatVersion   int    `json:"format_version"`
		LANPrefix       string `json:"lan_prefix"`
		WireGuardPrefix string `json:"wireguard_prefix"`
		Modems          []struct {
			ID               string `json:"id"`
			Priority         int64  `json:"priority"`
			InterfaceName    string `json:"interface_name"`
			ManagementPrefix string `json:"management_prefix"`
			Gateway          string `json:"gateway"`
			RoutingTableID   uint32 `json:"routing_table_id"`
			Fwmark           uint32 `json:"fwmark"`
		} `json:"modems"`
		Expected string `json:"expected"`
	}
	decodeStrict(t, name, &fixture)
	input := networkplan.Input{LANPrefix: fixture.LANPrefix, WireGuardPrefix: fixture.WireGuardPrefix}
	for _, modem := range fixture.Modems {
		input.Modems = append(input.Modems, networkplan.ModemInput{ID: modem.ID, Priority: modem.Priority, InterfaceName: modem.InterfaceName, ManagementPrefix: modem.ManagementPrefix, Gateway: modem.Gateway, RoutingTableID: modem.RoutingTableID, Fwmark: modem.Fwmark})
	}
	return input
}

type fixtureProbe struct{ devices []hilink.RawDevice }

func (probe fixtureProbe) ListUSBNetworkDevices(context.Context) ([]hilink.RawDevice, error) {
	return append([]hilink.RawDevice(nil), probe.devices...), nil
}

func decodeStrict(t *testing.T, name string, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(mustRead(t, name)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		t.Fatalf("%s contains a second JSON value", name)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}
