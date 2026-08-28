package hilink

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkplan"
)

type fakeLeaseReader struct{ leases map[string]Lease }

func (reader fakeLeaseReader) Lease(_ context.Context, interfaceName string) (Lease, error) {
	lease, ok := reader.leases[interfaceName]
	if !ok {
		return Lease{}, errors.New("lease unavailable")
	}
	return lease, nil
}

type fakeRoutes struct {
	plans    []networkplan.Plan
	removed  []string
	onApply  func(networkplan.Plan) error
	onRemove func(modem.Modem) error
}

func (routes *fakeRoutes) ApplyPlan(_ context.Context, plan networkplan.Plan) error {
	routes.plans = append(routes.plans, plan)
	if routes.onApply != nil {
		return routes.onApply(plan)
	}
	return nil
}

func (routes *fakeRoutes) RemoveModem(_ context.Context, record modem.Modem) error {
	routes.removed = append(routes.removed, record.ID)
	if routes.onRemove != nil {
		return routes.onRemove(record)
	}
	return nil
}

func TestManagerPersistsObservedStateBeforeAuthoritativeRouteSync(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := modem.NewRepository(database, 1101, 0x1101)
	salt := []byte(strings.Repeat("s", 32))
	device := RawDevice{InterfaceName: "enx1", VendorID: "12d1", ProductID: "14dc", USBSerial: "one", Carrier: true}
	if _, err := repository.Adopt(ctx, modem.AdoptInput{ID: "m-one", Name: "one", IdentityKind: "usb_serial_hash", IdentityHash: saltedIdentityHash(salt, "usb_serial_hash", device.USBSerial)}); err != nil {
		t.Fatal(err)
	}
	lease, err := ParseNetworkdLease([]byte("ADDRESS=192.168.8.10\nPREFIXLEN=24\nROUTER=192.168.8.1\n"), "enx1", 1500)
	if err != nil {
		t.Fatal(err)
	}
	readyObserved, offlineObserved := false, false
	routes := &fakeRoutes{
		onApply: func(networkplan.Plan) error {
			record, err := repository.Get(ctx, "m-one")
			readyObserved = err == nil && record.State == modem.StateReady
			return err
		},
		onRemove: func(modem.Modem) error {
			record, err := repository.Get(ctx, "m-one")
			offlineObserved = err == nil && record.State == modem.StateConfiguredOffline
			return err
		},
	}
	manager := Manager{Probe: fakeProbe{devices: []RawDevice{device}}, LeaseReader: fakeLeaseReader{leases: map[string]Lease{"enx1": lease}}, Routes: routes, Modems: repository, IdentitySalt: salt, LANPrefix: "192.168.200.0/24", WireGuardPrefix: "10.80.0.0/24"}
	if _, err := manager.Reconcile(ctx); err != nil || !readyObserved {
		t.Fatalf("ready reconcile/state = %v/%v", err, readyObserved)
	}
	manager.Probe = fakeProbe{}
	offlineResult, err := manager.Reconcile(ctx)
	if err != nil || !offlineObserved || offlineResult.PhysicalFailures["m-one"] != PhysicalFailureDeviceAbsent {
		t.Fatalf("offline reconcile/state = %v/%v", err, offlineObserved)
	}
	stillOffline, err := manager.Reconcile(ctx)
	if err != nil || stillOffline.PhysicalFailures["m-one"] != PhysicalFailureDeviceAbsent {
		t.Fatalf("persistent absent observation = %+v, %v", stillOffline, err)
	}
}

func TestManagerQuarantinesConflictingModemsWithoutDroppingIndependentOne(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := modem.NewRepository(database, 1101, 0x1101)
	salt := []byte(strings.Repeat("s", 32))
	raw := []RawDevice{{InterfaceName: "enx1", VendorID: "12d1", ProductID: "14dc", USBSerial: "one", Carrier: true}, {InterfaceName: "enx2", VendorID: "12d1", ProductID: "14dc", USBSerial: "two", Carrier: true}, {InterfaceName: "enx3", VendorID: "12d1", ProductID: "14dc", USBSerial: "three", Carrier: true}}
	for _, device := range raw {
		identity := saltedIdentityHash(salt, "usb_serial_hash", device.USBSerial)
		if _, err := repository.Adopt(ctx, modem.AdoptInput{ID: "m-" + device.USBSerial, Name: device.USBSerial, IdentityKind: "usb_serial_hash", IdentityHash: identity}); err != nil {
			t.Fatal(err)
		}
	}
	lease := func(interfaceName, content string) Lease {
		result, err := ParseNetworkdLease([]byte(content), interfaceName, 1500)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	routes := &fakeRoutes{}
	manager := Manager{
		Probe: fakeProbe{devices: raw},
		LeaseReader: fakeLeaseReader{leases: map[string]Lease{
			"enx1": lease("enx1", "ADDRESS=192.168.8.10\nPREFIXLEN=24\nROUTER=192.168.8.1\n"),
			"enx2": lease("enx2", "ADDRESS=192.168.8.20\nPREFIXLEN=24\nROUTER=192.168.8.1\n"),
			"enx3": lease("enx3", "ADDRESS=192.168.9.10\nPREFIXLEN=24\nROUTER=192.168.9.1\n"),
		}},
		Routes: routes, Modems: repository, IdentitySalt: salt,
		LANPrefix: "192.168.200.0/24", WireGuardPrefix: "10.80.0.0/24",
	}
	result, err := manager.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ConflictModems) != 2 || len(result.ReadyModems) != 1 || result.ReadyModems[0] != "m-three" || len(routes.plans) != 1 || len(routes.plans[0].Rules) != 1 {
		t.Fatalf("cycle result = %+v, plans=%+v", result, routes.plans)
	}
	for _, id := range []string{"m-one", "m-two"} {
		record, _ := repository.Get(ctx, id)
		if record.State != modem.StateSubnetConflict {
			t.Errorf("%s state = %s", id, record.State)
		}
	}
}
