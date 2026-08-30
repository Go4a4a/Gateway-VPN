package vpsfabric

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

const (
	journalVersion  = 1
	statePrepared   = "PREPARED"
	stateApplying   = "APPLYING"
	stateCommitted  = "COMMITTED"
	stateRolledBack = "ROLLED_BACK"
	restorePrepared = "PREPARED"
	restoreActive   = "ACTIVE"
)

var (
	restoreIDPattern    = regexp.MustCompile(`^vps-restore-[a-f0-9]{32}$`)
	relayCounterPattern = regexp.MustCompile(`counter packets ([0-9]+) bytes ([0-9]+).*comment "gateway-vpn administrator relay (?:rate limit|dnat|ingress|return|snat) ([A-Za-z0-9_.:-]{1,128})"`)
)

// WatchdogTelemetry is a bounded, secret-free projection for the VPS Hub
// status file. It never authorizes reconciliation and contains no addresses,
// peer keys, paths or individual relay identifiers.
type WatchdogTelemetry struct {
	DesiredGeneration int64
	AppliedGeneration int64
	RelayCount        int
	RelayRuleCount    int
	RelayPackets      uint64
	RelayBytes        uint64
}

type Paths struct {
	TransactionRoot string
	WireGuardConfig string
	FirewallConfig  string
	PrivateKey      string
	IP              string
	NFT             string
	WG              string
	Systemctl       string
}

func DefaultPaths(privateKey string) Paths {
	return Paths{
		TransactionRoot: "/var/lib/gateway-vpn-vps-privileged/fabric",
		WireGuardConfig: "/etc/wireguard/wg-mgmt.conf",
		FirewallConfig:  "/etc/gateway-vpn-vps/firewall.nft",
		PrivateKey:      privateKey,
		IP:              "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", Systemctl: "/usr/bin/systemctl",
	}
}

type Applier struct {
	Repository vpsagent.HubRepository
	Executor   platformexec.Executor
	Paths      Paths
	Now        func() time.Time
}

type Receipt struct {
	FormatVersion int                  `json:"format_version"`
	Generation    int64                `json:"generation"`
	PlanSHA256    string               `json:"plan_sha256"`
	AppliedAt     string               `json:"applied_at"`
	Plan          vpsagent.VPSHostPlan `json:"plan"`
}

type transactionJournal struct {
	FormatVersion      int                  `json:"format_version"`
	State              string               `json:"state"`
	PreviousGeneration int64                `json:"previous_generation"`
	TargetGeneration   int64                `json:"target_generation"`
	PreviousReceipt    *Receipt             `json:"previous_receipt,omitempty"`
	PreviousRoutes     []string             `json:"previous_routes"`
	RestoreMarker      *RestoreMarker       `json:"restore_marker,omitempty"`
	TargetPlan         vpsagent.VPSHostPlan `json:"target_plan"`
	StartedAt          string               `json:"started_at"`
	UpdatedAt          string               `json:"updated_at"`
}

// RestoreMarker is a root-owned, single-purpose authorization allowing one
// post-restore reconciliation when the portable database generation cannot
// legitimately match the host receipt that existed before restore.
type RestoreMarker struct {
	FormatVersion      int    `json:"format_version"`
	State              string `json:"state"`
	RestoreID          string `json:"restore_id"`
	PreviousGeneration int64  `json:"previous_generation"`
	PreviousPlanSHA256 string `json:"previous_plan_sha256"`
	TargetGeneration   int64  `json:"target_generation,omitempty"`
	TargetVPSID        string `json:"target_vps_id,omitempty"`
	TargetPublicKey    string `json:"target_public_key,omitempty"`
	PreparedAt         string `json:"prepared_at"`
	UpdatedAt          string `json:"updated_at"`
}

// PrepareRestore writes the root-owned authorization before the portable
// restore can replace the agent database. Repeating the same restore is
// idempotent; another restore or a pending fabric generation is rejected.
func (applier *Applier) PrepareRestore(ctx context.Context, restoreID string) error {
	if err := applier.validate(); err != nil {
		return err
	}
	if !restoreIDPattern.MatchString(restoreID) || exists(applier.journalPath()) {
		return errors.New("VPS restore cannot prepare fabric reconciliation")
	}
	receipt, exists, err := applier.readReceipt()
	if err != nil || !exists {
		return errors.New("VPS fabric receipt is required before restore")
	}
	desired, applied, err := applier.Repository.FabricGenerations(ctx)
	if err != nil || desired != applied || receipt.Generation != applied {
		return errors.New("VPS fabric must be fully applied before restore")
	}
	current, hasCurrent, err := applier.readRestoreMarker()
	if err != nil {
		return err
	}
	if hasCurrent {
		if current.RestoreID == restoreID && current.PreviousGeneration == receipt.Generation && current.PreviousPlanSHA256 == receipt.PlanSHA256 {
			return nil
		}
		return errors.New("another VPS restore reconciliation is pending")
	}
	now := applier.now().Format(time.RFC3339Nano)
	return applier.writeRestoreMarker(RestoreMarker{
		FormatVersion: journalVersion, State: restorePrepared, RestoreID: restoreID,
		PreviousGeneration: receipt.Generation, PreviousPlanSHA256: receipt.PlanSHA256,
		PreparedAt: now, UpdatedAt: now,
	})
}

// ResetAfterRestore converts a prepared authorization into the one active
// generation mismatch accepted by Apply. Calling it after a safely rolled-back
// restore is harmless: the current desired projection is simply re-applied.
func (applier *Applier) ResetAfterRestore(ctx context.Context) (bool, error) {
	if err := applier.validate(); err != nil {
		return false, err
	}
	if exists(applier.journalPath()) {
		return false, errors.New("VPS fabric transaction must recover before restore reset")
	}
	marker, exists, err := applier.readRestoreMarker()
	if err != nil || !exists {
		return false, err
	}
	receipt, hasReceipt, err := applier.readReceipt()
	if err != nil || !hasReceipt || receipt.Generation != marker.PreviousGeneration || receipt.PlanSHA256 != marker.PreviousPlanSHA256 {
		return false, errors.New("VPS restore authorization no longer matches the previous host receipt")
	}
	target, err := applier.Repository.RenderHostPlan(ctx)
	if err != nil {
		return false, err
	}
	identity, err := vpsagent.ReadIdentity(ctx, applier.Repository.Database)
	if err != nil {
		return false, err
	}
	if marker.State == restoreActive && (identity.VPSID != marker.TargetVPSID || identity.PublicKey != marker.TargetPublicKey || target.Generation < marker.TargetGeneration) {
		return false, errors.New("active VPS restore reconciliation identity or generation changed unexpectedly")
	}
	if err := applier.Repository.RestoreHostPlanAppliedGeneration(ctx, 0, applier.now()); err != nil {
		return false, err
	}
	marker.State = restoreActive
	marker.TargetGeneration = target.Generation
	marker.TargetVPSID = identity.VPSID
	marker.TargetPublicKey = identity.PublicKey
	marker.UpdatedAt = applier.now().Format(time.RFC3339Nano)
	if err := applier.writeRestoreMarker(marker); err != nil {
		return false, err
	}
	return true, nil
}

func (applier *Applier) RestoreReconciliationPending() (bool, error) {
	if err := applier.validate(); err != nil {
		return false, err
	}
	_, exists, err := applier.readRestoreMarker()
	return exists, err
}

// NeedsApply performs a read-only comparison between the authenticated desired
// projection, the root receipt, persistent files and current kernel state.
// true means the fixed fabric service may safely reconcile; receipt/database
// inconsistencies remain hard errors and are never auto-authorized.
func (applier *Applier) NeedsApply(ctx context.Context) (bool, string, error) {
	if err := applier.validate(); err != nil {
		return false, "VALIDATION_FAILED", err
	}
	if exists(applier.journalPath()) {
		return true, "TRANSACTION_RECOVERY_REQUIRED", nil
	}
	if marker, exists, err := applier.readRestoreMarker(); err != nil {
		return false, "RESTORE_MARKER_INVALID", err
	} else if exists {
		return true, "RESTORE_" + marker.State, nil
	}
	target, err := applier.Repository.RenderHostPlan(ctx)
	if err != nil {
		return false, "DESIRED_STATE_INVALID", err
	}
	desired, applied, err := applier.Repository.FabricGenerations(ctx)
	if err != nil || desired != target.Generation {
		return false, "GENERATION_INVALID", errors.New("VPS fabric generation changed during watchdog check")
	}
	receipt, hasReceipt, err := applier.readReceipt()
	if err != nil {
		return false, "RECEIPT_INVALID", err
	}
	if !hasReceipt {
		if applied == 0 || applied == desired {
			return true, "BOOTSTRAP_RECEIPT_MISSING", nil
		}
		return false, "RECEIPT_MISSING", errors.New("VPS fabric receipt is missing for an intermediate applied generation")
	}
	if receipt.Generation != applied || receipt.PlanSHA256 != planDigest(receipt.Plan) {
		return false, "RECEIPT_GENERATION_MISMATCH", errors.New("VPS fabric receipt and database applied generation differ")
	}
	if desired != applied || receipt.PlanSHA256 != planDigest(target) {
		return true, "DESIRED_GENERATION_PENDING", nil
	}
	privateKey, err := readProtected(applier.Paths.PrivateKey, 256)
	if err != nil {
		return false, "PRIVATE_KEY_UNAVAILABLE", err
	}
	defer func() {
		for index := range privateKey {
			privateKey[index] = 0
		}
	}()
	wireGuard, err := RenderWireGuard(target, string(privateKey))
	if err != nil {
		return false, "WIREGUARD_RENDER_FAILED", err
	}
	firewall, err := RenderFirewall(target)
	if err != nil {
		return false, "FIREWALL_RENDER_FAILED", err
	}
	currentWG, wgErr := readProtected(applier.Paths.WireGuardConfig, 1<<20)
	currentFirewall, firewallErr := readProtected(applier.Paths.FirewallConfig, 1<<20)
	if wgErr != nil || firewallErr != nil || !bytes.Equal(currentWG, wireGuard) || !bytes.Equal(currentFirewall, firewall) {
		return true, "PERSISTENT_PROJECTION_DRIFT", nil
	}
	routes, err := routeDestinations(target)
	if err != nil {
		return false, "ROUTE_RENDER_FAILED", err
	}
	if err := applier.verifyRuntime(ctx, target, routes); err != nil {
		return true, "RUNTIME_PROJECTION_DRIFT", nil
	}
	return false, "HEALTHY", nil
}

// ReadWatchdogTelemetry verifies that every configured relay has exactly five
// owned nftables rules and aggregates their counters without exposing tuples.
func (applier *Applier) ReadWatchdogTelemetry(ctx context.Context) (WatchdogTelemetry, error) {
	var telemetry WatchdogTelemetry
	if err := applier.validate(); err != nil {
		return telemetry, err
	}
	plan, err := applier.Repository.RenderHostPlan(ctx)
	if err != nil {
		return telemetry, err
	}
	telemetry.DesiredGeneration, telemetry.AppliedGeneration, err = applier.Repository.FabricGenerations(ctx)
	if err != nil || telemetry.DesiredGeneration != plan.Generation {
		return telemetry, errors.New("VPS watchdog telemetry generation is invalid")
	}
	telemetry.RelayCount = len(plan.AdminRelays)
	result, err := applier.Executor.Run(ctx, platformexec.Request{
		Executable: applier.Paths.NFT, Arguments: []string{"list", "table", "inet", "gateway_vpn_vps"}, MaxOutputBytes: 1 << 20,
	})
	if err != nil {
		return telemetry, errors.New("read VPS relay counters failed")
	}
	expected := make([]string, 0, len(plan.AdminRelays))
	for _, relay := range plan.AdminRelays {
		expected = append(expected, relay.ID)
	}
	telemetry.RelayRuleCount, telemetry.RelayPackets, telemetry.RelayBytes, err = parseRelayCounters(result.Stdout, expected)
	if err != nil {
		return telemetry, err
	}
	return telemetry, nil
}

func parseRelayCounters(output string, expectedIDs []string) (int, uint64, uint64, error) {
	expected := make(map[string]int, len(expectedIDs))
	for _, id := range expectedIDs {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, " /\\\x00\r\n\t") {
			return 0, 0, 0, errors.New("VPS relay telemetry inventory is invalid")
		}
		if _, duplicate := expected[id]; duplicate {
			return 0, 0, 0, errors.New("VPS relay telemetry inventory is duplicated")
		}
		expected[id] = 0
	}
	var ruleCount int
	var packetTotal, byteTotal uint64
	for _, match := range relayCounterPattern.FindAllStringSubmatch(output, -1) {
		if len(match) != 4 {
			return 0, 0, 0, errors.New("VPS relay counter output is invalid")
		}
		if _, exists := expected[match[3]]; !exists {
			return 0, 0, 0, errors.New("VPS relay counter escaped desired inventory")
		}
		packets, packetErr := strconv.ParseUint(match[1], 10, 64)
		bytes, byteErr := strconv.ParseUint(match[2], 10, 64)
		if packetErr != nil || byteErr != nil || expected[match[3]] >= 5 {
			return 0, 0, 0, errors.New("VPS relay counter value is invalid")
		}
		expected[match[3]]++
		ruleCount++
		packetTotal += packets
		byteTotal += bytes
	}
	for _, count := range expected {
		if count != 5 {
			return 0, 0, 0, errors.New("VPS relay rule inventory is incomplete")
		}
	}
	return ruleCount, packetTotal, byteTotal, nil
}

func (applier *Applier) Apply(ctx context.Context) error {
	if err := applier.validate(); err != nil {
		return err
	}
	if exists(applier.journalPath()) {
		return errors.New("interrupted VPS fabric transaction requires recovery")
	}
	target, err := applier.Repository.RenderHostPlan(ctx)
	if err != nil {
		return err
	}
	desired, applied, err := applier.Repository.FabricGenerations(ctx)
	if err != nil || target.Generation != desired {
		return errors.New("VPS fabric generation changed before apply")
	}
	previous, hasReceipt, err := applier.readReceipt()
	if err != nil {
		return err
	}
	restoreMarker, hasRestoreMarker, err := applier.readRestoreMarker()
	if err != nil {
		return err
	}
	if hasRestoreMarker {
		if !hasReceipt || restoreMarker.State != restoreActive || applied != 0 || restoreMarker.PreviousGeneration != previous.Generation || restoreMarker.PreviousPlanSHA256 != previous.PlanSHA256 || target.Generation < restoreMarker.TargetGeneration {
			return errors.New("VPS post-restore fabric authorization does not match current state")
		}
		identity, identityErr := vpsagent.ReadIdentity(ctx, applier.Repository.Database)
		if identityErr != nil || identity.VPSID != restoreMarker.TargetVPSID || identity.PublicKey != restoreMarker.TargetPublicKey {
			return errors.New("VPS post-restore identity changed before reconciliation")
		}
	} else if hasReceipt && previous.Generation != applied {
		return errors.New("VPS fabric receipt and database applied generation differ")
	} else if !hasReceipt && applied != 0 && applied != desired {
		return errors.New("VPS fabric applied receipt is missing")
	}
	privateKey, err := readProtected(applier.Paths.PrivateKey, 256)
	if err != nil {
		return err
	}
	defer func() {
		for index := range privateKey {
			privateKey[index] = 0
		}
	}()
	identity, err := vpsagent.ReadIdentity(ctx, applier.Repository.Database)
	if err != nil {
		return err
	}
	if public, keyErr := wgingress.PublicKey(strings.TrimSpace(string(privateKey))); keyErr != nil || public != identity.PublicKey {
		return errors.New("VPS fabric private key does not match immutable identity")
	}
	wireGuard, err := RenderWireGuard(target, string(privateKey))
	if err != nil {
		return err
	}
	firewall, err := RenderFirewall(target)
	if err != nil {
		return err
	}
	if _, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.NFT, Arguments: []string{"--check", "--file", "-"}, Stdin: firewall, MaxOutputBytes: 1 << 20}); err != nil {
		return errors.New("candidate VPS fabric firewall failed nft validation")
	}
	previousRoutes, err := applier.readOwnedRoutes(ctx)
	if err != nil {
		return err
	}
	if err := applier.snapshotFiles(); err != nil {
		return err
	}
	var previousReceipt *Receipt
	if hasReceipt {
		copy := previous
		previousReceipt = &copy
	}
	var journalRestoreMarker *RestoreMarker
	if hasRestoreMarker {
		copy := restoreMarker
		journalRestoreMarker = &copy
	}
	journal := transactionJournal{
		FormatVersion: journalVersion, State: statePrepared, PreviousGeneration: applied,
		TargetGeneration: target.Generation, PreviousReceipt: previousReceipt, PreviousRoutes: previousRoutes,
		RestoreMarker: journalRestoreMarker, TargetPlan: target,
		StartedAt: applier.now().Format(time.RFC3339Nano), UpdatedAt: applier.now().Format(time.RFC3339Nano),
	}
	if err := applier.writeJournal(journal); err != nil {
		return err
	}
	journal.State, journal.UpdatedAt = stateApplying, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return err
	}
	if err := atomicWrite(applier.Paths.WireGuardConfig, wireGuard, 0o600); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	if err := atomicWrite(applier.Paths.FirewallConfig, firewall, 0o640); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	if err := applier.applyRuntime(ctx, target, previousRoutes, firewall); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	if err := applier.Repository.MarkHostPlanApplied(ctx, target.Generation, applier.now()); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	receipt := Receipt{FormatVersion: journalVersion, Generation: target.Generation, Plan: target, AppliedAt: applier.now().Format(time.RFC3339Nano)}
	if err := applier.writeReceipt(receipt); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	if hasRestoreMarker {
		if err := removeRegular(applier.restoreMarkerPath()); err != nil {
			return applier.rollback(ctx, journal, err)
		}
	}
	journal.State, journal.UpdatedAt = stateCommitted, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	return applier.cleanupTransaction()
}

func (applier *Applier) Recover(ctx context.Context) (bool, error) {
	if err := applier.validate(); err != nil {
		return false, err
	}
	journal, exists, err := applier.readJournal()
	if err != nil || !exists {
		return false, err
	}
	if journal.State == stateCommitted {
		if journal.RestoreMarker != nil {
			if err := removeRegular(applier.restoreMarkerPath()); err != nil {
				return false, err
			}
		}
		return true, applier.cleanupTransaction()
	}
	if journal.State != statePrepared && journal.State != stateApplying && journal.State != stateRolledBack {
		return false, errors.New("VPS fabric journal has an unsupported recovery state")
	}
	if err := applier.restoreSnapshotFiles(); err != nil {
		return false, err
	}
	oldFirewall, err := readProtected(applier.snapshotFirewallPath(), 1<<20)
	if err != nil {
		return false, err
	}
	if err := applier.restoreRuntime(ctx, journal.PreviousRoutes, oldFirewall); err != nil {
		return false, err
	}
	if err := applier.Repository.RestoreHostPlanAppliedGeneration(ctx, journal.PreviousGeneration, applier.now()); err != nil {
		return false, err
	}
	if journal.PreviousReceipt != nil {
		if err := applier.writeReceipt(*journal.PreviousReceipt); err != nil {
			return false, err
		}
	} else if err := removeRegular(applier.receiptPath()); err != nil {
		return false, err
	}
	if journal.RestoreMarker != nil {
		if err := applier.writeRestoreMarker(*journal.RestoreMarker); err != nil {
			return false, err
		}
	}
	journal.State, journal.UpdatedAt = stateRolledBack, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return false, err
	}
	return true, applier.cleanupTransaction()
}

func (applier *Applier) rollback(ctx context.Context, journal transactionJournal, cause error) error {
	if err := applier.restoreSnapshotFiles(); err != nil {
		return errors.Join(cause, errors.New("VPS fabric rollback could not restore persistent files"), err)
	}
	oldFirewall, readErr := readProtected(applier.snapshotFirewallPath(), 1<<20)
	if readErr != nil {
		return errors.Join(cause, readErr)
	}
	if err := applier.restoreRuntime(ctx, journal.PreviousRoutes, oldFirewall); err != nil {
		return errors.Join(cause, errors.New("VPS fabric runtime rollback failed"), err)
	}
	if err := applier.Repository.RestoreHostPlanAppliedGeneration(ctx, journal.PreviousGeneration, applier.now()); err != nil {
		return errors.Join(cause, err)
	}
	if journal.PreviousReceipt != nil {
		if err := applier.writeReceipt(*journal.PreviousReceipt); err != nil {
			return errors.Join(cause, err)
		}
	} else if err := removeRegular(applier.receiptPath()); err != nil {
		return errors.Join(cause, err)
	}
	if journal.RestoreMarker != nil {
		if err := applier.writeRestoreMarker(*journal.RestoreMarker); err != nil {
			return errors.Join(cause, err)
		}
	}
	journal.State, journal.UpdatedAt = stateRolledBack, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return errors.Join(cause, err)
	}
	if err := applier.cleanupTransaction(); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, errors.New("VPS fabric apply failed and was safely rolled back"))
}

func (applier *Applier) applyRuntime(ctx context.Context, desired vpsagent.VPSHostPlan, previousRoutes []string, firewall []byte) error {
	if _, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.Systemctl, Arguments: []string{"restart", "wg-quick@wg-mgmt.service"}, MaxOutputBytes: 1 << 20}); err != nil {
		return errors.New("restart owned VPS WireGuard interface failed")
	}
	if err := applier.loadFirewall(ctx, firewall); err != nil {
		return errors.New("load owned VPS fabric firewall failed")
	}
	newRoutes, err := routeDestinations(desired)
	if err != nil {
		return err
	}
	if err := applier.replaceRoutes(ctx, previousRoutes, newRoutes); err != nil {
		return err
	}
	return applier.verifyRuntime(ctx, desired, newRoutes)
}

func (applier *Applier) restoreRuntime(ctx context.Context, previousRoutes []string, firewall []byte) error {
	if _, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.Systemctl, Arguments: []string{"restart", "wg-quick@wg-mgmt.service"}, MaxOutputBytes: 1 << 20}); err != nil {
		return errors.New("restart previous VPS WireGuard interface failed")
	}
	if err := applier.loadFirewall(ctx, firewall); err != nil {
		return errors.New("restore previous VPS firewall failed")
	}
	current, err := applier.readOwnedRoutes(ctx)
	if err != nil {
		return err
	}
	if err := applier.replaceRoutes(ctx, current, previousRoutes); err != nil {
		return err
	}
	actual, err := applier.readOwnedRoutes(ctx)
	if err != nil || !equalStrings(actual, previousRoutes) {
		return errors.New("restored VPS fabric routes differ from snapshot")
	}
	return nil
}

func (applier *Applier) loadFirewall(ctx context.Context, firewall []byte) error {
	currentTable, tableErr := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.NFT, Arguments: []string{"list", "table", "inet", "gateway_vpn_vps"}, MaxOutputBytes: 1 << 20})
	payload := firewall
	if tableErr == nil && strings.Contains(currentTable.Stdout, "table inet gateway_vpn_vps") {
		payload = append([]byte("delete table inet gateway_vpn_vps\n"), firewall...)
	}
	_, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.NFT, Arguments: []string{"--file", "-"}, Stdin: payload, MaxOutputBytes: 1 << 20})
	return err
}

func (applier *Applier) replaceRoutes(ctx context.Context, oldRoutes, newRoutes []string) error {
	newSet := map[string]struct{}{}
	for _, route := range newRoutes {
		newSet[route] = struct{}{}
	}
	for _, route := range oldRoutes {
		if _, keep := newSet[route]; keep {
			continue
		}
		_, _ = applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.IP, Arguments: []string{"-4", "route", "del", route, "dev", "wg-mgmt", "protocol", "186"}, MaxOutputBytes: 1 << 20})
	}
	for _, route := range newRoutes {
		if _, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.IP, Arguments: []string{"-4", "route", "replace", route, "dev", "wg-mgmt", "protocol", "186"}, MaxOutputBytes: 1 << 20}); err != nil {
			return errors.New("apply owned VPS fabric route failed")
		}
	}
	return nil
}

func (applier *Applier) verifyRuntime(ctx context.Context, plan vpsagent.VPSHostPlan, routes []string) error {
	if plan.Generation == 0 {
		return nil
	}
	identity, err := vpsagent.ReadIdentity(ctx, applier.Repository.Database)
	if err != nil {
		return err
	}
	for _, check := range []struct {
		args []string
		want string
	}{
		{[]string{"show", "wg-mgmt", "listen-port"}, strconv.Itoa(plan.ListenPort)},
		{[]string{"show", "wg-mgmt", "public-key"}, identity.PublicKey},
	} {
		result, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.WG, Arguments: check.args, MaxOutputBytes: 1 << 20})
		if err != nil || strings.TrimSpace(result.Stdout) != check.want {
			return errors.New("owned VPS WireGuard verification failed")
		}
	}
	peers, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.WG, Arguments: []string{"show", "wg-mgmt", "peers"}, MaxOutputBytes: 1 << 20})
	if err != nil {
		return errors.New("read owned VPS WireGuard peers failed")
	}
	actualPeers := strings.Fields(peers.Stdout)
	expectedPeers := make([]string, 0, len(plan.Peers))
	for _, peer := range plan.Peers {
		expectedPeers = append(expectedPeers, peer.PublicKey)
	}
	sort.Strings(actualPeers)
	sort.Strings(expectedPeers)
	if strings.Join(actualPeers, "\n") != strings.Join(expectedPeers, "\n") {
		return errors.New("owned VPS WireGuard peer set differs from plan")
	}
	addresses, err := applier.readInterfaceAddresses(ctx)
	if err != nil || !equalStrings(addresses, plan.InterfaceAddresses) {
		return errors.New("owned VPS WireGuard address set differs from plan")
	}
	actualRoutes, err := applier.readOwnedRoutes(ctx)
	if err != nil || !equalStrings(actualRoutes, routes) {
		return errors.New("owned VPS fabric route verification failed")
	}
	firewall, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.NFT, Arguments: []string{"list", "table", "inet", "gateway_vpn_vps"}, MaxOutputBytes: 1 << 20})
	marker := "gateway-vpn fabric generation " + strconv.FormatInt(plan.Generation, 10) + " plan " + planDigest(plan)
	if err != nil || !strings.Contains(firewall.Stdout, marker) || strings.Count(firewall.Stdout, "gateway-vpn ") != expectedFirewallRuleCount(plan) {
		return errors.New("owned VPS fabric firewall verification failed")
	}
	return nil
}

func (applier *Applier) readInterfaceAddresses(ctx context.Context) ([]string, error) {
	result, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.IP, Arguments: []string{"-json", "-4", "address", "show", "dev", "wg-mgmt"}, MaxOutputBytes: 1 << 20})
	if err != nil {
		return nil, errors.New("read owned VPS WireGuard addresses failed")
	}
	var links []struct {
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(result.Stdout), &links) != nil || len(links) != 1 || len(links[0].Addresses) > 65 {
		return nil, errors.New("owned VPS WireGuard address output is invalid")
	}
	addresses := make([]string, 0, len(links[0].Addresses))
	for _, row := range links[0].Addresses {
		address, parseErr := netip.ParseAddr(row.Local)
		if parseErr != nil || row.Family != "inet" || !address.Is4() || !address.IsPrivate() || row.PrefixLen < 16 || row.PrefixLen > 30 {
			return nil, errors.New("owned VPS WireGuard address escaped its contract")
		}
		addresses = append(addresses, netip.PrefixFrom(address, row.PrefixLen).String())
	}
	sort.Strings(addresses)
	return addresses, nil
}

func expectedFirewallRuleCount(plan vpsagent.VPSHostPlan) int {
	gateways := 0
	for _, peer := range plan.Peers {
		if peer.Kind == "GATEWAY" {
			gateways++
		}
	}
	// input: generation marker, established, two rules for each
	// administrator/address pair, final reject. forward: established, two
	// management rules per administrator/Gateway pair, ACLs, two final rejects.
	// Each relay adds rate-limit + DNAT, ingress + return forwarding and SNAT.
	return 1 + 1 + 2*len(plan.HubAdminSources)*len(plan.InterfaceAddresses) + 1 +
		1 + 2*len(plan.HubAdminSources)*gateways + len(plan.ACL) + 2 + 5*len(plan.AdminRelays)
}

func (applier *Applier) readOwnedRoutes(ctx context.Context) ([]string, error) {
	result, err := applier.Executor.Run(ctx, platformexec.Request{Executable: applier.Paths.IP, Arguments: []string{"-json", "-4", "route", "show", "dev", "wg-mgmt", "protocol", "186"}, MaxOutputBytes: 1 << 20})
	if err != nil {
		return nil, errors.New("read owned VPS fabric routes failed")
	}
	var rows []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
		Protocol    any    `json:"protocol"`
	}
	if json.Unmarshal([]byte(result.Stdout), &rows) != nil || len(rows) > 4096 {
		return nil, errors.New("owned VPS fabric route output is invalid")
	}
	found := map[string]struct{}{}
	for _, row := range rows {
		prefix, prefixErr := parseOwnedRouteDestination(row.Destination)
		// Current iproute2 also omits `dev` after the fixed `dev wg-mgmt`
		// selector; if it is repeated, it must still match exactly.
		if (row.Device != "" && row.Device != "wg-mgmt") || prefixErr != nil || !ownedProtocol(row.Protocol) {
			return nil, errors.New("owned VPS fabric route output escaped its contract")
		}
		found[prefix.String()] = struct{}{}
	}
	routes := make([]string, 0, len(found))
	for route := range found {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	return routes, nil
}

func parseOwnedRouteDestination(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		address, addressErr := netip.ParseAddr(value)
		if addressErr != nil {
			return netip.Prefix{}, errors.New("owned route destination is invalid")
		}
		prefix = netip.PrefixFrom(address, 32)
	}
	if !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 16 {
		return netip.Prefix{}, errors.New("owned route destination escaped its private IPv4 contract")
	}
	return prefix, nil
}

func ownedProtocol(value any) bool {
	switch typed := value.(type) {
	case nil:
		// `ip -json route show ... protocol 186` omits the already-filtered
		// protocol field from each returned row on current Ubuntu iproute2.
		return true
	case float64:
		return typed == float64(vpsagent.VPSOwnedRouteProtocol)
	case string:
		// iproute2 renders protocol 186 using its canonical rt_protos name
		// ("bgp") on Ubuntu, while minimal builds may preserve the number.
		return typed == strconv.Itoa(vpsagent.VPSOwnedRouteProtocol) || typed == "bgp"
	default:
		return false
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (applier *Applier) snapshotFiles() error {
	for source, destination := range map[string]string{
		applier.Paths.WireGuardConfig: applier.snapshotWireGuardPath(),
		applier.Paths.FirewallConfig:  applier.snapshotFirewallPath(),
	} {
		content, err := readProtected(source, 1<<20)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if source == applier.Paths.FirewallConfig {
			mode = 0o640
		}
		if err := atomicWrite(destination, content, mode); err != nil {
			return err
		}
	}
	return nil
}

func (applier *Applier) restoreSnapshotFiles() error {
	for source, destination := range map[string]string{
		applier.snapshotWireGuardPath(): applier.Paths.WireGuardConfig,
		applier.snapshotFirewallPath():  applier.Paths.FirewallConfig,
	} {
		content, err := readProtected(source, 1<<20)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if destination == applier.Paths.FirewallConfig {
			mode = 0o640
		}
		if err := atomicWrite(destination, content, mode); err != nil {
			return err
		}
	}
	return nil
}

func (applier *Applier) validate() error {
	if applier == nil || applier.Repository.Database == nil || applier.Executor == nil {
		return errors.New("complete VPS fabric applier is required")
	}
	for _, path := range []string{applier.Paths.TransactionRoot, applier.Paths.WireGuardConfig, applier.Paths.FirewallConfig, applier.Paths.PrivateKey, applier.Paths.IP, applier.Paths.NFT, applier.Paths.WG, applier.Paths.Systemctl} {
		if !filepath.IsAbs(path) {
			return errors.New("VPS fabric paths must be absolute")
		}
	}
	if filepath.Base(applier.Paths.WireGuardConfig) != "wg-mgmt.conf" || filepath.Base(applier.Paths.FirewallConfig) != "firewall.nft" || filepath.Base(applier.Paths.PrivateKey) != "server.key" {
		return errors.New("VPS fabric managed path contract is invalid")
	}
	if err := secureDirectory(applier.Paths.TransactionRoot); err != nil {
		return err
	}
	return nil
}

func (applier *Applier) writeReceipt(receipt Receipt) error {
	if err := vpsagent.ValidateHostPlan(receipt.Plan); err != nil || receipt.FormatVersion != journalVersion || receipt.Generation != receipt.Plan.Generation || receipt.Generation < 1 {
		return errors.New("VPS fabric receipt is invalid")
	}
	receipt.PlanSHA256 = planDigest(receipt.Plan)
	content, _ := json.MarshalIndent(receipt, "", "  ")
	return atomicWrite(applier.receiptPath(), append(content, '\n'), 0o600)
}

func (applier *Applier) readReceipt() (Receipt, bool, error) {
	content, err := readProtected(applier.receiptPath(), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var receipt Receipt
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.FormatVersion != journalVersion || receipt.Generation != receipt.Plan.Generation || receipt.PlanSHA256 != planDigest(receipt.Plan) || vpsagent.ValidateHostPlan(receipt.Plan) != nil {
		return Receipt{}, false, errors.New("VPS fabric applied receipt is invalid")
	}
	return receipt, true, nil
}

func (applier *Applier) writeRestoreMarker(marker RestoreMarker) error {
	if err := validateRestoreMarker(marker); err != nil {
		return err
	}
	content, _ := json.MarshalIndent(marker, "", "  ")
	return atomicWrite(applier.restoreMarkerPath(), append(content, '\n'), 0o600)
}

func (applier *Applier) readRestoreMarker() (RestoreMarker, bool, error) {
	content, err := readProtected(applier.restoreMarkerPath(), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return RestoreMarker{}, false, nil
	}
	if err != nil {
		return RestoreMarker{}, false, err
	}
	var marker RestoreMarker
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&marker) != nil || validateRestoreMarker(marker) != nil {
		return RestoreMarker{}, false, errors.New("VPS fabric restore reconciliation marker is invalid")
	}
	return marker, true, nil
}

func validateRestoreMarker(marker RestoreMarker) error {
	if marker.FormatVersion != journalVersion || !restoreIDPattern.MatchString(marker.RestoreID) || marker.PreviousGeneration < 1 || len(marker.PreviousPlanSHA256) != 64 || marker.PreparedAt == "" || marker.UpdatedAt == "" {
		return errors.New("VPS fabric restore reconciliation marker contract is invalid")
	}
	if _, err := hex.DecodeString(marker.PreviousPlanSHA256); err != nil {
		return errors.New("VPS fabric restore receipt digest is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, marker.PreparedAt); err != nil {
		return errors.New("VPS fabric restore prepared timestamp is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, marker.UpdatedAt); err != nil {
		return errors.New("VPS fabric restore updated timestamp is invalid")
	}
	switch marker.State {
	case restorePrepared:
		if marker.TargetGeneration != 0 || marker.TargetVPSID != "" || marker.TargetPublicKey != "" {
			return errors.New("prepared VPS fabric restore marker contains target state")
		}
	case restoreActive:
		if marker.TargetGeneration < 1 || !strings.HasPrefix(marker.TargetVPSID, "vps-") && !strings.HasPrefix(marker.TargetVPSID, "vps:") || !wgingress.ValidKey(marker.TargetPublicKey) {
			return errors.New("active VPS fabric restore marker has invalid target state")
		}
	default:
		return errors.New("VPS fabric restore marker state is invalid")
	}
	return nil
}

func (applier *Applier) writeJournal(journal transactionJournal) error {
	if err := applier.validateJournal(journal); err != nil {
		return err
	}
	content, _ := json.MarshalIndent(journal, "", "  ")
	return atomicWrite(applier.journalPath(), append(content, '\n'), 0o600)
}

func (applier *Applier) readJournal() (transactionJournal, bool, error) {
	content, err := readProtected(applier.journalPath(), 8<<20)
	if errors.Is(err, os.ErrNotExist) {
		return transactionJournal{}, false, nil
	}
	if err != nil {
		return transactionJournal{}, false, err
	}
	var journal transactionJournal
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || applier.validateJournal(journal) != nil {
		return transactionJournal{}, false, errors.New("VPS fabric recovery journal is invalid")
	}
	return journal, true, nil
}

func (applier *Applier) validateJournal(journal transactionJournal) error {
	if journal.FormatVersion != journalVersion || journal.PreviousGeneration < 0 || journal.TargetGeneration < 1 || journal.TargetGeneration != journal.TargetPlan.Generation || vpsagent.ValidateHostPlan(journal.TargetPlan) != nil || !validRouteList(journal.PreviousRoutes) {
		return errors.New("VPS fabric journal contract is invalid")
	}
	if journal.PreviousReceipt != nil {
		if journal.PreviousReceipt.Generation < 1 || journal.PreviousReceipt.PlanSHA256 != planDigest(journal.PreviousReceipt.Plan) || vpsagent.ValidateHostPlan(journal.PreviousReceipt.Plan) != nil {
			return errors.New("VPS fabric journal previous receipt is invalid")
		}
		if journal.RestoreMarker == nil && journal.PreviousReceipt.Generation != journal.PreviousGeneration {
			return errors.New("VPS fabric journal generation does not match previous receipt")
		}
	} else if journal.RestoreMarker != nil {
		return errors.New("VPS restore reconciliation requires a previous receipt")
	}
	if journal.RestoreMarker != nil && validateRestoreMarker(*journal.RestoreMarker) != nil {
		return errors.New("VPS fabric journal restore marker is invalid")
	}
	switch journal.State {
	case statePrepared, stateApplying, stateCommitted, stateRolledBack:
	default:
		return errors.New("VPS fabric journal state is invalid")
	}
	return nil
}

func validRouteList(routes []string) bool {
	previous := ""
	for _, raw := range routes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 16 || raw <= previous {
			return false
		}
		previous = raw
	}
	return true
}

func (applier *Applier) cleanupTransaction() error {
	for _, path := range []string{applier.snapshotWireGuardPath(), applier.snapshotFirewallPath(), applier.journalPath()} {
		if err := removeRegular(path); err != nil {
			return err
		}
	}
	return syncDirectory(applier.Paths.TransactionRoot)
}

func planDigest(plan vpsagent.VPSHostPlan) string {
	content, _ := json.Marshal(plan)
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func (applier *Applier) receiptPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "applied.json")
}
func (applier *Applier) restoreMarkerPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "restore-reconcile.json")
}
func (applier *Applier) journalPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "transaction.json")
}
func (applier *Applier) snapshotWireGuardPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "previous-wg-mgmt.conf")
}
func (applier *Applier) snapshotFirewallPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "previous-firewall.nft")
}
func (applier *Applier) now() time.Time {
	if applier.Now != nil {
		return applier.Now().UTC()
	}
	return time.Now().UTC()
}

func secureDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("VPS fabric transaction directory is unsafe")
	}
	return nil
}

func readProtected(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("VPS fabric protected file is unsafe")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("read VPS fabric protected file failed")
	}
	return content, nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("VPS fabric destination directory is unsafe")
	}
	if current, err := os.Lstat(path); err == nil && (current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular()) {
		return errors.New("VPS fabric destination is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gateway-vpn-vps-fabric-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func removeRegular(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refuse to remove unsafe VPS fabric file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }
