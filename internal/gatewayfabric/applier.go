package gatewayfabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
)

const (
	gatewayJournalVersion = 1
	gatewayPrepared       = "PREPARED"
	gatewayApplying       = "APPLYING"
	gatewayCommitted      = "COMMITTED"
	gatewayRolledBack     = "ROLLED_BACK"
)

type Paths struct {
	TransactionRoot      string
	SecretRoot           string
	SecretReferenceRoot  string
	IP                   string
	NFT                  string
	WG                   string
	Ping                 string
	RequireRootOwnership bool
}

func DefaultPaths() Paths {
	return Paths{
		TransactionRoot:     "/var/lib/gateway-vpn-privileged/management-fabric",
		SecretRoot:          "/var/lib/gateway-vpn/secrets/management",
		SecretReferenceRoot: "/var/lib/gateway-vpn/secrets/management",
		IP:                  "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", Ping: "/usr/bin/ping",
		RequireRootOwnership: true,
	}
}

type Applier struct {
	Repository     *managementfabric.Repository
	Executor       platformexec.Executor
	Paths          Paths
	Now            func() time.Time
	TransportProbe ResourceTransportProbe
	mutex          sync.Mutex
}

type Receipt struct {
	FormatVersion int                                     `json:"format_version"`
	Generation    int64                                   `json:"generation"`
	PlanSHA256    string                                  `json:"plan_sha256"`
	Plan          managementfabric.GatewayHostPlan        `json:"plan"`
	AppliedState  managementfabric.GatewayAppliedSnapshot `json:"applied_state"`
	AppliedAt     string                                  `json:"applied_at"`
}

type transactionJournal struct {
	FormatVersion   int                                     `json:"format_version"`
	State           string                                  `json:"state"`
	PreviousReceipt *Receipt                                `json:"previous_receipt,omitempty"`
	PreviousState   managementfabric.GatewayAppliedSnapshot `json:"previous_state"`
	TargetPlan      managementfabric.GatewayHostPlan        `json:"target_plan"`
	StartedAt       string                                  `json:"started_at"`
	UpdatedAt       string                                  `json:"updated_at"`
}

func (applier *Applier) NeedsApply(ctx context.Context) (bool, string, error) {
	if err := applier.validate(); err != nil {
		return false, "VALIDATION_FAILED", err
	}
	if exists(applier.journalPath()) {
		return true, "TRANSACTION_RECOVERY_REQUIRED", nil
	}
	plan, err := applier.Repository.BuildGatewayHostPlan(ctx)
	if err != nil {
		return false, "DESIRED_STATE_INVALID", err
	}
	desired, applied, _, _, err := applier.Repository.GatewayFabricGenerations(ctx)
	if err != nil || desired != plan.Generation {
		return false, "GENERATION_INVALID", errors.New("Gateway Management Fabric generation changed during inspection")
	}
	receipt, hasReceipt, err := applier.readReceipt()
	if err != nil {
		return false, "RECEIPT_INVALID", err
	}
	if !hasReceipt {
		if applied == 0 {
			return true, "BOOTSTRAP_RECEIPT_MISSING", nil
		}
		return false, "RECEIPT_MISSING", errors.New("Gateway Management Fabric receipt is missing")
	}
	if receipt.Generation != applied {
		return false, "RECEIPT_GENERATION_MISMATCH", errors.New("Gateway Management Fabric receipt and database differ")
	}
	if desired != applied || receipt.PlanSHA256 != planDigest(plan) {
		return true, "DESIRED_GENERATION_PENDING", nil
	}
	if err := applier.verifyRuntime(ctx, plan); err != nil {
		return true, "RUNTIME_PROJECTION_DRIFT", nil
	}
	return false, "HEALTHY", nil
}

func (applier *Applier) Apply(ctx context.Context) error {
	applier.mutex.Lock()
	defer applier.mutex.Unlock()
	return applier.applyUnlocked(ctx)
}

func (applier *Applier) applyUnlocked(ctx context.Context) error {
	if err := applier.validate(); err != nil {
		return err
	}
	if exists(applier.journalPath()) {
		return errors.New("interrupted Gateway Management Fabric transaction requires recovery")
	}
	target, err := applier.Repository.BuildGatewayHostPlan(ctx)
	if err != nil {
		return err
	}
	desired, applied, _, _, err := applier.Repository.GatewayFabricGenerations(ctx)
	if err != nil || desired != target.Generation {
		return errors.New("Gateway Management Fabric generation changed before apply")
	}
	previous, hasReceipt, err := applier.readReceipt()
	if err != nil {
		return err
	}
	if hasReceipt && previous.Generation != applied {
		return errors.New("Gateway Management Fabric receipt and database applied generation differ")
	}
	if !hasReceipt && applied != 0 {
		return errors.New("Gateway Management Fabric applied receipt is missing")
	}
	previousState, err := applier.Repository.CaptureGatewayAppliedState(ctx)
	if err != nil || previousState.Generation != applied {
		return errors.New("capture Gateway Management Fabric applied state failed")
	}
	if err := applier.preflightKeys(target); err != nil {
		return err
	}
	if err := applier.preflightInterfaces(ctx, target, previous.Plan, hasReceipt); err != nil {
		return err
	}
	firewall, err := RenderFirewallTransaction(target)
	if err != nil {
		return err
	}
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.NFT, []string{"--check", "--file", "-"}, firewall)); err != nil {
		return errors.New("candidate Gateway Management Fabric firewall failed nft validation")
	}
	now := applier.now().Format(time.RFC3339Nano)
	journal := transactionJournal{
		FormatVersion: gatewayJournalVersion, State: gatewayPrepared, PreviousState: previousState,
		TargetPlan: target, StartedAt: now, UpdatedAt: now,
	}
	if hasReceipt {
		copy := previous
		journal.PreviousReceipt = &copy
	}
	if err := applier.writeJournal(journal); err != nil {
		return err
	}
	journal.State, journal.UpdatedAt = gatewayApplying, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return err
	}
	previousPlan := managementfabric.GatewayHostPlan{Generation: target.Generation, RouteProtocol: managementfabric.OwnedRouteProtocol}
	if hasReceipt {
		previousPlan = previous.Plan
	}
	if err := applier.replaceRuntime(ctx, previousPlan, target); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	if err := applier.Repository.MarkGatewayHostPlanApplied(ctx, target, applier.now()); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	appliedState, err := applier.Repository.CaptureGatewayAppliedState(ctx)
	if err != nil || appliedState.Generation != target.Generation {
		return applier.rollback(ctx, journal, errors.New("capture committed Gateway Management Fabric state failed"))
	}
	receipt := Receipt{
		FormatVersion: gatewayJournalVersion, Generation: target.Generation, Plan: target,
		AppliedState: appliedState, AppliedAt: applier.now().Format(time.RFC3339Nano),
	}
	if err := applier.writeReceipt(receipt); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	journal.State, journal.UpdatedAt = gatewayCommitted, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return applier.rollback(ctx, journal, err)
	}
	return applier.cleanupTransaction()
}

func (applier *Applier) Recover(ctx context.Context) (bool, error) {
	applier.mutex.Lock()
	defer applier.mutex.Unlock()
	return applier.recoverUnlocked(ctx)
}

func (applier *Applier) recoverUnlocked(ctx context.Context) (bool, error) {
	if err := applier.validate(); err != nil {
		return false, err
	}
	journal, found, err := applier.readJournal()
	if err != nil || !found {
		return false, err
	}
	if journal.State == gatewayCommitted {
		return true, applier.cleanupTransaction()
	}
	if journal.State != gatewayPrepared && journal.State != gatewayApplying && journal.State != gatewayRolledBack {
		return false, errors.New("Gateway Management Fabric journal state cannot recover")
	}
	previous := emptyPlan(journal.TargetPlan.Generation)
	if journal.PreviousReceipt != nil {
		previous = journal.PreviousReceipt.Plan
	}
	if err := applier.replaceRuntime(ctx, journal.TargetPlan, previous); err != nil {
		return false, err
	}
	if err := applier.Repository.RestoreGatewayAppliedState(ctx, journal.PreviousState, applier.now()); err != nil {
		return false, err
	}
	if journal.PreviousReceipt != nil {
		if err := applier.writeReceipt(*journal.PreviousReceipt); err != nil {
			return false, err
		}
	} else if err := removeRegular(applier.receiptPath()); err != nil {
		return false, err
	}
	journal.State, journal.UpdatedAt = gatewayRolledBack, applier.now().Format(time.RFC3339Nano)
	if err := applier.writeJournal(journal); err != nil {
		return false, err
	}
	return true, applier.cleanupTransaction()
}

func (applier *Applier) rollback(ctx context.Context, journal transactionJournal, cause error) error {
	previous := emptyPlan(journal.TargetPlan.Generation)
	if journal.PreviousReceipt != nil {
		previous = journal.PreviousReceipt.Plan
	}
	runtimeErr := applier.replaceRuntime(ctx, journal.TargetPlan, previous)
	databaseErr := applier.Repository.RestoreGatewayAppliedState(ctx, journal.PreviousState, applier.now())
	var receiptErr error
	if journal.PreviousReceipt != nil {
		receiptErr = applier.writeReceipt(*journal.PreviousReceipt)
	} else {
		receiptErr = removeRegular(applier.receiptPath())
	}
	journal.State, journal.UpdatedAt = gatewayRolledBack, applier.now().Format(time.RFC3339Nano)
	journalErr := applier.writeJournal(journal)
	cleanupErr := error(nil)
	if runtimeErr == nil && databaseErr == nil && receiptErr == nil && journalErr == nil {
		cleanupErr = applier.cleanupTransaction()
	}
	markErr := applier.Repository.MarkGatewayHostPlanFailed(ctx, journal.TargetPlan.Generation, "HOST_APPLY_FAILED", applier.now())
	return errors.Join(cause, runtimeErr, databaseErr, receiptErr, journalErr, cleanupErr, markErr, errors.New("Gateway Management Fabric apply failed and was safely rolled back"))
}

func (applier *Applier) replaceRuntime(ctx context.Context, oldPlan, newPlan managementfabric.GatewayHostPlan) error {
	closed, err := RenderFirewallTransaction(emptyPlan(newPlan.Generation))
	if err != nil {
		return err
	}
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.NFT, []string{"--file", "-"}, closed)); err != nil {
		return errors.New("close Gateway Management Fabric firewall contour failed")
	}
	remove, apply := runtimeLinkDelta(oldPlan, newPlan)
	if err := applier.removePlan(ctx, remove); err != nil {
		return err
	}
	if err := applier.preflightKeys(newPlan); err != nil {
		return err
	}
	if err := applier.applyPlan(ctx, apply); err != nil {
		return err
	}
	if err := applier.replaceAdminContour(ctx, oldPlan.AdminContour, newPlan.AdminContour); err != nil {
		return err
	}
	firewall, err := RenderFirewallTransaction(newPlan)
	if err != nil {
		return err
	}
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.NFT, []string{"--file", "-"}, firewall)); err != nil {
		return errors.New("load Gateway Management Fabric firewall transaction failed")
	}
	return applier.verifyRuntime(ctx, newPlan)
}

// runtimeLinkDelta keeps byte-for-byte equivalent links alive while the
// generation-scoped firewall projection is replaced.  Removing one VPS or
// changing only an ACL must not reset handshakes on unrelated gvm<N> links.
// A link whose interface-bound settings changed is deliberately treated as a
// remove+apply pair so rollback can restore the exact previous projection.
func runtimeLinkDelta(oldPlan, newPlan managementfabric.GatewayHostPlan) (managementfabric.GatewayHostPlan, managementfabric.GatewayHostPlan) {
	oldByInterface := make(map[string]managementfabric.GatewayHostLink, len(oldPlan.Links))
	newByInterface := make(map[string]managementfabric.GatewayHostLink, len(newPlan.Links))
	for _, link := range oldPlan.Links {
		oldByInterface[link.InterfaceName] = link
	}
	for _, link := range newPlan.Links {
		newByInterface[link.InterfaceName] = link
	}
	remove := managementfabric.GatewayHostPlan{Generation: newPlan.Generation, RouteProtocol: managementfabric.OwnedRouteProtocol}
	apply := managementfabric.GatewayHostPlan{Generation: newPlan.Generation, RouteProtocol: managementfabric.OwnedRouteProtocol}
	for _, link := range oldPlan.Links {
		if next, exists := newByInterface[link.InterfaceName]; !exists || !reflect.DeepEqual(link, next) {
			remove.Links = append(remove.Links, link)
		}
	}
	for _, link := range newPlan.Links {
		if previous, exists := oldByInterface[link.InterfaceName]; !exists || !reflect.DeepEqual(previous, link) {
			apply.Links = append(apply.Links, link)
		}
	}
	return remove, apply
}

func (applier *Applier) removePlan(ctx context.Context, plan managementfabric.GatewayHostPlan) error {
	for _, link := range plan.Links {
		endpoint := netip.MustParseAddr(link.EndpointAddress)
		endpointPrefix := netip.PrefixFrom(endpoint, 32).String()
		_, _ = applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "del", endpointPrefix, "via", link.UplinkGateway, "dev", link.UplinkInterface, "table", strconv.FormatInt(link.UplinkTable, 10), "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
		if err := applier.verifyRouteAbsent(ctx, endpointPrefix, link.UplinkInterface, strconv.FormatInt(link.UplinkTable, 10)); err != nil {
			return fmt.Errorf("remove Gateway Management Fabric endpoint route for %s: %w", link.InterfaceName, err)
		}
		for _, route := range link.Routes {
			_, _ = applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "del", route.Destination, "dev", link.InterfaceName, "table", "main", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
			if err := applier.verifyRouteAbsent(ctx, route.Destination, link.InterfaceName, "main"); err != nil {
				return fmt.Errorf("remove Gateway Management Fabric route for %s: %w", link.InterfaceName, err)
			}
		}
		_, _ = applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"link", "del", "dev", link.InterfaceName}, nil))
		names, err := applier.interfaceNames(ctx)
		if err != nil {
			return errors.New("verify removed Gateway Management Fabric interface inventory failed")
		}
		if _, exists := names[link.InterfaceName]; exists {
			return fmt.Errorf("Gateway Management Fabric interface %s remained after removal", link.InterfaceName)
		}
	}
	return nil
}

func (applier *Applier) verifyRouteAbsent(ctx context.Context, destination, device, table string) error {
	result, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "show", "table", table, "exact", destination, "dev", device, "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
	if err != nil {
		return errors.New("query owned route after removal failed")
	}
	var rows []json.RawMessage
	if json.Unmarshal([]byte(result.Stdout), &rows) != nil || len(rows) != 0 {
		return errors.New("owned route remained after removal")
	}
	return nil
}

func (applier *Applier) applyPlan(ctx context.Context, plan managementfabric.GatewayHostPlan) error {
	for _, link := range plan.Links {
		commands := [][]string{
			{"link", "add", "name", link.InterfaceName, "type", "wireguard"},
			{"-4", "address", "replace", link.LocalAddress, "dev", link.InterfaceName},
		}
		for _, args := range commands {
			if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, args, nil)); err != nil {
				return fmt.Errorf("configure Gateway Management Fabric interface %s failed", link.InterfaceName)
			}
		}
		endpoint := net.JoinHostPort(link.EndpointAddress, strconv.Itoa(link.EndpointPort))
		secretPath, err := applier.secretPath(link.PrivateKeyRef)
		if err != nil {
			return err
		}
		wgArgs := []string{"set", link.InterfaceName, "private-key", secretPath, "fwmark", strconv.FormatInt(link.UplinkMark, 10), "peer", link.RemotePublicKey, "endpoint", endpoint, "persistent-keepalive", strconv.Itoa(link.PersistentKeepalive), "allowed-ips", strings.Join(link.AllowedIPs, ",")}
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.WG, wgArgs, nil)); err != nil {
			return errors.New("configure Gateway Management Fabric WireGuard peer failed")
		}
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"link", "set", "dev", link.InterfaceName, "up"}, nil)); err != nil {
			return errors.New("activate Gateway Management Fabric interface failed")
		}
		endpointPrefix := netip.PrefixFrom(netip.MustParseAddr(link.EndpointAddress), 32).String()
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "replace", endpointPrefix, "via", link.UplinkGateway, "dev", link.UplinkInterface, "table", strconv.FormatInt(link.UplinkTable, 10), "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil)); err != nil {
			return errors.New("apply Gateway Management Fabric endpoint route failed")
		}
		for _, route := range link.Routes {
			if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "replace", route.Destination, "dev", link.InterfaceName, "table", "main", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil)); err != nil {
				return errors.New("apply Gateway Management Fabric owned route failed")
			}
		}
	}
	return nil
}

func (applier *Applier) replaceAdminContour(ctx context.Context, oldContour, newContour *managementfabric.RenderedAdminContour) error {
	if oldContour == nil && newContour == nil {
		return nil
	}
	identityChanged := oldContour == nil || newContour == nil || !sameAdminContourIdentity(*oldContour, *newContour)
	if identityChanged && oldContour != nil {
		if err := applier.removeAdminContour(ctx, *oldContour); err != nil {
			return err
		}
	}
	if newContour == nil {
		return nil
	}
	if identityChanged {
		return applier.createAdminContour(ctx, *newContour)
	}
	// Reassert the fixed identity even when the durable projection is unchanged.
	// A failed candidate rotation can leave the owned interface present but only
	// partially configured before the transaction rollback gets control.  Peer
	// deltas alone cannot repair that state.
	if err := applier.configureAdminContourIdentity(ctx, *newContour); err != nil {
		return err
	}

	oldPeers := make(map[string]managementfabric.RenderedAdminPeer, len(oldContour.Peers))
	newPeers := make(map[string]managementfabric.RenderedAdminPeer, len(newContour.Peers))
	for _, peer := range oldContour.Peers {
		oldPeers[peer.TunnelID] = peer
	}
	for _, peer := range newContour.Peers {
		newPeers[peer.TunnelID] = peer
	}
	for _, peer := range oldContour.Peers {
		if next, exists := newPeers[peer.TunnelID]; exists && reflect.DeepEqual(peer, next) {
			continue
		}
		_, _ = applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"set", managementfabric.AdminInterfaceName, "peer", peer.PublicKey, "remove"}, nil))
		_, _ = applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "del", peer.AssignedAddress, "dev", managementfabric.AdminInterfaceName, "table", "main", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
		if err := applier.verifyRouteAbsent(ctx, peer.AssignedAddress, managementfabric.AdminInterfaceName, "main"); err != nil {
			return errors.New("remove Gateway administrator peer route failed")
		}
	}
	for _, peer := range newContour.Peers {
		if previous, exists := oldPeers[peer.TunnelID]; exists && reflect.DeepEqual(previous, peer) {
			continue
		}
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"set", managementfabric.AdminInterfaceName, "peer", peer.PublicKey, "allowed-ips", peer.AssignedAddress}, nil)); err != nil {
			return errors.New("configure Gateway administrator peer failed")
		}
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "replace", peer.AssignedAddress, "dev", managementfabric.AdminInterfaceName, "table", "main", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil)); err != nil {
			return errors.New("configure Gateway administrator peer route failed")
		}
	}
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"link", "set", "dev", newContour.InterfaceName, "up"}, nil)); err != nil {
		return errors.New("activate Gateway administrator WireGuard interface failed")
	}
	return nil
}

func sameAdminContourIdentity(left, right managementfabric.RenderedAdminContour) bool {
	return left.InterfaceName == right.InterfaceName && left.PrivateKeySecretRef == right.PrivateKeySecretRef &&
		left.PublicKey == right.PublicKey && left.Subnet == right.Subnet &&
		left.GatewayAddress == right.GatewayAddress && left.ListenPort == right.ListenPort
}

func (applier *Applier) createAdminContour(ctx context.Context, contour managementfabric.RenderedAdminContour) error {
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"link", "add", "name", contour.InterfaceName, "type", "wireguard"}, nil)); err != nil {
		return errors.New("create Gateway administrator WireGuard interface failed")
	}
	if err := applier.configureAdminContourIdentity(ctx, contour); err != nil {
		return err
	}
	for _, peer := range contour.Peers {
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"set", contour.InterfaceName, "peer", peer.PublicKey, "allowed-ips", peer.AssignedAddress}, nil)); err != nil {
			return errors.New("configure Gateway administrator WireGuard peer failed")
		}
		if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "replace", peer.AssignedAddress, "dev", contour.InterfaceName, "table", "main", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil)); err != nil {
			return errors.New("configure Gateway administrator route failed")
		}
	}
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"link", "set", "dev", contour.InterfaceName, "up"}, nil)); err != nil {
		return errors.New("activate Gateway administrator WireGuard interface failed")
	}
	return nil
}

func (applier *Applier) configureAdminContourIdentity(ctx context.Context, contour managementfabric.RenderedAdminContour) error {
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "address", "replace", contour.GatewayAddress, "dev", contour.InterfaceName}, nil)); err != nil {
		return errors.New("configure Gateway administrator address failed")
	}
	secretPath, err := applier.secretPath(contour.PrivateKeySecretRef)
	if err != nil {
		return err
	}
	if _, err := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"set", contour.InterfaceName, "private-key", secretPath, "listen-port", strconv.Itoa(contour.ListenPort)}, nil)); err != nil {
		return errors.New("configure Gateway administrator WireGuard identity failed")
	}
	return nil
}

func (applier *Applier) removeAdminContour(ctx context.Context, contour managementfabric.RenderedAdminContour) error {
	for _, peer := range contour.Peers {
		_, _ = applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-4", "route", "del", peer.AssignedAddress, "dev", contour.InterfaceName, "table", "main", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
		if err := applier.verifyRouteAbsent(ctx, peer.AssignedAddress, contour.InterfaceName, "main"); err != nil {
			return errors.New("remove Gateway administrator route failed")
		}
	}
	_, _ = applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"link", "del", "dev", contour.InterfaceName}, nil))
	names, err := applier.interfaceNames(ctx)
	if err != nil {
		return errors.New("verify removed Gateway administrator interface failed")
	}
	if _, exists := names[contour.InterfaceName]; exists {
		return errors.New("Gateway administrator interface remained after removal")
	}
	return nil
}

func (applier *Applier) verifyRuntime(ctx context.Context, plan managementfabric.GatewayHostPlan) error {
	for _, link := range plan.Links {
		for _, check := range []struct {
			args []string
			want string
		}{
			{[]string{"show", link.InterfaceName, "public-key"}, link.LocalPublicKey},
			{[]string{"show", link.InterfaceName, "peers"}, link.RemotePublicKey},
		} {
			result, err := applier.Executor.Run(ctx, request(applier.Paths.WG, check.args, nil))
			if err != nil || strings.TrimSpace(result.Stdout) != check.want {
				return fmt.Errorf("Gateway Management Fabric WireGuard verification failed for %s", link.InterfaceName)
			}
		}
		fwmark, err := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"show", link.InterfaceName, "fwmark"}, nil))
		if err != nil || !sameMark(strings.TrimSpace(fwmark.Stdout), link.UplinkMark) {
			return errors.New("Gateway Management Fabric fwmark verification failed")
		}
		addresses, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "address", "show", "dev", link.InterfaceName}, nil))
		if err != nil || !exactInterfaceAddress(addresses.Stdout, link.LocalAddress) {
			return errors.New("Gateway Management Fabric address verification failed")
		}
		routeGet, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "get", link.EndpointAddress, "mark", strconv.FormatInt(link.UplinkMark, 10)}, nil))
		if err != nil || !exactRouteGet(routeGet.Stdout, link.UplinkInterface, link.UplinkGateway, link.UplinkTable) {
			return errors.New("Gateway Management Fabric endpoint policy route verification failed")
		}
		endpointPrefix := netip.PrefixFrom(netip.MustParseAddr(link.EndpointAddress), 32).String()
		endpointRoute, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "show", "table", strconv.FormatInt(link.UplinkTable, 10), "exact", endpointPrefix, "dev", link.UplinkInterface, "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
		if err != nil || !exactOwnedEndpointRoute(endpointRoute.Stdout, endpointPrefix, link.UplinkInterface, link.UplinkGateway) {
			return errors.New("Gateway Management Fabric endpoint host route verification failed")
		}
		for _, route := range link.Routes {
			result, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "show", "table", "main", "exact", route.Destination, "dev", link.InterfaceName, "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
			if err != nil || !exactOwnedRoute(result.Stdout, route.Destination, link.InterfaceName) {
				return errors.New("Gateway Management Fabric owned route verification failed")
			}
		}
	}
	if plan.AdminContour != nil {
		contour := plan.AdminContour
		for _, check := range []struct {
			args []string
			want string
		}{
			{[]string{"show", contour.InterfaceName, "public-key"}, contour.PublicKey},
			{[]string{"show", contour.InterfaceName, "listen-port"}, strconv.Itoa(contour.ListenPort)},
		} {
			result, err := applier.Executor.Run(ctx, request(applier.Paths.WG, check.args, nil))
			if err != nil || strings.TrimSpace(result.Stdout) != check.want {
				return errors.New("Gateway administrator WireGuard identity verification failed")
			}
		}
		peerResult, err := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"show", contour.InterfaceName, "peers"}, nil))
		if err != nil {
			return errors.New("read Gateway administrator peer set failed")
		}
		actualPeers := strings.Fields(peerResult.Stdout)
		expectedPeers := make([]string, 0, len(contour.Peers))
		for _, peer := range contour.Peers {
			expectedPeers = append(expectedPeers, peer.PublicKey)
			route, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "show", "table", "main", "exact", peer.AssignedAddress, "dev", contour.InterfaceName, "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)}, nil))
			if err != nil || !exactOwnedRoute(route.Stdout, peer.AssignedAddress, contour.InterfaceName) {
				return errors.New("Gateway administrator owned route verification failed")
			}
		}
		sort.Strings(actualPeers)
		sort.Strings(expectedPeers)
		if !reflect.DeepEqual(actualPeers, expectedPeers) {
			return errors.New("Gateway administrator peer set differs from plan")
		}
		addresses, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "address", "show", "dev", contour.InterfaceName}, nil))
		if err != nil || !exactInterfaceAddress(addresses.Stdout, contour.GatewayAddress) {
			return errors.New("Gateway administrator address verification failed")
		}
	}
	if err := applier.verifyOwnedInterfaceInventory(ctx, plan); err != nil {
		return err
	}
	firewall, err := applier.Executor.Run(ctx, request(applier.Paths.NFT, []string{"list", "table", "inet", "gateway_vpn"}, nil))
	marker := fmt.Sprintf("gateway-vpn management fabric generation %d plan %s", plan.Generation, planDigest(plan))
	if err != nil || !strings.Contains(firewall.Stdout, marker) {
		return errors.New("Gateway Management Fabric firewall verification failed")
	}
	return nil
}

func (applier *Applier) preflightKeys(plan managementfabric.GatewayHostPlan) error {
	for _, link := range plan.Links {
		content, err := applier.readSecret(link.PrivateKeyRef)
		if err != nil {
			return err
		}
		key := strings.TrimSpace(string(content))
		public, keyErr := wgingress.PublicKey(key)
		for index := range content {
			content[index] = 0
		}
		if keyErr != nil || public != link.LocalPublicKey {
			return fmt.Errorf("Gateway Management Fabric private key for %s does not match its public identity", link.LinkID)
		}
	}
	if plan.AdminContour != nil {
		content, err := applier.readSecret(plan.AdminContour.PrivateKeySecretRef)
		if err != nil {
			return err
		}
		public, keyErr := wgingress.PublicKey(strings.TrimSpace(string(content)))
		for index := range content {
			content[index] = 0
		}
		if keyErr != nil || public != plan.AdminContour.PublicKey {
			return errors.New("Gateway administrator private key does not match its public identity")
		}
	}
	return nil
}

func (applier *Applier) preflightInterfaces(ctx context.Context, target, previous managementfabric.GatewayHostPlan, hasPrevious bool) error {
	owned := make(map[string]struct{}, len(previous.Links))
	if hasPrevious {
		for _, link := range previous.Links {
			owned[link.InterfaceName] = struct{}{}
		}
		if previous.AdminContour != nil {
			owned[previous.AdminContour.InterfaceName] = struct{}{}
		}
	}
	names, err := applier.interfaceNames(ctx)
	if err != nil {
		return errors.New("inspect Gateway Management Fabric interface inventory failed")
	}
	for name := range names {
		if !reservedInterfaceName(name) {
			continue
		}
		if _, exists := owned[name]; !exists {
			return fmt.Errorf("Gateway Management Fabric reserved interface %s exists outside the applied receipt", name)
		}
	}
	for _, link := range target.Links {
		if _, exists := owned[link.InterfaceName]; exists {
			continue
		}
		result, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "link", "show", "dev", link.InterfaceName}, nil))
		if err != nil || strings.TrimSpace(result.Stdout) == "" || strings.TrimSpace(result.Stdout) == "[]" {
			continue
		}
		if link.InterfaceName != "wg-mgmt" {
			return fmt.Errorf("Gateway Management Fabric interface %s already exists outside the applied receipt", link.InterfaceName)
		}
		public, keyErr := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"show", link.InterfaceName, "public-key"}, nil))
		if keyErr != nil || strings.TrimSpace(public.Stdout) != link.LocalPublicKey {
			return errors.New("legacy wg-mgmt interface does not match the adopted slot-0 identity")
		}
	}
	if target.AdminContour != nil {
		if _, exists := owned[target.AdminContour.InterfaceName]; !exists {
			result, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "link", "show", "dev", target.AdminContour.InterfaceName}, nil))
			if err == nil && strings.TrimSpace(result.Stdout) != "" && strings.TrimSpace(result.Stdout) != "[]" {
				return errors.New("Gateway administrator interface exists outside the applied receipt")
			}
		}
	}
	return nil
}

func (applier *Applier) interfaceNames(ctx context.Context) (map[string]struct{}, error) {
	result, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "link", "show"}, nil))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Name string `json:"ifname"`
	}
	if json.Unmarshal([]byte(result.Stdout), &rows) != nil {
		return nil, errors.New("decode interface inventory failed")
	}
	names := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.Name == "" {
			return nil, errors.New("interface inventory contains an empty name")
		}
		names[row.Name] = struct{}{}
	}
	return names, nil
}

func (applier *Applier) verifyOwnedInterfaceInventory(ctx context.Context, plan managementfabric.GatewayHostPlan) error {
	names, err := applier.interfaceNames(ctx)
	if err != nil {
		return errors.New("verify Gateway Management Fabric interface inventory failed")
	}
	expected := make(map[string]struct{}, len(plan.Links))
	for _, link := range plan.Links {
		if reservedInterfaceName(link.InterfaceName) {
			expected[link.InterfaceName] = struct{}{}
		}
	}
	if plan.AdminContour != nil {
		expected[plan.AdminContour.InterfaceName] = struct{}{}
	}
	for name := range names {
		if !reservedInterfaceName(name) {
			continue
		}
		if _, exists := expected[name]; !exists {
			return fmt.Errorf("stale Gateway Management Fabric interface %s remains outside the target plan", name)
		}
		delete(expected, name)
	}
	if len(expected) != 0 {
		return errors.New("target Gateway Management Fabric interface is missing from inventory")
	}
	return nil
}

func reservedInterfaceName(name string) bool {
	if name == managementfabric.AdminInterfaceName {
		return true
	}
	if !strings.HasPrefix(name, "gvm") || len(name) <= 3 || name[3] == '0' {
		return false
	}
	value, err := strconv.ParseUint(name[3:], 10, 32)
	return err == nil && value > 0 && name == "gvm"+strconv.FormatUint(value, 10)
}

func (applier *Applier) readSecret(path string) ([]byte, error) {
	cleanPath, err := applier.secretPath(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(cleanPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 40 || info.Size() > 256 {
		return nil, errors.New("Gateway Management Fabric private key file is unsafe")
	}
	if applier.Paths.RequireRootOwnership {
		if err := validateRootOwned(info, 0o600); err != nil {
			return nil, errors.New("Gateway Management Fabric private key ownership is unsafe")
		}
	}
	content, err := os.ReadFile(cleanPath)
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("read Gateway Management Fabric private key failed")
	}
	return content, nil
}

func (applier *Applier) secretPath(reference string) (string, error) {
	prefix := strings.TrimSuffix(applier.Paths.SecretReferenceRoot, "/") + "/"
	if !strings.HasPrefix(reference, prefix) {
		return "", errors.New("Gateway Management Fabric secret escaped its reference root")
	}
	relative := strings.TrimPrefix(reference, prefix)
	if relative == "" || strings.Contains(relative, "..") || strings.Contains(relative, "\\") || strings.Contains(relative, "/") || strings.HasPrefix(relative, "/") {
		return "", errors.New("Gateway Management Fabric secret reference is unsafe")
	}
	cleanRoot := filepath.Clean(applier.Paths.SecretRoot)
	cleanPath := filepath.Join(cleanRoot, filepath.FromSlash(relative))
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", errors.New("Gateway Management Fabric secret escaped its root")
	}
	return cleanPath, nil
}

func sameMark(value string, expected int64) bool {
	base := 10
	if strings.HasPrefix(value, "0x") {
		base, value = 16, strings.TrimPrefix(value, "0x")
	}
	parsed, err := strconv.ParseInt(value, base, 64)
	return err == nil && parsed == expected
}

func exactInterfaceAddress(payload, expected string) bool {
	prefix, err := netip.ParsePrefix(expected)
	if err != nil {
		return false
	}
	var rows []struct {
		Info []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(payload), &rows) != nil || len(rows) != 1 || len(rows[0].Info) != 1 {
		return false
	}
	item := rows[0].Info[0]
	return item.Family == "inet" && item.Local == prefix.Addr().String() && item.Prefix == prefix.Bits()
}

func exactRouteGet(payload, device, gateway string, table int64) bool {
	var rows []struct {
		Device  string `json:"dev"`
		Gateway string `json:"gateway"`
		Table   any    `json:"table"`
	}
	if json.Unmarshal([]byte(payload), &rows) != nil || len(rows) != 1 || rows[0].Device != device || rows[0].Gateway != gateway {
		return false
	}
	return numericTable(rows[0].Table) == table
}

func numericTable(value any) int64 {
	switch item := value.(type) {
	case float64:
		return int64(item)
	case string:
		parsed, _ := strconv.ParseInt(item, 10, 64)
		return parsed
	default:
		return 0
	}
}

func exactOwnedRoute(payload, destination, device string) bool {
	var rows []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
		Protocol    any    `json:"protocol"`
	}
	if json.Unmarshal([]byte(payload), &rows) != nil || len(rows) != 1 {
		return false
	}
	row := rows[0]
	return canonicalRouteDestination(row.Destination) == canonicalRouteDestination(destination) && (row.Device == "" || row.Device == device) && ownedProtocol(row.Protocol)
}

func exactOwnedEndpointRoute(payload, destination, device, gateway string) bool {
	var rows []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
		Gateway     string `json:"gateway"`
		Protocol    any    `json:"protocol"`
	}
	if json.Unmarshal([]byte(payload), &rows) != nil || len(rows) != 1 {
		return false
	}
	row := rows[0]
	return canonicalRouteDestination(row.Destination) == canonicalRouteDestination(destination) && (row.Device == "" || row.Device == device) && row.Gateway == gateway && ownedProtocol(row.Protocol)
}

func canonicalRouteDestination(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String()
	}
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(address, bits).String()
	}
	return ""
}

func ownedProtocol(value any) bool {
	switch item := value.(type) {
	case nil:
		return true
	case float64:
		return int(item) == managementfabric.OwnedRouteProtocol
	case string:
		return item == "186" || item == "bgp"
	default:
		return false
	}
}

func emptyPlan(generation int64) managementfabric.GatewayHostPlan {
	return managementfabric.GatewayHostPlan{Generation: generation, RouteProtocol: managementfabric.OwnedRouteProtocol}
}

func request(executable string, arguments []string, stdin []byte) platformexec.Request {
	return platformexec.Request{Executable: executable, Arguments: arguments, Stdin: stdin, MaxOutputBytes: 2 << 20}
}

func (applier *Applier) validate() error {
	if applier == nil || applier.Repository == nil || applier.Repository.Database == nil || applier.Executor == nil {
		return errors.New("complete Gateway Management Fabric applier is required")
	}
	for _, path := range []string{applier.Paths.TransactionRoot, applier.Paths.SecretRoot, applier.Paths.IP, applier.Paths.NFT, applier.Paths.WG, applier.Paths.Ping} {
		if !filepath.IsAbs(path) {
			return errors.New("Gateway Management Fabric paths must be absolute")
		}
	}
	if applier.Paths.SecretReferenceRoot != "/var/lib/gateway-vpn/secrets/management" {
		return errors.New("Gateway Management Fabric secret reference root is invalid")
	}
	if err := secureDirectory(applier.Paths.TransactionRoot); err != nil {
		return err
	}
	if applier.Paths.RequireRootOwnership {
		for _, directory := range []string{applier.Paths.TransactionRoot, applier.Paths.SecretRoot} {
			info, err := os.Lstat(directory)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || validateRootOwned(info, 0o700) != nil {
				return errors.New("Gateway Management Fabric root-owned directory is unsafe")
			}
		}
	}
	return nil
}

func (applier *Applier) writeReceipt(receipt Receipt) error {
	if receipt.FormatVersion != gatewayJournalVersion || receipt.Generation != receipt.Plan.Generation || managementfabric.ValidateGatewayHostPlan(receipt.Plan) != nil || receipt.AppliedState.Generation != receipt.Generation {
		return errors.New("Gateway Management Fabric receipt is invalid")
	}
	receipt.PlanSHA256 = planDigest(receipt.Plan)
	content, _ := json.MarshalIndent(receipt, "", "  ")
	return atomicWrite(applier.receiptPath(), append(content, '\n'), 0o600)
}

func (applier *Applier) readReceipt() (Receipt, bool, error) {
	content, err := readProtected(applier.receiptPath(), 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var receipt Receipt
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.FormatVersion != gatewayJournalVersion || receipt.Generation != receipt.Plan.Generation || receipt.PlanSHA256 != planDigest(receipt.Plan) || managementfabric.ValidateGatewayHostPlan(receipt.Plan) != nil || receipt.AppliedState.Generation != receipt.Generation {
		return Receipt{}, false, errors.New("Gateway Management Fabric receipt is invalid")
	}
	return receipt, true, nil
}

func (applier *Applier) writeJournal(journal transactionJournal) error {
	if err := validateJournal(journal); err != nil {
		return err
	}
	content, _ := json.MarshalIndent(journal, "", "  ")
	return atomicWrite(applier.journalPath(), append(content, '\n'), 0o600)
}

func (applier *Applier) readJournal() (transactionJournal, bool, error) {
	content, err := readProtected(applier.journalPath(), 32<<20)
	if errors.Is(err, os.ErrNotExist) {
		return transactionJournal{}, false, nil
	}
	if err != nil {
		return transactionJournal{}, false, err
	}
	var journal transactionJournal
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || validateJournal(journal) != nil {
		return transactionJournal{}, false, errors.New("Gateway Management Fabric recovery journal is invalid")
	}
	return journal, true, nil
}

func validateJournal(journal transactionJournal) error {
	if journal.FormatVersion != gatewayJournalVersion || managementfabric.ValidateGatewayHostPlan(journal.TargetPlan) != nil || journal.PreviousState.Generation < 0 {
		return errors.New("Gateway Management Fabric journal contract is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, journal.StartedAt); err != nil {
		return errors.New("Gateway Management Fabric journal start time is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, journal.UpdatedAt); err != nil {
		return errors.New("Gateway Management Fabric journal update time is invalid")
	}
	if journal.PreviousReceipt != nil {
		item := journal.PreviousReceipt
		if item.FormatVersion != gatewayJournalVersion || item.PlanSHA256 != planDigest(item.Plan) || item.Generation != item.Plan.Generation || item.AppliedState.Generation != item.Generation || managementfabric.ValidateGatewayHostPlan(item.Plan) != nil || journal.PreviousState.Generation != item.Generation {
			return errors.New("Gateway Management Fabric previous receipt is invalid")
		}
	} else if journal.PreviousState.Generation != 0 {
		return errors.New("Gateway Management Fabric journal lost its previous receipt")
	}
	switch journal.State {
	case gatewayPrepared, gatewayApplying, gatewayCommitted, gatewayRolledBack:
		return nil
	default:
		return errors.New("Gateway Management Fabric journal state is invalid")
	}
}

func (applier *Applier) cleanupTransaction() error {
	if err := removeRegular(applier.journalPath()); err != nil {
		return err
	}
	return syncDirectory(applier.Paths.TransactionRoot)
}

func (applier *Applier) receiptPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "applied.json")
}
func (applier *Applier) journalPath() string {
	return filepath.Join(applier.Paths.TransactionRoot, "transaction.json")
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
		return errors.New("Gateway Management Fabric transaction directory is unsafe")
	}
	return nil
}

func readProtected(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("Gateway Management Fabric protected file is unsafe")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("read Gateway Management Fabric protected file failed")
	}
	return content, nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Gateway Management Fabric destination directory is unsafe")
	}
	if current, err := os.Lstat(path); err == nil && (current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular()) {
		return errors.New("Gateway Management Fabric destination is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gateway-vpn-management-fabric-")
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
		return errors.New("refuse to remove unsafe Gateway Management Fabric file")
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

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func sortedStrings(values []string) []string {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	return copy
}
