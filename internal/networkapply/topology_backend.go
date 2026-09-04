package networkapply

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"

	"go.yaml.in/yaml/v3"
)

type TopologyPathGate interface {
	BlockPath(context.Context) error
}

type TopologyRoutingSynchronizer interface {
	SyncRouting(context.Context) error
}

type TopologyRuntimeContext interface {
	SetTopologyNetwork(string, string) error
}

type TopologyIngressController interface {
	UpdateServer(context.Context, wgingress.ServerUpdate) (wgingress.Server, error)
	Sync(context.Context) error
}

type topologyProfileSnapshot struct {
	ActiveProfile     string `json:"active_profile"`
	DesiredGeneration int64  `json:"desired_generation"`
	AppliedGeneration int64  `json:"applied_generation"`
	State             string `json:"state"`
	LastErrorCode     string `json:"last_error_code"`
	UpdatedAt         string `json:"updated_at"`
}

type topologyMemberSnapshot struct {
	NetworkInterfaceID string `json:"network_interface_id"`
	InterfaceName      string `json:"interface_name"`
	PathKind           string `json:"path_kind"`
	Existed            bool   `json:"existed"`
	SHA256             string `json:"sha256,omitempty"`
}

type topologySnapshot struct {
	Profile             topologyProfileSnapshot  `json:"profile"`
	Roles               []ethernetRoleSnapshot   `json:"roles"`
	Members             []topologyMemberSnapshot `json:"members"`
	Ingress             wgingress.Server         `json:"ingress"`
	IngressExists       bool                     `json:"ingress_exists"`
	LANNetDevExisted    bool                     `json:"lan_netdev_existed"`
	LANNetworkExisted   bool                     `json:"lan_network_existed"`
	DNSMasqExisted      bool                     `json:"dnsmasq_existed"`
	DNSMasqWasActive    bool                     `json:"dnsmasq_was_active"`
	PreviousLANIfname   string                   `json:"previous_lan_ifname"`
	PreviousLANCIDR     string                   `json:"previous_lan_cidr"`
	CandidateGeneration int64                    `json:"candidate_generation"`
	EthernetUplinkIDs   []string                 `json:"ethernet_uplink_ids,omitempty"`
}

type topologyInterface struct {
	ID      string
	Ifname  string
	Carrier string
	Roles   map[string]string
}

func (backend UbuntuBackend) PreviewTopology(ctx context.Context, manifest Manifest) (TopologyPreview, error) {
	if err := backend.validateTopologyBackend(); err != nil {
		return TopologyPreview{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return TopologyPreview{}, err
	}
	current, interfaces, err := backend.validateTopologyProtectedState(ctx, manifest, false)
	if err != nil {
		return TopologyPreview{}, err
	}
	configuration, err := config.Load(backend.Paths.ConfigFile)
	if err != nil {
		return TopologyPreview{}, err
	}
	managementIfnames := topologyManagementIfnames(manifest.Topology, interfaces)
	if _, _, apiPort, err := renderTopologyConfigs(configuration, manifest, managementIfnames); err != nil {
		return TopologyPreview{}, err
	} else if _, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: manifest.Topology.LANInterfaceName, ManagementInterfaces: managementIfnames,
		TUNInterface: configuration.Mihomo.TunName, WireGuardInterface: "wg-mgmt",
		APIPort: apiPort, WireGuardListenPort: 51821,
		DisableSSHManagement: configuration.Network.DisableSSHManagement,
	}); err != nil {
		return TopologyPreview{}, err
	}
	if manifest.Topology.DHCPDNSEnabled {
		if _, err := renderLANNetDev(manifest.Topology.LANInterfaceName); err != nil {
			return TopologyPreview{}, err
		}
		if _, err := renderLANNetwork(manifest.Topology.LANInterfaceName, manifest.Topology.LANAddress); err != nil {
			return TopologyPreview{}, err
		}
		if _, err := renderDNSMasq(manifest.Topology.LANInterfaceName, manifest.Topology.LANAddress); err != nil {
			return TopologyPreview{}, err
		}
	}
	for _, id := range manifest.Topology.LANInterfaceIDs {
		if _, err := renderTopologyMember(interfaces[id].Ifname, manifest.Topology.LANInterfaceName); err != nil {
			return TopologyPreview{}, err
		}
	}
	required := topologyPrerequisites(manifest.Topology, interfaces)
	acknowledged := stringSet(manifest.Topology.AcknowledgedPrerequisites)
	missing := make([]string, 0, len(required))
	for _, value := range required {
		if _, exists := acknowledged[value]; !exists {
			missing = append(missing, value)
		}
	}
	return TopologyPreview{
		CurrentProfile: current.ActiveProfile, CandidateProfile: manifest.Topology.Profile,
		CurrentDesiredGeneration: current.DesiredGeneration, CandidateDesiredGeneration: current.DesiredGeneration + 1,
		OldURL: manifest.OldURL, NewURL: manifest.NewURL,
		RequiredPrerequisites: required, MissingPrerequisites: missing,
		RequireWireGuardConfirmation: manifest.RequireWireGuardConfirmation,
		ManagementInterfaces:         managementIfnames,
		AffectedInterfaces:           topologyAffectedIfnames(interfaces, manifest.Topology, configuration.Network.LANInterface, manifest.Topology.LANInterfaceName),
	}, nil
}

func (backend UbuntuBackend) snapshotTopology(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateTopologyBackend(); err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	current, interfaces, err := backend.validateTopologyProtectedState(ctx, manifest, true)
	if err != nil {
		return err
	}
	snapshotDirectory, candidateDirectory, err := prepareBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	configuration, err := config.Load(backend.Paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("load topology source configuration: %w", err)
	}
	snapshot := topologySnapshot{
		Profile: current, PreviousLANIfname: configuration.Network.LANInterface,
		PreviousLANCIDR:     configuration.Network.LANAddress,
		CandidateGeneration: current.DesiredGeneration + 1,
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		snapshot.EthernetUplinkIDs = append(snapshot.EthernetUplinkIDs, item.ID)
	}
	snapshot.Roles, err = backend.snapshotTopologyRoles(ctx)
	if err != nil {
		return err
	}
	if err := snapshotRequiredFile(backend.Paths.ConfigFile, filepath.Join(snapshotDirectory, "config.yaml")); err != nil {
		return fmt.Errorf("snapshot topology configuration: %w", err)
	}
	if err := snapshotRequiredFile(backend.Paths.BootNFTFile, filepath.Join(snapshotDirectory, "boot.nft")); err != nil {
		return fmt.Errorf("snapshot topology firewall: %w", err)
	}
	snapshot.LANNetworkExisted, err = snapshotOptionalFile(backend.Paths.LANNetworkFile, filepath.Join(snapshotDirectory, "lan.network"))
	if err != nil {
		return fmt.Errorf("snapshot topology LAN networkd policy: %w", err)
	}
	snapshot.LANNetDevExisted, err = snapshotOptionalFile(backend.Paths.LANNetDevFile, filepath.Join(snapshotDirectory, "lan.netdev"))
	if err != nil {
		return fmt.Errorf("snapshot topology LAN netdev policy: %w", err)
	}
	snapshot.DNSMasqExisted, err = snapshotOptionalFile(backend.Paths.DNSMasqFile, filepath.Join(snapshotDirectory, "dnsmasq.conf"))
	if err != nil {
		return fmt.Errorf("snapshot topology dnsmasq policy: %w", err)
	}
	snapshot.DNSMasqWasActive = backend.serviceActive(ctx, "gateway-vpn-dnsmasq.service")
	runtimeFirewall, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.NFT, Arguments: []string{"list", "table", "inet", firewall.TableName}})
	if err != nil || !strings.Contains(runtimeFirewall.Stdout, "table inet "+firewall.TableName) {
		return errors.New("snapshot topology runtime firewall failed")
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "runtime-firewall.nft"), []byte(runtimeFirewall.Stdout), 0o600); err != nil {
		return err
	}

	interfaceIDs := make([]string, 0, len(interfaces))
	for id := range interfaces {
		interfaceIDs = append(interfaceIDs, id)
	}
	sort.Strings(interfaceIDs)
	for _, id := range interfaceIDs {
		item := interfaces[id]
		for _, kind := range []string{"stable", "legacy"} {
			member := topologyMemberSnapshot{NetworkInterfaceID: id, InterfaceName: item.Ifname, PathKind: kind}
			path, pathErr := backend.topologySnapshotMemberPath(member)
			if pathErr != nil {
				return pathErr
			}
			exists, content, readErr := readOptionalRegular(path, 1<<20)
			if readErr != nil {
				return fmt.Errorf("snapshot topology member %s (%s): %w", id, kind, readErr)
			}
			member.Existed = exists
			if exists {
				digest := sha256.Sum256(content)
				member.SHA256 = hex.EncodeToString(digest[:])
				if err := atomicWrite(filepath.Join(snapshotDirectory, topologyMemberSnapshotName(id, kind)), content, 0o600); err != nil {
					return err
				}
			}
			snapshot.Members = append(snapshot.Members, member)
		}
	}
	if server, ingressErr := (wgingress.Repository{Database: backend.Database}).GetServer(ctx); ingressErr == nil {
		snapshot.Ingress, snapshot.IngressExists = server, true
	} else if !errors.Is(ingressErr, store.ErrNotFound) {
		return fmt.Errorf("snapshot WireGuard ingress topology: %w", ingressErr)
	}

	managementIfnames := topologyManagementIfnames(manifest.Topology, interfaces)
	graceConfig, finalConfig, apiPort, err := renderTopologyConfigs(configuration, manifest, managementIfnames)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(candidateDirectory, "config-grace.yaml"), graceConfig, 0o600); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(candidateDirectory, "config-final.yaml"), finalConfig, 0o600); err != nil {
		return err
	}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: manifest.Topology.LANInterfaceName, TUNInterface: configuration.Mihomo.TunName,
		ManagementInterfaces: managementIfnames,
		WireGuardInterface:   "wg-mgmt", APIPort: apiPort, WireGuardListenPort: 51821,
		DisableSSHManagement: configuration.Network.DisableSSHManagement,
	})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(candidateDirectory, "boot.nft"), []byte(ruleset.Text), 0o600); err != nil {
		return err
	}
	if manifest.Topology.DHCPDNSEnabled {
		lanNetDev, err := renderLANNetDev(manifest.Topology.LANInterfaceName)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(candidateDirectory, "lan.netdev"), []byte(lanNetDev), 0o600); err != nil {
			return err
		}
		lanNetwork, err := renderLANNetwork(manifest.Topology.LANInterfaceName, manifest.Topology.LANAddress)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(candidateDirectory, "lan.network"), []byte(lanNetwork), 0o600); err != nil {
			return err
		}
		dnsmasq, err := renderDNSMasq(manifest.Topology.LANInterfaceName, manifest.Topology.LANAddress)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(candidateDirectory, "dnsmasq.conf"), []byte(dnsmasq), 0o600); err != nil {
			return err
		}
	}
	for _, id := range manifest.Topology.LANInterfaceIDs {
		item := interfaces[id]
		content, err := renderTopologyMember(item.Ifname, manifest.Topology.LANInterfaceName)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(candidateDirectory, topologyMemberCandidateName(id)), []byte(content), 0o600); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "topology-state.json"), payload, 0o600); err != nil {
		return err
	}
	return syncDirectory(transactionDirectory)
}

func (backend UbuntuBackend) applyTopology(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateTopologyBackend(); err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	snapshotDirectory, candidateDirectory, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	snapshot, err := readTopologySnapshot(snapshotDirectory, manifest)
	if err != nil {
		return err
	}
	_, interfaces, err := backend.validateTopologyProtectedState(ctx, manifest, true)
	if err != nil {
		return err
	}
	if err := backend.TopologyGate.BlockPath(ctx); err != nil {
		return errors.New("close user data path before topology apply failed")
	}
	if err := backend.applyTopologyEthernet(ctx, manifest.Topology); err != nil {
		return err
	}
	if err := backend.applyTopologyDatabase(ctx, manifest, snapshot); err != nil {
		return err
	}
	if err := backend.TopologyContext.SetTopologyNetwork(manifest.Topology.LANInterfaceName, manifest.Topology.LANAddress); err != nil {
		return err
	}
	for _, id := range manifest.Topology.LANInterfaceIDs {
		candidate := filepath.Join(candidateDirectory, topologyMemberCandidateName(id))
		if err := installRegular(candidate, backend.topologyMemberPath(id), 0o644, -1); err != nil {
			return err
		}
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		configured, getErr := (uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)).Get(ctx, item.ID)
		if getErr != nil {
			return getErr
		}
		content, renderErr := renderEthernetNetwork(configured)
		if renderErr != nil {
			return renderErr
		}
		candidatePath := filepath.Join(candidateDirectory, "ethernet-"+item.ID+".network")
		if err := atomicWrite(candidatePath, []byte(content), 0o600); err != nil {
			return err
		}
		if err := installRegular(candidatePath, backend.ethernetOwnedPath(item.ID), 0o644, -1); err != nil {
			return err
		}
	}
	if manifest.Topology.DHCPDNSEnabled {
		if err := installRegular(filepath.Join(candidateDirectory, "lan.netdev"), backend.Paths.LANNetDevFile, 0o644, -1); err != nil {
			return err
		}
		if err := installRegular(filepath.Join(candidateDirectory, "lan.network"), backend.Paths.LANNetworkFile, 0o644, -1); err != nil {
			return err
		}
		if err := installRegular(filepath.Join(candidateDirectory, "dnsmasq.conf"), backend.Paths.DNSMasqFile, 0o640, backend.Paths.ConfigGID); err != nil {
			return err
		}
	}
	if err := installRegular(filepath.Join(candidateDirectory, "config-grace.yaml"), backend.Paths.ConfigFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	if err := installRegular(filepath.Join(candidateDirectory, "boot.nft"), backend.Paths.BootNFTFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	ruleset, err := loadRuleset(filepath.Join(candidateDirectory, "boot.nft"))
	if err != nil {
		return err
	}
	if err := firewall.ValidateAndLoad(ctx, backend.Executor, ruleset, firewall.LoadOptions{NFTExecutable: backend.Paths.NFT, Mutate: true}); err != nil {
		return err
	}
	newPrefix, _ := netip.ParsePrefix(manifest.Topology.LANAddress)
	if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "replace", newPrefix.String(), "dev", manifest.Topology.LANInterfaceName}}); err != nil {
		return errors.New("add candidate topology LAN address failed")
	}
	if err := backend.networkctlReload(ctx); err != nil {
		return err
	}
	for _, ifname := range topologyAffectedIfnames(interfaces, manifest.Topology, snapshot.PreviousLANIfname, manifest.Topology.LANInterfaceName) {
		if err := backend.networkctlReconfigure(ctx, ifname); err != nil {
			return err
		}
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		if err := backend.networkctlReconfigure(ctx, interfaces[item.NetworkInterfaceID].Ifname); err != nil {
			return err
		}
	}
	if manifest.Topology.DHCPDNSEnabled {
		if err := backend.controlService(ctx, "restart", "gateway-vpn-dnsmasq.service"); err != nil {
			return err
		}
	} else if err := backend.controlService(ctx, "stop", "gateway-vpn-dnsmasq.service"); err != nil {
		return err
	}
	if err := backend.applyTopologyIngress(ctx, manifest.Topology, snapshot.Ingress, snapshot.IngressExists); err != nil {
		return err
	}
	if err := backend.TopologyRouting.SyncRouting(ctx); err != nil {
		return errors.New("synchronize topology policy routing failed")
	}
	if err := backend.TopologyGate.BlockPath(ctx); err != nil {
		return errors.New("verify fail-closed topology candidate failed")
	}
	return backend.controlService(ctx, "restart", "gateway-vpn.service")
}

func (backend UbuntuBackend) applyTopologyEthernet(ctx context.Context, mutation *TopologyMutation) error {
	if mutation == nil || len(mutation.EthernetUplinks) == 0 {
		return nil
	}
	repository := uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)
	for _, item := range mutation.EthernetUplinks {
		input := uplink.CreateEthernetInput{ID: item.ID, Name: item.Name, NetworkInterfaceID: item.NetworkInterfaceID, AddressMode: item.AddressMode, IPv4CIDR: item.IPv4CIDR, Gateway: item.Gateway, DNS: append([]string(nil), item.DNS...), MTU: item.MTU}
		var created uplink.Uplink
		var err error
		if mutation.ExpectedDesiredGeneration == 1 && item.NetworkInterfaceID == mutation.SharedOneArmInterfaceID {
			created, err = repository.CreateInitialEthernet(ctx, input)
		} else {
			created, err = repository.CreateEthernet(ctx, input)
		}
		if err != nil {
			return fmt.Errorf("create topology Ethernet uplink %s: %w", item.ID, err)
		}
		content, err := renderEthernetNetwork(created)
		if err != nil {
			return err
		}
		candidatePath := filepath.Join(backend.Paths.EthernetNetworkDir, ".gateway-vpn-topology-"+item.ID+".network")
		if err := atomicWrite(candidatePath, []byte(content), 0o600); err != nil {
			return err
		}
		if err := installRegular(candidatePath, backend.ethernetOwnedPath(item.ID), 0o644, -1); err != nil {
			return err
		}
		_ = os.Remove(candidatePath)
	}
	return nil
}

func (backend UbuntuBackend) commitTopology(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateTopologyBackend(); err != nil {
		return err
	}
	snapshotDirectory, candidateDirectory, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	snapshot, err := readTopologySnapshot(snapshotDirectory, manifest)
	if err != nil {
		return err
	}
	var profile string
	var desired, applied int64
	var state string
	if err := backend.Database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state); err != nil {
		return err
	}
	finalizeGeneration := profile == manifest.Topology.Profile &&
		desired == snapshot.CandidateGeneration &&
		applied == snapshot.Profile.AppliedGeneration && state == "APPLYING"
	alreadyFinalized := profile == manifest.Topology.Profile &&
		desired == snapshot.CandidateGeneration &&
		applied == snapshot.CandidateGeneration && state == "ACTIVE"
	if !finalizeGeneration && !alreadyFinalized {
		return errors.New("topology desired state changed before confirmation")
	}
	candidateMembers := stringSet(manifest.Topology.LANInterfaceIDs)
	for _, member := range snapshot.Members {
		if _, keep := candidateMembers[member.NetworkInterfaceID]; keep && member.PathKind == "stable" {
			continue
		}
		path, pathErr := backend.topologySnapshotMemberPath(member)
		if pathErr != nil {
			return pathErr
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale topology LAN member: %w", err)
		}
	}
	if !manifest.Topology.DHCPDNSEnabled {
		for _, path := range []string{backend.Paths.LANNetDevFile, backend.Paths.LANNetworkFile, backend.Paths.DNSMasqFile} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove disabled LAN service policy: %w", err)
			}
		}
	}
	if err := installRegular(filepath.Join(candidateDirectory, "config-final.yaml"), backend.Paths.ConfigFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	oldPrefix, _ := netip.ParsePrefix(snapshot.PreviousLANCIDR)
	newPrefix, _ := netip.ParsePrefix(manifest.Topology.LANAddress)
	if snapshot.PreviousLANIfname != manifest.Topology.LANInterfaceName || oldPrefix.String() != newPrefix.String() {
		if present, observeErr := backend.addressPresent(ctx, snapshot.PreviousLANIfname, oldPrefix.String()); observeErr == nil && present {
			if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "del", oldPrefix.String(), "dev", snapshot.PreviousLANIfname}}); err != nil {
				return errors.New("remove previous topology LAN address failed")
			}
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if finalizeGeneration {
		result, err := backend.Database.ExecContext(ctx, `
UPDATE topology_profile_state
SET applied_generation=desired_generation,state='ACTIVE',last_error_code='',updated_at=?
WHERE singleton_id=1 AND desired_generation=? AND state='APPLYING'`, now, snapshot.CandidateGeneration)
		if err != nil {
			return err
		}
		if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
			return errors.New("confirm topology generation failed")
		}
		if _, err := backend.Database.ExecContext(ctx, `UPDATE interface_role_assignments SET observed_generation=desired_generation,state='ACTIVE',updated_at=? WHERE role IN ('LAN_MEMBER','MANAGEMENT','WG_ENDPOINT','SHARED_ONE_ARM')`, now); err != nil {
			return err
		}
	}
	if err := backend.networkctlReload(ctx); err != nil {
		return err
	}
	for _, ifname := range topologySnapshotAffectedIfnames(snapshot, manifest.Topology, manifest.Topology.LANInterfaceName) {
		if err := backend.networkctlReconfigure(ctx, ifname); err != nil {
			return err
		}
	}
	if err := backend.TopologyIngress.Sync(ctx); err != nil {
		return err
	}
	if err := backend.TopologyRouting.SyncRouting(ctx); err != nil {
		return err
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		configured, getErr := (uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)).Get(ctx, item.ID)
		if getErr != nil || configured.Type != uplink.TypeEthernet || configured.NetworkInterfaceID != item.NetworkInterfaceID || !configured.Enabled {
			return fmt.Errorf("topology Ethernet uplink %s did not converge", item.ID)
		}
		want, renderErr := renderEthernetNetwork(configured)
		if renderErr != nil {
			return renderErr
		}
		current, readErr := readBoundedRegular(backend.ethernetOwnedPath(item.ID), 1<<20)
		if readErr != nil || string(current) != want {
			return fmt.Errorf("topology Ethernet networkd policy %s did not converge", item.ID)
		}
	}
	return backend.controlService(ctx, "restart", "gateway-vpn.service")
}

func (backend UbuntuBackend) rollbackTopology(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateTopologyBackend(); err != nil {
		return err
	}
	snapshotDirectory, _, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	snapshot, err := readTopologySnapshot(snapshotDirectory, manifest)
	if err != nil {
		return err
	}
	var failures []error
	if err := backend.TopologyGate.BlockPath(ctx); err != nil {
		failures = append(failures, err)
	}
	if err := backend.restoreTopologyDatabase(ctx, manifest, snapshot); err != nil {
		failures = append(failures, err)
	}
	if err := backend.TopologyContext.SetTopologyNetwork(snapshot.PreviousLANIfname, snapshot.PreviousLANCIDR); err != nil {
		failures = append(failures, err)
	}
	for _, member := range snapshot.Members {
		path, pathErr := backend.topologySnapshotMemberPath(member)
		if pathErr != nil {
			failures = append(failures, pathErr)
			continue
		}
		if member.Existed {
			content, readErr := readBoundedRegular(filepath.Join(snapshotDirectory, topologyMemberSnapshotName(member.NetworkInterfaceID, member.PathKind)), 1<<20)
			if readErr != nil {
				failures = append(failures, readErr)
				continue
			}
			digest := sha256.Sum256(content)
			if hex.EncodeToString(digest[:]) != member.SHA256 {
				failures = append(failures, errors.New("topology member snapshot checksum mismatch"))
				continue
			}
			if err := installRegular(filepath.Join(snapshotDirectory, topologyMemberSnapshotName(member.NetworkInterfaceID, member.PathKind)), path, 0o644, -1); err != nil {
				failures = append(failures, err)
			}
		} else if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	for _, item := range []struct {
		existed bool
		source  string
		target  string
		mode    os.FileMode
		gid     int
	}{
		{true, "config.yaml", backend.Paths.ConfigFile, 0o640, backend.Paths.ConfigGID},
		{true, "boot.nft", backend.Paths.BootNFTFile, 0o640, backend.Paths.ConfigGID},
		{snapshot.LANNetDevExisted, "lan.netdev", backend.Paths.LANNetDevFile, 0o644, -1},
		{snapshot.LANNetworkExisted, "lan.network", backend.Paths.LANNetworkFile, 0o644, -1},
		{snapshot.DNSMasqExisted, "dnsmasq.conf", backend.Paths.DNSMasqFile, 0o640, backend.Paths.ConfigGID},
	} {
		if item.existed {
			if err := installRegular(filepath.Join(snapshotDirectory, item.source), item.target, item.mode, item.gid); err != nil {
				failures = append(failures, err)
			}
		} else if err := os.Remove(item.target); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		if err := os.Remove(backend.ethernetOwnedPath(item.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove rolled-back topology Ethernet networkd policy %s: %w", item.ID, err))
		}
	}
	if snapshot.IngressExists {
		if err := backend.restoreTopologyIngress(ctx, snapshot.Ingress); err != nil {
			failures = append(failures, err)
		}
	}
	if err := backend.networkctlReload(ctx); err != nil {
		failures = append(failures, err)
	}
	for _, ifname := range topologySnapshotAffectedIfnames(snapshot, manifest.Topology, manifest.Topology.LANInterfaceName) {
		if err := backend.networkctlReconfigure(ctx, ifname); err != nil {
			failures = append(failures, err)
		}
	}
	oldPrefix, oldErr := netip.ParsePrefix(snapshot.PreviousLANCIDR)
	newPrefix, newErr := netip.ParsePrefix(manifest.Topology.LANAddress)
	if oldErr != nil || newErr != nil {
		failures = append(failures, errors.New("topology rollback address snapshot is invalid"))
	} else {
		if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "replace", oldPrefix.String(), "dev", snapshot.PreviousLANIfname}}); err != nil {
			failures = append(failures, errors.New("restore previous topology LAN address failed"))
		}
		if snapshot.PreviousLANIfname != manifest.Topology.LANInterfaceName || oldPrefix.String() != newPrefix.String() {
			if present, observeErr := backend.addressPresent(ctx, manifest.Topology.LANInterfaceName, newPrefix.String()); observeErr != nil {
				failures = append(failures, observeErr)
			} else if present {
				if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "del", newPrefix.String(), "dev", manifest.Topology.LANInterfaceName}}); err != nil {
					failures = append(failures, errors.New("remove rolled-back topology LAN address failed"))
				}
			}
		}
	}
	if err := backend.TopologyRouting.SyncRouting(ctx); err != nil {
		failures = append(failures, err)
	}
	if snapshot.DNSMasqWasActive {
		if err := backend.controlService(ctx, "restart", "gateway-vpn-dnsmasq.service"); err != nil {
			failures = append(failures, err)
		}
	} else if err := backend.controlService(ctx, "stop", "gateway-vpn-dnsmasq.service"); err != nil {
		failures = append(failures, err)
	}
	if err := backend.controlService(ctx, "restart", "gateway-vpn.service"); err != nil {
		failures = append(failures, err)
	}
	// The snapshot can contain an active path.  Reopen it only after every
	// network, routing, ingress and service rollback step has succeeded;
	// otherwise retaining PATH_BLOCKED is the only safe terminal state.
	if len(failures) == 0 {
		runtimeRuleset, loadErr := loadRuleset(filepath.Join(snapshotDirectory, "runtime-firewall.nft"))
		if loadErr != nil {
			failures = append(failures, loadErr)
		} else if err := firewall.ValidateAndLoad(ctx, backend.Executor, runtimeRuleset, firewall.LoadOptions{NFTExecutable: backend.Paths.NFT, Mutate: true}); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (backend UbuntuBackend) validateTopologyBackend() error {
	if err := backend.validateEthernetBackend(); err != nil {
		return err
	}
	if backend.TopologyGate == nil || backend.TopologyRouting == nil || backend.TopologyIngress == nil || backend.TopologyContext == nil {
		return errors.New("topology safe-apply reconcilers are incomplete")
	}
	return nil
}

func (backend UbuntuBackend) validateTopologyProtectedState(ctx context.Context, manifest Manifest, requirePrerequisites bool) (topologyProfileSnapshot, map[string]topologyInterface, error) {
	mutation := manifest.Topology
	var profile topologyProfileSnapshot
	if err := backend.Database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state,last_error_code,updated_at FROM topology_profile_state WHERE singleton_id=1`).Scan(
		&profile.ActiveProfile, &profile.DesiredGeneration, &profile.AppliedGeneration, &profile.State, &profile.LastErrorCode, &profile.UpdatedAt,
	); err != nil {
		return profile, nil, fmt.Errorf("read protected topology generation: %w", err)
	}
	if profile.DesiredGeneration != mutation.ExpectedDesiredGeneration || profile.DesiredGeneration != profile.AppliedGeneration || profile.State != "ACTIVE" {
		return profile, nil, errors.New("topology generation is stale or not converged")
	}
	configuration, err := config.Load(backend.Paths.ConfigFile)
	if err != nil {
		return profile, nil, err
	}
	if mutation.Profile == TopologyOneArmWireGuard || mutation.Profile == TopologyMixed && mutation.SharedOneArmInterfaceID != "" && len(mutation.LANInterfaceIDs) == 0 {
		server, ingressErr := (wgingress.Repository{Database: backend.Database}).GetServer(ctx)
		if ingressErr != nil || server.ServerAddress != mutation.LANAddress {
			return profile, nil, errors.New("one-arm topology LAN address must equal the initialized WireGuard ingress server address")
		}
	}
	if err := backend.validateTopologySubnetConflicts(ctx, mutation, configuration); err != nil {
		return profile, nil, err
	}
	interfaces, err := backend.loadTopologyInterfaces(ctx)
	if err != nil {
		return profile, nil, err
	}
	candidateUplinks := make(map[string]TopologyEthernetUplink, len(mutation.EthernetUplinks))
	for _, candidate := range mutation.EthernetUplinks {
		var existing int
		if err := backend.Database.QueryRowContext(ctx, `SELECT COUNT(*) FROM uplinks WHERE id=? OR network_interface_id=?`, candidate.ID, candidate.NetworkInterfaceID).Scan(&existing); err != nil {
			return profile, nil, err
		}
		if existing != 0 {
			return profile, nil, fmt.Errorf("candidate Ethernet uplink %s already exists", candidate.ID)
		}
		item, exists := interfaces[candidate.NetworkInterfaceID]
		if !exists || !validInterfaceName(item.Ifname) || item.Carrier == "ABSENT" {
			return profile, nil, fmt.Errorf("candidate Ethernet interface %s is absent", candidate.NetworkInterfaceID)
		}
		for role := range item.Roles {
			initialSharedRole := mutation.ExpectedDesiredGeneration == 1 && candidate.NetworkInterfaceID == mutation.SharedOneArmInterfaceID && (role == "LAN_MEMBER" || role == "MANAGEMENT")
			currentSharedRole := candidate.NetworkInterfaceID == mutation.SharedOneArmInterfaceID && role == "SHARED_ONE_ARM"
			if role != "UNUSED" && !currentSharedRole && !initialSharedRole {
				return profile, nil, fmt.Errorf("candidate Ethernet interface %s already has role %s", candidate.NetworkInterfaceID, role)
			}
		}
		candidateUplinks[candidate.NetworkInterfaceID] = candidate
	}
	assigned := append(append(append([]string(nil), mutation.LANInterfaceIDs...), mutation.ManagementInterfaceIDs...), mutation.WGEndpointInterfaceIDs...)
	if mutation.SharedOneArmInterfaceID != "" {
		assigned = append(assigned, mutation.SharedOneArmInterfaceID)
	}
	for _, id := range assigned {
		item, exists := interfaces[id]
		if !exists || !validInterfaceName(item.Ifname) || item.Carrier == "ABSENT" {
			return profile, nil, fmt.Errorf("candidate interface %s is absent or has no protected kernel name", id)
		}
	}
	lanSet := stringSet(mutation.LANInterfaceIDs)
	for id := range lanSet {
		for role := range interfaces[id].Roles {
			if role == "ETHERNET_UPLINK" || role == "HILINK_UPLINK" {
				return profile, nil, fmt.Errorf("LAN member %s is already a dedicated uplink", id)
			}
		}
	}
	if mutation.SharedOneArmInterfaceID != "" {
		_, createsSharedUplink := candidateUplinks[mutation.SharedOneArmInterfaceID]
		if interfaces[mutation.SharedOneArmInterfaceID].Roles["ETHERNET_UPLINK"] == "" && !createsSharedUplink {
			return profile, nil, errors.New("shared one-arm interface must own an Ethernet uplink")
		}
	}
	var enabledHiLink, enabledEthernet int
	if err := backend.Database.QueryRowContext(ctx, `SELECT COUNT(*) FROM uplinks WHERE enabled=1 AND type='HILINK'`).Scan(&enabledHiLink); err != nil {
		return profile, nil, err
	}
	if err := backend.Database.QueryRowContext(ctx, `SELECT COUNT(*) FROM uplinks WHERE enabled=1 AND type='ETHERNET'`).Scan(&enabledEthernet); err != nil {
		return profile, nil, err
	}
	switch mutation.Profile {
	case TopologyEthernetHiLink:
		if enabledHiLink == 0 {
			return profile, nil, errors.New("Ethernet to HiLink profile requires an enabled HiLink uplink")
		}
	case TopologyEthernetEthernet, TopologyOneArmWireGuard:
		if enabledEthernet+len(mutation.EthernetUplinks) == 0 {
			return profile, nil, errors.New("selected profile requires an enabled Ethernet uplink")
		}
	case TopologyMixed:
		if enabledHiLink+enabledEthernet+len(mutation.EthernetUplinks) == 0 {
			return profile, nil, errors.New("mixed profile requires at least one enabled uplink")
		}
	}
	if err := backend.validateTopologyManagementSafety(ctx, manifest, interfaces); err != nil {
		return profile, nil, err
	}
	if requirePrerequisites {
		if err := validateTopologyPrerequisites(mutation, interfaces); err != nil {
			return profile, nil, err
		}
	}
	return profile, interfaces, nil
}

func (backend UbuntuBackend) validateTopologyManagementSafety(ctx context.Context, manifest Manifest, interfaces map[string]topologyInterface) error {
	currentManagement := make(map[string]struct{})
	for id, item := range interfaces {
		if _, exists := item.Roles["MANAGEMENT"]; exists && id != "netif:managed:lan" {
			currentManagement[id] = struct{}{}
		}
	}
	candidateManagement := stringSet(manifest.Topology.ManagementInterfaceIDs)
	retained := false
	for id := range currentManagement {
		if _, exists := candidateManagement[id]; exists {
			retained = true
		}
	}
	if len(currentManagement) == 0 || retained {
		return nil
	}
	oldURL, oldErr := url.Parse(manifest.OldURL)
	newURL, newErr := url.Parse(manifest.NewURL)
	distinctDestination := oldErr == nil && newErr == nil && oldURL.Hostname() != newURL.Hostname()
	if distinctDestination && !manifest.RequireWireGuardConfirmation {
		return nil
	}
	if !manifest.RequireWireGuardConfirmation {
		return errors.New("removing the last local management path requires confirmed WireGuard management")
	}
	reachable, err := backend.reachableManagementLink(ctx)
	if err != nil {
		return err
	}
	if !reachable {
		return errors.New("WireGuard-only confirmation requested but no fresh reachable management link exists")
	}
	return nil
}

func (backend UbuntuBackend) reachableManagementLink(ctx context.Context) (bool, error) {
	var count int
	cutoff := time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339Nano)
	err := backend.Database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM management_links
WHERE enabled=1 AND state='REACHABLE' AND last_handshake_at IS NOT NULL AND last_handshake_at>=?`, cutoff).Scan(&count)
	if err == nil && count > 0 {
		return true, nil
	}
	if err != nil && !strings.Contains(err.Error(), "no such table") {
		return false, err
	}
	var encoded string
	if scanErr := backend.Database.QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key='wireguard_runtime'`).Scan(&encoded); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return false, nil
		}
		return false, scanErr
	}
	var legacy struct {
		LastHandshakeAt string `json:"last_handshake_at"`
	}
	if json.Unmarshal([]byte(encoded), &legacy) != nil {
		return false, errors.New("legacy WireGuard runtime state is invalid")
	}
	handshake, parseErr := time.Parse(time.RFC3339Nano, legacy.LastHandshakeAt)
	return parseErr == nil && handshake.After(time.Now().UTC().Add(-3*time.Minute)), nil
}

func (backend UbuntuBackend) validateTopologySubnetConflicts(ctx context.Context, mutation *TopologyMutation, current config.Config) error {
	candidate, _ := netip.ParsePrefix(mutation.LANAddress)
	candidate = candidate.Masked()
	if candidate.Overlaps(netip.MustParsePrefix("10.80.0.0/24")) {
		return errors.New("topology LAN overlaps WireGuard management")
	}
	rows, err := backend.Database.QueryContext(ctx, `SELECT id,ipv4_cidr FROM uplinks WHERE ipv4_cidr IS NOT NULL AND ipv4_cidr<>''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		other, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return fmt.Errorf("stored uplink %s has an invalid IPv4 prefix", id)
		}
		if candidate.Overlaps(other.Masked()) {
			return fmt.Errorf("topology LAN overlaps uplink %s", id)
		}
	}
	for _, item := range mutation.EthernetUplinks {
		input := uplink.CreateEthernetInput{ID: item.ID, Name: item.Name, NetworkInterfaceID: item.NetworkInterfaceID, AddressMode: item.AddressMode, IPv4CIDR: item.IPv4CIDR, Gateway: item.Gateway, DNS: item.DNS, MTU: item.MTU}
		if err := uplink.ValidateEthernetInput(input); err != nil {
			return fmt.Errorf("candidate Ethernet uplink %s is invalid: %w", item.ID, err)
		}
		if item.AddressMode == uplink.AddressStatic {
			prefix, _ := netip.ParsePrefix(item.IPv4CIDR)
			if candidate.Overlaps(prefix.Masked()) || prefix.Overlaps(netip.MustParsePrefix("10.80.0.0/24")) {
				return fmt.Errorf("candidate Ethernet uplink %s overlaps topology or WireGuard management", item.ID)
			}
			for _, other := range mutation.EthernetUplinks {
				if other.ID == item.ID || other.AddressMode != uplink.AddressStatic {
					continue
				}
				otherPrefix, _ := netip.ParsePrefix(other.IPv4CIDR)
				if prefix.Overlaps(otherPrefix.Masked()) {
					return errors.New("candidate Ethernet uplinks have overlapping static subnets")
				}
			}
		}
	}
	var ingressSubnet string
	if err := backend.Database.QueryRowContext(ctx, `SELECT subnet_cidr FROM wireguard_ingress_servers LIMIT 1`).Scan(&ingressSubnet); err == nil {
		ingress, parseErr := netip.ParsePrefix(ingressSubnet)
		if parseErr == nil && candidate.Overlaps(ingress.Masked()) && mutation.LANInterfaceName != wgingress.DefaultInterfaceName {
			return errors.New("topology LAN overlaps WireGuard ingress")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_ = current
	return rows.Err()
}

func (backend UbuntuBackend) loadTopologyInterfaces(ctx context.Context) (map[string]topologyInterface, error) {
	rows, err := backend.Database.QueryContext(ctx, `SELECT id,COALESCE(current_ifname,''),carrier_state FROM network_interfaces ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]topologyInterface)
	for rows.Next() {
		var item topologyInterface
		if err := rows.Scan(&item.ID, &item.Ifname, &item.Carrier); err != nil {
			return nil, err
		}
		item.Roles = make(map[string]string)
		result[item.ID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	roleRows, err := backend.Database.QueryContext(ctx, `SELECT network_interface_id,role,COALESCE(uplink_id,'') FROM interface_role_assignments`)
	if err != nil {
		return nil, err
	}
	defer roleRows.Close()
	for roleRows.Next() {
		var id, role, uplinkID string
		if err := roleRows.Scan(&id, &role, &uplinkID); err != nil {
			return nil, err
		}
		item, exists := result[id]
		if !exists {
			return nil, errors.New("interface role references a missing interface")
		}
		item.Roles[role] = uplinkID
		result[id] = item
	}
	return result, roleRows.Err()
}

func (backend UbuntuBackend) snapshotTopologyRoles(ctx context.Context) ([]ethernetRoleSnapshot, error) {
	rows, err := backend.Database.QueryContext(ctx, `
SELECT id,network_interface_id,role,COALESCE(uplink_id,''),desired_generation,
       observed_generation,state,created_at,updated_at
FROM interface_role_assignments
WHERE role IN ('LAN_MEMBER','MANAGEMENT','WG_ENDPOINT','SHARED_ONE_ARM','UNUSED')
ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ethernetRoleSnapshot
	for rows.Next() {
		var item ethernetRoleSnapshot
		if err := rows.Scan(&item.ID, &item.NetworkInterfaceID, &item.Role, &item.UplinkID, &item.DesiredGeneration, &item.ObservedGeneration, &item.State, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (backend UbuntuBackend) applyTopologyDatabase(ctx context.Context, manifest Manifest, snapshot topologySnapshot) error {
	tx, err := backend.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `
UPDATE topology_profile_state SET active_profile=?,desired_generation=?,state='APPLYING',last_error_code='',updated_at=?
WHERE singleton_id=1 AND desired_generation=? AND applied_generation=? AND state='ACTIVE'`,
		manifest.Topology.Profile, snapshot.CandidateGeneration, now,
		snapshot.Profile.DesiredGeneration, snapshot.Profile.AppliedGeneration)
	if err != nil {
		return err
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("topology profile generation changed before apply")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE role IN ('LAN_MEMBER','MANAGEMENT','WG_ENDPOINT','SHARED_ONE_ARM','UNUSED')`); err != nil {
		return err
	}
	roles := map[string][]string{
		"LAN_MEMBER":  manifest.Topology.LANInterfaceIDs,
		"MANAGEMENT":  manifest.Topology.ManagementInterfaceIDs,
		"WG_ENDPOINT": manifest.Topology.WGEndpointInterfaceIDs,
	}
	if manifest.Topology.SharedOneArmInterfaceID != "" {
		roles["SHARED_ONE_ARM"] = []string{manifest.Topology.SharedOneArmInterfaceID}
	}
	for role, ids := range roles {
		for _, id := range uniqueStrings(ids) {
			digest := sha256.Sum256([]byte(role + ":" + id))
			roleID := "role:topology:" + strings.ToLower(role) + ":" + hex.EncodeToString(digest[:8])
			if _, err := tx.ExecContext(ctx, `
INSERT INTO interface_role_assignments(id,network_interface_id,role,desired_generation,observed_generation,state,created_at,updated_at)
VALUES(?,?,?,?,0,'PENDING',?,?)`, roleID, id, role, snapshot.CandidateGeneration, now, now); err != nil {
				return fmt.Errorf("assign topology role %s: %w", role, err)
			}
		}
	}
	details, _ := json.Marshal(map[string]any{"profile": manifest.Topology.Profile, "generation": snapshot.CandidateGeneration})
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?,'INFO','TOPOLOGY_APPLY_STARTED',?)`, now, string(details)); err != nil {
		return err
	}
	return tx.Commit()
}

func (backend UbuntuBackend) restoreTopologyDatabase(ctx context.Context, manifest Manifest, snapshot topologySnapshot) error {
	tx, err := backend.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var profile, state string
	var desired, applied int64
	if err := tx.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state); err != nil {
		return err
	}
	candidateState := profile == manifest.Topology.Profile && desired == snapshot.CandidateGeneration &&
		(applied == snapshot.Profile.AppliedGeneration || applied == snapshot.CandidateGeneration) &&
		(state == "APPLYING" || state == "ACTIVE")
	alreadyRestored := profile == snapshot.Profile.ActiveProfile && desired == snapshot.Profile.DesiredGeneration &&
		applied == snapshot.Profile.AppliedGeneration && state == snapshot.Profile.State
	if !candidateState && !alreadyRestored {
		return errors.New("topology rollback refuses to overwrite a concurrent generation")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE role IN ('LAN_MEMBER','MANAGEMENT','WG_ENDPOINT','SHARED_ONE_ARM','UNUSED')`); err != nil {
		return err
	}
	for _, role := range snapshot.Roles {
		var uplinkID any
		if role.UplinkID != "" {
			uplinkID = role.UplinkID
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO interface_role_assignments(id,network_interface_id,role,uplink_id,desired_generation,observed_generation,state,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?)`, role.ID, role.NetworkInterfaceID, role.Role, uplinkID, role.DesiredGeneration, role.ObservedGeneration, role.State, role.CreatedAt, role.UpdatedAt); err != nil {
			return err
		}
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		if _, err := tx.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE role='ETHERNET_UPLINK' AND uplink_id=?`, item.ID); err != nil {
			return fmt.Errorf("remove rolled-back topology Ethernet role %s: %w", item.ID, err)
		}
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_state WHERE singleton_id=1 AND active_uplink_id=?`, item.ID).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return fmt.Errorf("cannot roll back active topology Ethernet uplink %s", item.ID)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM uplinks WHERE id=? AND type='ETHERNET'`, item.ID); err != nil {
			return fmt.Errorf("remove rolled-back topology Ethernet uplink %s: %w", item.ID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE topology_profile_state SET active_profile=?,desired_generation=?,applied_generation=?,state=?,last_error_code=?,updated_at=? WHERE singleton_id=1`,
		snapshot.Profile.ActiveProfile, snapshot.Profile.DesiredGeneration, snapshot.Profile.AppliedGeneration,
		snapshot.Profile.State, snapshot.Profile.LastErrorCode, snapshot.Profile.UpdatedAt); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	details, _ := json.Marshal(map[string]any{"profile": snapshot.Profile.ActiveProfile, "failed_candidate": manifest.Topology.Profile})
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?,'WARNING','TOPOLOGY_APPLY_ROLLED_BACK',?)`, now, string(details)); err != nil {
		return err
	}
	return tx.Commit()
}

func (backend UbuntuBackend) applyTopologyIngress(ctx context.Context, mutation *TopologyMutation, current wgingress.Server, exists bool) error {
	if !exists {
		if mutation.IngressEnabled {
			return errors.New("WireGuard ingress server must be initialized before enabling it in a topology profile")
		}
		return nil
	}
	listeners := make([]wgingress.ListenInterface, 0, len(mutation.IngressListenInterfaces))
	for _, item := range mutation.IngressListenInterfaces {
		listeners = append(listeners, wgingress.ListenInterface{NetworkInterfaceID: item.NetworkInterfaceID, ExposureMode: item.ExposureMode, Priority: item.Priority})
	}
	_, err := backend.TopologyIngress.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: mutation.IngressEnabled, Name: current.Name, SubnetCIDR: current.SubnetCIDR,
		ListenPort: current.ListenPort, EndpointHost: current.EndpointHost, MTU: current.MTU,
		TopologyMode: mutation.IngressTopologyMode, NetworkInterfaceID: mutation.SharedOneArmInterfaceID,
		DNS: append([]string(nil), current.DNS...), ListenInterfaces: listeners,
	})
	return err
}

func (backend UbuntuBackend) restoreTopologyIngress(ctx context.Context, previous wgingress.Server) error {
	listeners := make([]wgingress.ListenInterface, len(previous.ListenInterfaces))
	copy(listeners, previous.ListenInterfaces)
	_, err := backend.TopologyIngress.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: previous.Enabled, Name: previous.Name, SubnetCIDR: previous.SubnetCIDR,
		ListenPort: previous.ListenPort, EndpointHost: previous.EndpointHost, MTU: previous.MTU,
		TopologyMode: previous.TopologyMode, NetworkInterfaceID: previous.NetworkInterfaceID,
		DNS: append([]string(nil), previous.DNS...), ListenInterfaces: listeners,
	})
	return err
}

func renderTopologyConfigs(current config.Config, manifest Manifest, managementIfnames []string) ([]byte, []byte, uint16, error) {
	mutation := manifest.Topology
	oldURL, err := url.Parse(manifest.OldURL)
	if err != nil {
		return nil, nil, 0, err
	}
	newURL, err := url.Parse(manifest.NewURL)
	if err != nil {
		return nil, nil, 0, err
	}
	oldListen := net.JoinHostPort(oldURL.Hostname(), oldURL.Port())
	newListen := net.JoinHostPort(newURL.Hostname(), newURL.Port())
	final := current
	final.Network.LANInterface = mutation.LANInterfaceName
	final.Network.LANAddress = mutation.LANAddress
	final.Network.ManagementInterfaces = append([]string(nil), managementIfnames...)
	if mutation.DHCPDNSEnabled {
		final.Network.LANServiceMode = "dhcp_dns"
	} else {
		final.Network.LANServiceMode = "disabled"
	}
	replaced := 0
	for index, listen := range final.API.Listen {
		if listen == oldListen {
			final.API.Listen[index] = newListen
			replaced++
		}
	}
	if oldListen != newListen && replaced != 1 {
		return nil, nil, 0, errors.New("topology source API listener is not unique")
	}
	if oldListen == newListen && replaced == 0 {
		return nil, nil, 0, errors.New("topology management listener is not configured")
	}
	final.API.Listen = uniqueStrings(final.API.Listen)
	if err := final.Validate(); err != nil {
		return nil, nil, 0, fmt.Errorf("validate final topology configuration: %w", err)
	}
	grace := final
	if oldListen != newListen {
		grace.API.Listen = append(grace.API.Listen, oldListen)
		grace.API.Listen = uniqueStrings(grace.API.Listen)
		if err := grace.Validate(); err != nil {
			return nil, nil, 0, fmt.Errorf("validate grace topology configuration: %w", err)
		}
	}
	gracePayload, err := yaml.Marshal(grace)
	if err != nil {
		return nil, nil, 0, err
	}
	finalPayload, err := yaml.Marshal(final)
	if err != nil {
		return nil, nil, 0, err
	}
	port, err := strconv.ParseUint(newURL.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, nil, 0, errors.New("topology API port is invalid")
	}
	return gracePayload, finalPayload, uint16(port), nil
}

func renderTopologyMember(ifname, bridge string) (string, error) {
	if !validInterfaceName(ifname) || !validInterfaceName(bridge) || ifname == bridge {
		return "", errors.New("topology LAN member and bridge names are invalid")
	}
	return "# Managed by Gateway VPN; edit through WebUI safe apply.\n[Match]\nName=" + ifname + "\n\n[Network]\nBridge=" + bridge + "\nDHCP=no\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n\n[Link]\nRequiredForOnline=no\n", nil
}

func renderLANNetDev(name string) (string, error) {
	if name != topologyManagedLANName {
		return "", errors.New("Ethernet LAN topology requires the owned gateway-vpn-lan bridge")
	}
	return "[NetDev]\nName=gateway-vpn-lan\nKind=bridge\n\n[Bridge]\nSTP=yes\nForwardDelaySec=4s\n", nil
}

func validateTopologyPrerequisites(mutation *TopologyMutation, interfaces map[string]topologyInterface) error {
	ack := stringSet(mutation.AcknowledgedPrerequisites)
	for _, value := range topologyPrerequisites(mutation, interfaces) {
		if _, exists := ack[value]; !exists {
			return fmt.Errorf("topology prerequisite %s must be explicitly acknowledged", value)
		}
	}
	return nil
}

func topologyPrerequisites(mutation *TopologyMutation, interfaces map[string]topologyInterface) []string {
	required := []string{"ACCEPT_TEMPORARY_DISCONNECT"}
	currentLAN := make(map[string]struct{})
	for id, item := range interfaces {
		if _, exists := item.Roles["LAN_MEMBER"]; exists {
			currentLAN[id] = struct{}{}
		}
	}
	if !sameStringSet(currentLAN, stringSet(mutation.LANInterfaceIDs)) {
		required = append(required, "MOVE_LAN_CABLES")
	}
	if mutation.DHCPDNSEnabled {
		required = append(required, "CONFIGURE_KEENETIC_WAN_DHCP")
	}
	if mutation.Profile == TopologyOneArmWireGuard || mutation.Profile == TopologyMixed && mutation.SharedOneArmInterfaceID != "" && len(mutation.LANInterfaceIDs) == 0 {
		required = append(required, "CONFIGURE_KEENETIC_WIREGUARD", "VERIFY_UPSTREAM_RETURN_PATH")
	}
	return required
}

func readTopologySnapshot(directory string, manifest Manifest) (topologySnapshot, error) {
	payload, err := readBoundedRegular(filepath.Join(directory, "topology-state.json"), 2<<20)
	if err != nil {
		return topologySnapshot{}, err
	}
	var snapshot topologySnapshot
	if err := decodeStrictJSON(payload, &snapshot); err != nil {
		return topologySnapshot{}, errors.New("decode topology safe-apply snapshot failed")
	}
	if err := validateTopologySnapshot(snapshot, manifest); err != nil {
		return topologySnapshot{}, errors.New("topology safe-apply snapshot does not match manifest")
	}
	return snapshot, nil
}

func validateTopologySnapshot(snapshot topologySnapshot, manifest Manifest) error {
	if manifest.Topology == nil || snapshot.Profile.DesiredGeneration != manifest.Topology.ExpectedDesiredGeneration ||
		snapshot.Profile.DesiredGeneration < 1 || snapshot.Profile.AppliedGeneration != snapshot.Profile.DesiredGeneration ||
		snapshot.Profile.State != "ACTIVE" || snapshot.Profile.LastErrorCode != "" ||
		snapshot.CandidateGeneration <= snapshot.Profile.DesiredGeneration || snapshot.CandidateGeneration != snapshot.Profile.DesiredGeneration+1 ||
		!validTopologyProfile(snapshot.Profile.ActiveProfile) || !validInterfaceName(snapshot.PreviousLANIfname) {
		return errors.New("topology snapshot generation is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.Profile.UpdatedAt); err != nil {
		return errors.New("topology snapshot timestamp is invalid")
	}
	wantUplinkIDs := make([]string, 0, len(manifest.Topology.EthernetUplinks))
	for _, item := range manifest.Topology.EthernetUplinks {
		wantUplinkIDs = append(wantUplinkIDs, item.ID)
	}
	if !sameStringSlice(snapshot.EthernetUplinkIDs, wantUplinkIDs) {
		return errors.New("topology snapshot Ethernet uplink set does not match manifest")
	}
	previousPrefix, err := netip.ParsePrefix(snapshot.PreviousLANCIDR)
	if err != nil || !netutil.IsUsableIPv4Host(previousPrefix, previousPrefix.Addr()) {
		return errors.New("topology snapshot LAN prefix is invalid")
	}
	if len(snapshot.Roles) > 256 || len(snapshot.Members) > 256 {
		return errors.New("topology snapshot inventory exceeds its bound")
	}
	roleIDs := make(map[string]struct{}, len(snapshot.Roles))
	roleAssignments := make(map[string]struct{}, len(snapshot.Roles))
	requiredMemberIDs := stringSet(manifest.Topology.LANInterfaceIDs)
	for _, role := range snapshot.Roles {
		if !safeObjectID(role.ID) || !safeObjectID(role.NetworkInterfaceID) || role.UplinkID != "" ||
			!validTopologyRole(role.Role) || role.DesiredGeneration < 1 || role.ObservedGeneration < 0 ||
			role.ObservedGeneration > role.DesiredGeneration || len(role.State) == 0 || len(role.State) > 64 {
			return errors.New("topology snapshot role is invalid")
		}
		if _, err := time.Parse(time.RFC3339Nano, role.CreatedAt); err != nil {
			return errors.New("topology snapshot role timestamp is invalid")
		}
		if _, err := time.Parse(time.RFC3339Nano, role.UpdatedAt); err != nil {
			return errors.New("topology snapshot role timestamp is invalid")
		}
		if _, duplicate := roleIDs[role.ID]; duplicate {
			return errors.New("topology snapshot role id is duplicated")
		}
		roleIDs[role.ID] = struct{}{}
		assignment := role.NetworkInterfaceID + "\x00" + role.Role
		if _, duplicate := roleAssignments[assignment]; duplicate {
			return errors.New("topology snapshot role assignment is duplicated")
		}
		roleAssignments[assignment] = struct{}{}
		requiredMemberIDs[role.NetworkInterfaceID] = struct{}{}
	}
	memberKeys := make(map[string]struct{}, len(snapshot.Members))
	legacyPaths := make(map[string]struct{}, len(snapshot.Members)/2)
	memberKinds := make(map[string]map[string]struct{}, len(snapshot.Members)/2)
	for _, member := range snapshot.Members {
		if !safeObjectID(member.NetworkInterfaceID) || !validInterfaceName(member.InterfaceName) || member.PathKind != "stable" && member.PathKind != "legacy" {
			return errors.New("topology snapshot member is invalid")
		}
		if member.Existed {
			decoded, err := hex.DecodeString(member.SHA256)
			if err != nil || len(decoded) != sha256.Size || member.SHA256 != strings.ToLower(member.SHA256) {
				return errors.New("topology snapshot member checksum is invalid")
			}
		} else if member.SHA256 != "" {
			return errors.New("absent topology snapshot member has a checksum")
		}
		key := member.NetworkInterfaceID + "\x00" + member.PathKind
		if _, duplicate := memberKeys[key]; duplicate {
			return errors.New("topology snapshot member is duplicated")
		}
		memberKeys[key] = struct{}{}
		if member.PathKind == "legacy" {
			if _, duplicate := legacyPaths[member.InterfaceName]; duplicate {
				return errors.New("topology snapshot legacy path is duplicated")
			}
			legacyPaths[member.InterfaceName] = struct{}{}
		}
		if memberKinds[member.NetworkInterfaceID] == nil {
			memberKinds[member.NetworkInterfaceID] = make(map[string]struct{}, 2)
		}
		memberKinds[member.NetworkInterfaceID][member.PathKind] = struct{}{}
	}
	for id := range requiredMemberIDs {
		kinds := memberKinds[id]
		if len(kinds) != 2 {
			return errors.New("topology snapshot lacks a complete member path pair")
		}
	}
	return nil
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validTopologyProfile(value string) bool {
	return value == TopologyEthernetHiLink || value == TopologyEthernetEthernet || value == TopologyOneArmWireGuard || value == TopologyMixed
}

func validTopologyRole(value string) bool {
	return value == "LAN_MEMBER" || value == "MANAGEMENT" || value == "WG_ENDPOINT" || value == "SHARED_ONE_ARM" || value == "UNUSED"
}

func snapshotRequiredFile(source, destination string) error {
	content, err := readBoundedRegular(source, 1<<20)
	if err != nil {
		return err
	}
	return atomicWrite(destination, content, 0o600)
}

func snapshotOptionalFile(source, destination string) (bool, error) {
	exists, content, err := readOptionalRegular(source, 1<<20)
	if err != nil || !exists {
		return exists, err
	}
	return true, atomicWrite(destination, content, 0o600)
}

func (backend UbuntuBackend) topologyMemberPath(interfaceID string) string {
	digest := sha256.Sum256([]byte(interfaceID))
	return filepath.Join(backend.Paths.EthernetNetworkDir, "06-gateway-vpn-lan-member-"+hex.EncodeToString(digest[:8])+".network")
}

func (backend UbuntuBackend) topologySnapshotMemberPath(member topologyMemberSnapshot) (string, error) {
	switch member.PathKind {
	case "stable":
		return backend.topologyMemberPath(member.NetworkInterfaceID), nil
	case "legacy":
		if !validInterfaceName(member.InterfaceName) {
			return "", errors.New("legacy topology member snapshot has an invalid interface name")
		}
		return filepath.Join(backend.Paths.EthernetNetworkDir, "06-gateway-vpn-lan-"+member.InterfaceName+".network"), nil
	default:
		return "", errors.New("topology member snapshot path kind is invalid")
	}
}

func topologyMemberSnapshotName(interfaceID, kind string) string {
	digest := sha256.Sum256([]byte(kind + ":" + interfaceID))
	return "member-old-" + hex.EncodeToString(digest[:8]) + ".network"
}

func topologyMemberCandidateName(interfaceID string) string {
	digest := sha256.Sum256([]byte(interfaceID))
	return "member-new-" + hex.EncodeToString(digest[:8]) + ".network"
}

func (backend UbuntuBackend) serviceActive(ctx context.Context, unit string) bool {
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.Systemctl, Arguments: []string{"is-active", unit}})
	return err == nil && strings.TrimSpace(result.Stdout) == "active"
}

func (backend UbuntuBackend) controlService(ctx context.Context, action, unit string) error {
	if (action != "restart" && action != "stop") ||
		(unit != "gateway-vpn.service" && unit != "gateway-vpn-dnsmasq.service") {
		return errors.New("unsupported topology service operation")
	}
	_, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.Systemctl, Arguments: []string{"--no-block", action, unit}})
	if err != nil {
		return fmt.Errorf("request topology service %s %s: %w", action, unit, err)
	}
	return nil
}

func topologyAffectedIfnames(interfaces map[string]topologyInterface, mutation *TopologyMutation, extra ...string) []string {
	values := append([]string(nil), extra...)
	assigned := append(append(append([]string(nil), mutation.LANInterfaceIDs...), mutation.ManagementInterfaceIDs...), mutation.WGEndpointInterfaceIDs...)
	if mutation.SharedOneArmInterfaceID != "" {
		assigned = append(assigned, mutation.SharedOneArmInterfaceID)
	}
	for _, uplink := range mutation.EthernetUplinks {
		assigned = append(assigned, uplink.NetworkInterfaceID)
	}
	assignedSet := stringSet(assigned)
	for id, item := range interfaces {
		_, candidate := assignedSet[id]
		_, currentLAN := item.Roles["LAN_MEMBER"]
		_, currentManagement := item.Roles["MANAGEMENT"]
		_, currentEndpoint := item.Roles["WG_ENDPOINT"]
		_, currentShared := item.Roles["SHARED_ONE_ARM"]
		if candidate || currentLAN || currentManagement || currentEndpoint || currentShared {
			values = append(values, item.Ifname)
		}
	}
	return uniqueIfnames(values...)
}

func topologySnapshotAffectedIfnames(snapshot topologySnapshot, mutation *TopologyMutation, extra ...string) []string {
	values := append([]string(nil), extra...)
	values = append(values, snapshot.PreviousLANIfname)
	assigned := append(append(append([]string(nil), mutation.LANInterfaceIDs...), mutation.ManagementInterfaceIDs...), mutation.WGEndpointInterfaceIDs...)
	if mutation.SharedOneArmInterfaceID != "" {
		assigned = append(assigned, mutation.SharedOneArmInterfaceID)
	}
	for _, uplink := range mutation.EthernetUplinks {
		assigned = append(assigned, uplink.NetworkInterfaceID)
	}
	affected := stringSet(assigned)
	for _, role := range snapshot.Roles {
		if role.Role == "LAN_MEMBER" || role.Role == "MANAGEMENT" || role.Role == "WG_ENDPOINT" || role.Role == "SHARED_ONE_ARM" {
			affected[role.NetworkInterfaceID] = struct{}{}
		}
	}
	for _, member := range snapshot.Members {
		if _, exists := affected[member.NetworkInterfaceID]; exists {
			values = append(values, member.InterfaceName)
		}
	}
	return uniqueIfnames(values...)
}

func topologyManagementIfnames(mutation *TopologyMutation, interfaces map[string]topologyInterface) []string {
	values := make([]string, 0, len(mutation.ManagementInterfaceIDs)+1)
	// The logical ingress remains a management path even when LAN DHCP/DNS is
	// intentionally disabled by ONE_ARM_WIREGUARD.  Without this exact entry,
	// the new wg-ingress API listener could never be confirmed locally.
	values = append(values, mutation.LANInterfaceName)
	for _, id := range mutation.ManagementInterfaceIDs {
		if item, exists := interfaces[id]; exists {
			values = append(values, item.Ifname)
		}
	}
	return uniqueStrings(values)
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
