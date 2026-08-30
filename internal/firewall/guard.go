package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gateway-vpn/internal/platformexec"
)

const SchemaGenerationSet = "firewall_schema_generation"

type GuardResult struct {
	Healthy      bool
	Recovered    bool
	Quarantined  bool
	LANRestored  bool
	FailureCause string
}

// Guard owns recovery of the Gateway VPN nftables table. It deliberately
// quarantines only the configured transit LAN link and never flushes or
// modifies tables owned by another application.
type Guard struct {
	Executor     platformexec.Executor
	NFT          string
	IP           string
	LANInterface string
	Ruleset      Ruleset
	MarkerPath   string
}

func (guard *Guard) Ensure(ctx context.Context) (GuardResult, error) {
	if err := guard.validate(); err != nil {
		return GuardResult{}, err
	}
	integrityErr := guard.Inspect(ctx)
	ownsQuarantine, markerErr := guard.ownsQuarantine()
	if integrityErr == nil {
		if markerErr != nil {
			return GuardResult{Healthy: true}, markerErr
		}
		if !ownsQuarantine {
			return GuardResult{Healthy: true}, nil
		}
		if err := guard.setLAN(ctx, true); err != nil {
			return GuardResult{Healthy: true, Quarantined: true}, fmt.Errorf("restore guard-owned LAN quarantine: %w", err)
		}
		if err := guard.clearQuarantine(); err != nil {
			return GuardResult{Healthy: true, Quarantined: true, LANRestored: true}, err
		}
		return GuardResult{Healthy: true, Recovered: true, LANRestored: true}, nil
	}

	result := GuardResult{Quarantined: true, FailureCause: integrityErr.Error()}
	var observeErr, persistErr error
	if markerErr == nil && !ownsQuarantine {
		wasUp, err := guard.lanAdminUp(ctx)
		observeErr = err
		if err == nil && wasUp {
			persistErr = guard.recordQuarantine()
			ownsQuarantine = persistErr == nil
		}
	}
	downErr := guard.setLAN(ctx, false)
	recoveryErr := ValidateAndLoad(ctx, guard.Executor, guard.Ruleset, LoadOptions{NFTExecutable: guard.NFT, Mutate: true})
	verifyErr := error(nil)
	if recoveryErr == nil {
		verifyErr = guard.Inspect(ctx)
	}
	if recoveryErr == nil && verifyErr == nil {
		result.Healthy = true
		result.Recovered = true
	}
	var restoreErr, clearErr error
	if result.Healthy && ownsQuarantine {
		restoreErr = guard.setLAN(ctx, true)
		if restoreErr == nil {
			result.LANRestored = true
			clearErr = guard.clearQuarantine()
		}
	}
	return result, errors.Join(markerErr, observeErr, persistErr, downErr, recoveryErr, verifyErr, restoreErr, clearErr)
}

func (guard *Guard) Inspect(ctx context.Context) error {
	if err := guard.validate(); err != nil {
		return err
	}
	result, err := guard.Executor.Run(ctx, platformexec.Request{Executable: guard.NFT, Arguments: []string{"list", "table", "inet", TableName}})
	if err != nil {
		return errors.New("owned firewall table is unavailable")
	}
	for _, marker := range []string{
		"table inet " + TableName,
		"set " + SchemaGenerationSet,
		"set active_tun_interfaces",
		"set active_direct_interfaces",
		"set active_direct_context",
		"set user_ingress_interfaces",
		"set local_management_interfaces",
		"set wireguard_ingress_listeners",
		"set wireguard_ingress_allowed_v4",
		"map active_direct_marks",
		"set active_path_generation",
		"set active_route_generation",
		"set hilink_interfaces",
		"set wireguard_endpoint_v4",
		"set management_fabric_interfaces",
		"set management_fabric_endpoints",
		"set management_fabric_generation",
		"set mihomo_endpoint_tcp_v4",
		"counter user_upload",
		"counter user_download",
		"counter service_upload",
		"counter service_download",
		"chain input {",
		"hook input priority filter; policy drop",
		"jump management_fabric_input",
		"chain forward {",
		"hook forward priority filter; policy drop",
		"jump management_fabric_forward",
		"chain prerouting {",
		"hook prerouting priority mangle",
		"chain postrouting {",
		"hook postrouting priority srcnat",
		"jump management_fabric_postrouting",
		"chain output {",
		"hook output priority filter; policy drop",
		"chain management_fabric_input {",
		"chain management_fabric_forward {",
		"chain management_fabric_postrouting {",
		"chain management_fabric_prerouting {",
		"hook prerouting priority dstnat",
		"gateway-vpn PATH_BLOCKED",
		"oifname @active_tun_interfaces",
		"oifname . meta mark @active_direct_context",
		"map @active_direct_marks",
		"iifname . udp dport @wireguard_ingress_listeners",
		"ip saddr @wireguard_ingress_allowed_v4",
		"@wireguard_endpoint_v4 udp dport 51821",
		"@management_fabric_endpoints",
	} {
		if !strings.Contains(result.Stdout, marker) {
			return fmt.Errorf("owned firewall integrity marker is missing: %s", marker)
		}
	}
	generation, err := guard.Executor.Run(ctx, platformexec.Request{Executable: guard.NFT, Arguments: []string{"--json", "list", "set", "inet", TableName, SchemaGenerationSet}})
	if err != nil {
		return errors.New("firewall schema generation is unavailable")
	}
	if err := ValidateSchemaGenerationJSON([]byte(generation.Stdout)); err != nil {
		return err
	}
	return nil
}

func (guard *Guard) validate() error {
	if guard == nil || guard.Executor == nil || guard.NFT != "/usr/sbin/nft" || guard.IP != "/usr/sbin/ip" || !validInterfaceName(guard.LANInterface) || !filepath.IsAbs(guard.MarkerPath) || guard.Ruleset.Text == "" || guard.Ruleset.SHA256 == "" {
		return errors.New("complete fixed firewall guard configuration is required")
	}
	return nil
}

// ValidateSchemaGenerationJSON verifies that an nft JSON set response belongs
// to the owned table and contains exactly the current schema generation.
func ValidateSchemaGenerationJSON(payload []byte) error {
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return errors.New("firewall schema generation JSON is invalid")
	}
	for _, object := range document.NFTables {
		raw, exists := object["set"]
		if !exists {
			continue
		}
		var set struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Elem   []any  `json:"elem"`
		}
		if json.Unmarshal(raw, &set) != nil || set.Family != "inet" || set.Table != TableName || set.Name != SchemaGenerationSet {
			continue
		}
		if len(set.Elem) == 1 {
			switch value := set.Elem[0].(type) {
			case float64:
				if value == SchemaGeneration {
					return nil
				}
			case map[string]any:
				if nested, ok := value["val"].(float64); ok && nested == SchemaGeneration {
					return nil
				}
			}
		}
		return errors.New("firewall schema generation value is invalid")
	}
	return errors.New("firewall schema generation set is missing")
}

func (guard *Guard) lanAdminUp(ctx context.Context) (bool, error) {
	result, err := guard.Executor.Run(ctx, platformexec.Request{Executable: guard.IP, Arguments: []string{"-json", "link", "show", "dev", guard.LANInterface}})
	if err != nil {
		return false, errors.New("observe LAN administrative state failed")
	}
	var links []struct {
		Flags []string `json:"flags"`
	}
	if json.Unmarshal([]byte(result.Stdout), &links) != nil || len(links) != 1 {
		return false, errors.New("LAN administrative state JSON is invalid")
	}
	for _, flag := range links[0].Flags {
		if flag == "UP" {
			return true, nil
		}
	}
	return false, nil
}

func (guard *Guard) setLAN(ctx context.Context, up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	if _, err := guard.Executor.Run(ctx, platformexec.Request{Executable: guard.IP, Arguments: []string{"link", "set", "dev", guard.LANInterface, state}}); err != nil {
		return fmt.Errorf("set transit LAN %s failed", state)
	}
	return nil
}

func (guard *Guard) ownsQuarantine() (bool, error) {
	info, err := os.Lstat(guard.MarkerPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128 {
		return false, errors.New("firewall quarantine marker is unsafe")
	}
	content, err := os.ReadFile(guard.MarkerPath)
	if err != nil || string(content) != guard.LANInterface+"\n" {
		return false, errors.New("firewall quarantine marker is invalid")
	}
	return true, nil
}

func (guard *Guard) recordQuarantine() error {
	directory := filepath.Dir(guard.MarkerPath)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("firewall guard runtime directory is unsafe")
	}
	if exists, err := guard.ownsQuarantine(); err != nil || exists {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".quarantine-*.tmp")
	if err != nil {
		return errors.New("create firewall quarantine marker failed")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("protect firewall quarantine marker failed")
	}
	if _, err := temporary.WriteString(guard.LANInterface + "\n"); err != nil {
		temporary.Close()
		return errors.New("write firewall quarantine marker failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync firewall quarantine marker failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close firewall quarantine marker failed")
	}
	if err := os.Rename(name, guard.MarkerPath); err != nil {
		return errors.New("activate firewall quarantine marker failed")
	}
	return syncDirectory(directory)
}

func (guard *Guard) clearQuarantine() error {
	if err := os.Remove(guard.MarkerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove firewall quarantine marker failed")
	}
	return syncDirectory(filepath.Dir(guard.MarkerPath))
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("open firewall guard runtime directory failed")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("sync firewall guard runtime directory failed")
	}
	return nil
}
