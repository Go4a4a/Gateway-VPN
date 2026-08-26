// Package dataplane owns the small privileged runtime surface that opens or
// closes verified LAN traffic through the Mihomo TUN. It never creates a
// LAN-to-modem rule and only mutates two sets in the Gateway VPN-owned table.
package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/platformexec"
)

const (
	activeTUNSet        = "active_tun_interfaces"
	activeGenerationSet = "active_path_generation"
)

type PathState struct {
	Active     bool   `json:"active"`
	Generation uint32 `json:"generation"`
}

type FirewallBackend struct {
	Executor platformexec.Executor
	NFT      string
	TUNName  string
}

func (backend FirewallBackend) ActivatePath(ctx context.Context, generation uint32) error {
	if generation == 0 {
		return errors.New("active path generation must be non-zero")
	}
	return backend.apply(ctx, PathState{Active: true, Generation: generation})
}

func (backend FirewallBackend) BlockPath(ctx context.Context) error {
	return backend.apply(ctx, PathState{})
}

func (backend FirewallBackend) ObservePath(ctx context.Context) (PathState, error) {
	if err := backend.validate(); err != nil {
		return PathState{}, err
	}
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--json", "list", "table", "inet", firewall.TableName}})
	if err != nil {
		return PathState{}, fmt.Errorf("observe owned data-plane table: %w", err)
	}
	state, err := decodePathState([]byte(result.Stdout), backend.TUNName)
	if err != nil {
		return PathState{}, fmt.Errorf("decode owned data-plane state: %w", err)
	}
	return state, nil
}

func (backend FirewallBackend) apply(ctx context.Context, desired PathState) error {
	if err := backend.validate(); err != nil {
		return err
	}
	current, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"list", "table", "inet", firewall.TableName}})
	if err != nil {
		return fmt.Errorf("inspect owned data-plane table: %w", err)
	}
	for _, marker := range []string{
		"table inet " + firewall.TableName,
		"set firewall_schema_generation",
		"set " + activeTUNSet,
		"set " + activeGenerationSet,
		"hook forward priority filter; policy drop",
		"gateway-vpn PATH_BLOCKED",
		"oifname @" + activeTUNSet,
		"counter user_upload",
		"counter user_download",
		"counter service_upload",
		"counter service_download",
	} {
		if !strings.Contains(current.Stdout, marker) {
			return fmt.Errorf("owned data-plane table is missing integrity marker %q", marker)
		}
	}
	payload := renderPathTransaction(desired, backend.TUNName)
	if result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--check", "--file", "-"}, Stdin: payload}); err != nil {
		return fmt.Errorf("validate atomic data-plane state: %s: %w", bounded(result.Stderr), err)
	}
	if result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--file", "-"}, Stdin: payload}); err != nil {
		return fmt.Errorf("apply atomic data-plane state: %s: %w", bounded(result.Stderr), err)
	}
	observed, err := backend.ObservePath(ctx)
	if err != nil {
		return err
	}
	if observed != desired {
		return fmt.Errorf("data-plane state verification mismatch: observed=%+v desired=%+v", observed, desired)
	}
	return nil
}

func (backend FirewallBackend) validate() error {
	if backend.Executor == nil || backend.NFT != "/usr/sbin/nft" || !validInterfaceName(backend.TUNName) {
		return errors.New("fixed Ubuntu nft executor and valid Mihomo TUN are required")
	}
	return nil
}

func renderPathTransaction(state PathState, tunName string) []byte {
	var builder strings.Builder
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeTUNSet)
	builder.WriteByte('\n')
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeGenerationSet)
	builder.WriteByte('\n')
	if state.Active {
		builder.WriteString("add element inet ")
		builder.WriteString(firewall.TableName)
		builder.WriteByte(' ')
		builder.WriteString(activeGenerationSet)
		builder.WriteString(" { ")
		builder.WriteString(strconv.FormatUint(uint64(state.Generation), 10))
		builder.WriteString(" }\n")
		builder.WriteString("add element inet ")
		builder.WriteString(firewall.TableName)
		builder.WriteByte(' ')
		builder.WriteString(activeTUNSet)
		builder.WriteString(" { ")
		builder.WriteString(strconv.Quote(tunName))
		builder.WriteString(" }\n")
	}
	return []byte(builder.String())
}

func decodePathState(payload []byte, tunName string) (PathState, error) {
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return PathState{}, err
	}
	foundTUN, foundGeneration := false, false
	var tunElements, generationElements []any
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
		if err := json.Unmarshal(raw, &set); err != nil {
			return PathState{}, err
		}
		if set.Family != "inet" || set.Table != firewall.TableName {
			continue
		}
		switch set.Name {
		case activeTUNSet:
			foundTUN, tunElements = true, set.Elem
		case activeGenerationSet:
			foundGeneration, generationElements = true, set.Elem
		}
	}
	if !foundTUN || !foundGeneration {
		return PathState{}, errors.New("active path sets are missing")
	}
	if len(tunElements) == 0 && len(generationElements) == 0 {
		return PathState{}, nil
	}
	if len(tunElements) != 1 || len(generationElements) != 1 || stringElement(tunElements[0]) != tunName {
		return PathState{}, errors.New("active path set cardinality or TUN is invalid")
	}
	generation, ok := uint32Element(generationElements[0])
	if !ok || generation == 0 {
		return PathState{}, errors.New("active path generation is invalid")
	}
	return PathState{Active: true, Generation: generation}, nil
}

func stringElement(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]any:
		if nested, ok := typed["val"].(string); ok {
			return nested
		}
	}
	return ""
}

func uint32Element(value any) (uint32, bool) {
	if object, ok := value.(map[string]any); ok {
		value = object["val"]
	}
	number, ok := value.(float64)
	if !ok || number < 1 || number > math.MaxUint32 || math.Trunc(number) != number {
		return 0, false
	}
	return uint32(number), true
}

func bounded(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '_', '-', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}
