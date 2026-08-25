package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
)

type Controller struct {
	Executor     platformexec.Executor
	IPExecutable string
	WGExecutable string
	Mutate       bool
}

type Operation struct {
	Description      string
	Request          platformexec.Request
	AllowedExitCodes []int
}

func RenderConfigure(config Config, ipExecutable, wgExecutable string) ([]Operation, error) {
	syncConf, err := RenderSyncConf(config)
	if err != nil {
		return nil, err
	}
	return []Operation{
		{
			Description:      "create WireGuard management interface if absent",
			Request:          platformexec.Request{Executable: ipExecutable, Arguments: []string{"link", "add", "dev", config.InterfaceName, "type", "wireguard"}},
			AllowedExitCodes: []int{2},
		},
		{
			Description: "synchronize WireGuard management peers",
			Request:     platformexec.Request{Executable: wgExecutable, Arguments: []string{"syncconf", config.InterfaceName, "/dev/stdin"}, Stdin: syncConf},
		},
		{
			Description: "set WireGuard management address",
			Request:     platformexec.Request{Executable: ipExecutable, Arguments: []string{"-4", "address", "replace", config.Address, "dev", config.InterfaceName}},
		},
		{
			Description: "bring WireGuard management interface up",
			Request:     platformexec.Request{Executable: ipExecutable, Arguments: []string{"link", "set", "dev", config.InterfaceName, "up"}},
		},
	}, nil
}

func RenderUplinkSwitch(interfaceName string, endpoint, previousEndpoint netip.Addr, previous *modem.Modem, next modem.Modem, ipExecutable, wgExecutable string) ([]Operation, error) {
	if !validInterfaceName(interfaceName) || !endpoint.Is4() || !endpoint.IsGlobalUnicast() || endpoint.IsPrivate() || next.InterfaceName == "" || next.Gateway == "" || next.RoutingTableID < 256 || next.Fwmark == 0 {
		return nil, errors.New("invalid WireGuard uplink switch input")
	}
	destination := endpoint.String() + "/32"
	operations := []Operation{
		{Description: "install WireGuard endpoint route on new modem", Request: platformexec.Request{Executable: ipExecutable, Arguments: []string{"-4", "route", "replace", destination, "via", next.Gateway, "dev", next.InterfaceName, "table", strconv.FormatUint(uint64(next.RoutingTableID), 10), "protocol", strconv.Itoa(routing.OwnedProtocol)}}},
		{Description: "switch WireGuard encrypted packets to new modem mark", Request: platformexec.Request{Executable: wgExecutable, Arguments: []string{"set", interfaceName, "fwmark", fmt.Sprintf("%#x", next.Fwmark)}}},
	}
	oldEndpoint := endpoint
	if previousEndpoint.IsValid() && previousEndpoint.Is4() {
		oldEndpoint = previousEndpoint.Unmap()
	}
	if previous != nil && previous.ID != "" && (previous.ID != next.ID || oldEndpoint != endpoint) && previous.InterfaceName != "" && previous.Gateway != "" {
		operations = append(operations, Operation{
			Description: "remove previous WireGuard endpoint route",
			Request: platformexec.Request{Executable: ipExecutable, Arguments: []string{
				"-4", "route", "del", oldEndpoint.String() + "/32", "via", previous.Gateway,
				"dev", previous.InterfaceName, "table", strconv.FormatUint(uint64(previous.RoutingTableID), 10),
				"protocol", strconv.Itoa(routing.OwnedProtocol),
			}},
			AllowedExitCodes: []int{2},
		})
	}
	return operations, nil
}

func (controller Controller) Apply(ctx context.Context, operations []Operation) error {
	if controller.Executor == nil || controller.IPExecutable == "" || controller.WGExecutable == "" {
		return errors.New("complete WireGuard controller executables are required")
	}
	if !controller.Mutate {
		return nil
	}
	for _, operation := range operations {
		result, err := controller.Executor.Run(ctx, operation.Request)
		if err == nil || allowedExitCode(operation.AllowedExitCodes, result.ExitCode) {
			continue
		}
		return fmt.Errorf("%s: %w", operation.Description, err)
	}
	return nil
}

func allowedExitCode(allowed []int, value int) bool {
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}
