// Package routing renders an owned network plan into explicit iproute2
// operations. Rendering is platform-independent and does not mutate the host.
package routing

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"gateway-vpn/internal/networkplan"
	"gateway-vpn/internal/platformexec"
)

const OwnedProtocol = 186

type Operation struct {
	Description      string
	Request          platformexec.Request
	AllowedExitCodes []int
}

func Render(plan networkplan.Plan, ipExecutable string) ([]Operation, error) {
	if plan.Owner != networkplan.Owner {
		return nil, errors.New("refusing to render a network plan owned by another component")
	}
	var operations []Operation
	for _, route := range plan.Routes {
		if route.TableID < 256 || route.TableID == 254 {
			return nil, fmt.Errorf("refusing route in reserved/main table %d", route.TableID)
		}
		arguments := []string{"-4", "route", "replace", route.Destination.String()}
		if route.Via.IsValid() {
			arguments = append(arguments, "via", route.Via.String())
		}
		arguments = append(arguments, "dev", route.Device)
		if route.ScopeLink {
			arguments = append(arguments, "scope", "link")
		}
		arguments = append(arguments, "table", strconv.FormatUint(uint64(route.TableID), 10), "protocol", strconv.Itoa(OwnedProtocol))
		operations = append(operations, Operation{
			Description: fmt.Sprintf("replace route for modem %s", route.ModemID),
			Request:     platformexec.Request{Executable: ipExecutable, Arguments: arguments},
		})
	}
	for _, rule := range plan.Rules {
		priority := strconv.FormatUint(uint64(rule.Priority), 10)
		protocol := strconv.Itoa(OwnedProtocol)
		operations = append(operations,
			Operation{
				Description: "remove previous owned rule for modem " + rule.ModemID,
				Request: platformexec.Request{
					Executable: ipExecutable,
					Arguments:  []string{"-4", "rule", "del", "priority", priority, "protocol", protocol},
				},
				AllowedExitCodes: []int{2},
			},
			Operation{
				Description: "add owned rule for modem " + rule.ModemID,
				Request: platformexec.Request{
					Executable: ipExecutable,
					Arguments: []string{
						"-4", "rule", "add",
						"priority", priority,
						"fwmark", fmt.Sprintf("%#x/%#x", rule.Fwmark, rule.Mask),
						"lookup", strconv.FormatUint(uint64(rule.TableID), 10),
						"protocol", protocol,
					},
				},
			},
		)
	}
	return operations, nil
}

func RenderRemoval(plan networkplan.Plan, modemID, ipExecutable string) ([]Operation, error) {
	if plan.Owner != networkplan.Owner || modemID == "" {
		return nil, errors.New("owned network plan and modem id are required for removal")
	}
	var operations []Operation
	for _, rule := range plan.Rules {
		if rule.ModemID != modemID {
			continue
		}
		operations = append(operations, Operation{Description: "remove owned rule for modem " + modemID, Request: platformexec.Request{Executable: ipExecutable, Arguments: []string{"-4", "rule", "del", "priority", strconv.FormatUint(uint64(rule.Priority), 10), "protocol", strconv.Itoa(OwnedProtocol)}}, AllowedExitCodes: []int{2}})
	}
	for _, route := range plan.Routes {
		if route.ModemID != modemID {
			continue
		}
		arguments := []string{"-4", "route", "del", route.Destination.String()}
		if route.Via.IsValid() {
			arguments = append(arguments, "via", route.Via.String())
		}
		arguments = append(arguments, "dev", route.Device, "table", strconv.FormatUint(uint64(route.TableID), 10), "protocol", strconv.Itoa(OwnedProtocol))
		operations = append(operations, Operation{Description: "remove owned route for modem " + modemID, Request: platformexec.Request{Executable: ipExecutable, Arguments: arguments}, AllowedExitCodes: []int{2}})
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("modem %s is absent from owned network plan", modemID)
	}
	return operations, nil
}

type ApplyOptions struct {
	Mutate bool
}

func Apply(ctx context.Context, executor platformexec.Executor, operations []Operation, options ApplyOptions) error {
	if !options.Mutate {
		return nil
	}
	for _, operation := range operations {
		result, err := executor.Run(ctx, operation.Request)
		if err == nil {
			continue
		}
		if contains(operation.AllowedExitCodes, result.ExitCode) {
			continue
		}
		return fmt.Errorf("%s: %w", operation.Description, err)
	}
	return nil
}

func contains(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
