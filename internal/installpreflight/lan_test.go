package installpreflight

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gateway-vpn/internal/platformexec"
)

func TestCheckGatewayLANAllowsCleanHostAndIdempotentKernelRoutes(t *testing.T) {
	executor := &lanExecutor{
		addresses: `[{"ifname":"enp2s0","addr_info":[{"family":"inet","local":"192.168.200.1","prefixlen":24}]},{"ifname":"enxmodem","addr_info":[{"family":"inet","local":"192.168.8.2","prefixlen":24}]}]`,
		routes:    `[{"dst":"default","gateway":"192.168.8.1","dev":"enxmodem"},{"dst":"192.168.200.0/24","dev":"enp2s0","protocol":"kernel","scope":"link","prefsrc":"192.168.200.1"},{"type":"local","dst":"192.168.200.1","dev":"enp2s0","protocol":2,"scope":"host"},{"type":"broadcast","dst":"192.168.200.255","dev":"enp2s0","protocol":"kernel","scope":"link","prefsrc":"192.168.200.1"}]`,
	}
	if err := CheckGatewayLAN(context.Background(), executor, validLANOptions()); err != nil {
		t.Fatalf("CheckGatewayLAN() error = %v", err)
	}
	if len(executor.calls) != 2 || strings.Join(executor.calls[0].Arguments, " ") != "-json -4 address show" || strings.Join(executor.calls[1].Arguments, " ") != "-json -4 route show table all" {
		t.Fatalf("typed observation calls = %+v", executor.calls)
	}
}

func TestCheckGatewayLANRejectsAddressAndRouteOverlap(t *testing.T) {
	for _, test := range []struct {
		name      string
		addresses string
		routes    string
		want      string
	}{
		{name: "address", addresses: `[{"ifname":"wg-extra","addr_info":[{"family":"inet","local":"192.168.200.20","prefixlen":28}]}]`, routes: `[]`, want: "wg-extra"},
		{name: "route", addresses: `[]`, routes: `[{"dst":"192.168.200.0/25","dev":"wg-extra","protocol":"static"}]`, want: "route"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := CheckGatewayLAN(context.Background(), &lanExecutor{addresses: test.addresses, routes: test.routes}, validLANOptions())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("CheckGatewayLAN() error = %v", err)
			}
		})
	}
}

func TestCheckGatewayLANRejectsUnsafeInputAndMalformedObservation(t *testing.T) {
	for _, cidr := range []string{"8.8.8.8/24", "192.168.200.0/24", "10.80.0.2/24"} {
		if err := CheckGatewayLAN(context.Background(), &lanExecutor{}, LANOptions{Interface: "enp2s0", CIDR: cidr, IPPath: "/usr/sbin/ip"}); err == nil {
			t.Errorf("unsafe CIDR %q was accepted", cidr)
		}
	}
	if err := CheckGatewayLAN(context.Background(), &lanExecutor{addresses: `{`, routes: `[]`}, validLANOptions()); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("malformed observation error = %v", err)
	}
}

func validLANOptions() LANOptions {
	return LANOptions{Interface: "enp2s0", CIDR: "192.168.200.1/24", IPPath: "/usr/sbin/ip"}
}

type lanExecutor struct {
	addresses string
	routes    string
	calls     []platformexec.Request
}

func (executor *lanExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.calls = append(executor.calls, request)
	switch strings.Join(request.Arguments, " ") {
	case "-json -4 address show":
		return platformexec.Result{Stdout: executor.addresses}, nil
	case "-json -4 route show table all":
		return platformexec.Result{Stdout: executor.routes}, nil
	default:
		return platformexec.Result{}, errors.New("unexpected command")
	}
}
