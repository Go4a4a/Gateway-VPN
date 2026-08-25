package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/networkapply"
)

func networkCandidateBuilder(configuration config.Config, database *sql.DB) func(context.Context, string) (networkapply.Candidate, error) {
	return func(ctx context.Context, newLANAddress string) (networkapply.Candidate, error) {
		oldPrefix, err := netip.ParsePrefix(configuration.Network.LANAddress)
		if err != nil {
			return networkapply.Candidate{}, errors.New("current LAN address is invalid")
		}
		newPrefix, ok := netutil.ParsePrivateLAN(newLANAddress)
		if !ok {
			return networkapply.Candidate{}, errors.New("new LAN address must be a usable private IPv4 host CIDR")
		}
		newNetwork := newPrefix.Masked()
		if newNetwork.Overlaps(netip.MustParsePrefix("10.80.0.0/24")) {
			return networkapply.Candidate{}, errors.New("new LAN overlaps WireGuard management network")
		}
		rows, err := database.QueryContext(ctx, "SELECT id, management_cidr FROM modems WHERE management_cidr IS NOT NULL AND management_cidr<>''")
		if err != nil {
			return networkapply.Candidate{}, fmt.Errorf("read modem networks: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, raw string
			if err := rows.Scan(&id, &raw); err != nil {
				return networkapply.Candidate{}, err
			}
			management, err := netip.ParsePrefix(raw)
			if err != nil {
				return networkapply.Candidate{}, fmt.Errorf("modem %s has invalid stored management network", id)
			}
			if newNetwork.Overlaps(management.Masked()) {
				return networkapply.Candidate{}, fmt.Errorf("new LAN overlaps modem %s management network", id)
			}
		}
		if err := rows.Err(); err != nil {
			return networkapply.Candidate{}, err
		}
		var apiPort string
		matches := 0
		for _, listen := range configuration.API.Listen {
			host, port, err := net.SplitHostPort(listen)
			if err == nil && host == oldPrefix.Addr().String() {
				apiPort = port
				matches++
			}
		}
		if matches != 1 {
			return networkapply.Candidate{}, errors.New("current LAN API endpoint is ambiguous")
		}
		return networkapply.Candidate{
			InterfaceName: configuration.Network.LANInterface,
			OldLANCIDR:    configuration.Network.LANAddress,
			NewLANCIDR:    newPrefix.String(),
			OldURL:        "https://" + net.JoinHostPort(oldPrefix.Addr().String(), apiPort),
			NewURL:        "https://" + net.JoinHostPort(newPrefix.Addr().String(), apiPort),
		}, nil
	}
}
