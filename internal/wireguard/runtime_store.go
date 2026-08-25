package wireguard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const runtimeSettingsKey = "wireguard_runtime"

type RuntimeState struct {
	CurrentModemID     string `json:"current_modem_id,omitempty"`
	CandidateModemID   string `json:"candidate_modem_id,omitempty"`
	EndpointIP         string `json:"endpoint_ip,omitempty"`
	EndpointResolvedAt string `json:"endpoint_resolved_at,omitempty"`
	EndpointExpiresAt  string `json:"endpoint_expires_at,omitempty"`
	ProbeStartedAt     string `json:"probe_started_at,omitempty"`
	LastSwitchAt       string `json:"last_switch_at,omitempty"`
	LastHandshakeAt    string `json:"last_handshake_at,omitempty"`
	ConfigSHA256       string `json:"config_sha256,omitempty"`
	RouteModemID       string `json:"route_modem_id,omitempty"`
	RouteInterface     string `json:"route_interface,omitempty"`
	RouteGateway       string `json:"route_gateway,omitempty"`
	RouteTableID       uint32 `json:"route_table_id,omitempty"`
	RouteFwmark        uint32 `json:"route_fwmark,omitempty"`
}

type RuntimeStore struct {
	Database *sql.DB
}

func (store RuntimeStore) Get(ctx context.Context) (RuntimeState, error) {
	if store.Database == nil {
		return RuntimeState{}, errors.New("WireGuard runtime database is required")
	}
	var content string
	err := store.Database.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", runtimeSettingsKey).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeState{}, nil
	}
	if err != nil {
		return RuntimeState{}, fmt.Errorf("read WireGuard runtime state: %w", err)
	}
	var state RuntimeState
	if err := json.Unmarshal([]byte(content), &state); err != nil {
		return RuntimeState{}, errors.New("stored WireGuard runtime state is invalid")
	}
	return state, nil
}

func (store RuntimeStore) Put(ctx context.Context, state RuntimeState, now time.Time) error {
	if store.Database == nil {
		return errors.New("WireGuard runtime database is required")
	}
	content, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode WireGuard runtime state failed")
	}
	_, err = store.Database.ExecContext(ctx, `
INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at`, runtimeSettingsKey, string(content), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("persist WireGuard runtime state: %w", err)
	}
	return nil
}
