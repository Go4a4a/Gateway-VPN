package managementfabric

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// GatewayAppliedSnapshot contains only database convergence metadata.  It is
// persisted in the root-owned host transaction journal and may be restored
// after a failed kernel/nftables apply.  Desired configuration is never
// rewritten by rollback.
type GatewayAppliedSnapshot struct {
	Generation int64                     `json:"generation"`
	State      string                    `json:"state"`
	ErrorCode  string                    `json:"error_code"`
	Links      []GatewayLinkAppliedState `json:"links"`
	Resources  []GatewayResourceApplied  `json:"resources"`
	Aliases    []GatewayAliasApplied     `json:"aliases"`
	AdminPeers []GatewayAdminPeerApplied `json:"admin_peers"`
}

type GatewayLinkAppliedState struct {
	ID               string `json:"id"`
	SelectedUplinkID string `json:"selected_uplink_id,omitempty"`
	RouteGeneration  int64  `json:"route_generation"`
	ACLGeneration    int64  `json:"acl_generation"`
	State            string `json:"state"`
	ErrorCode        string `json:"error_code"`
}

type GatewayResourceApplied struct {
	ID              string `json:"id"`
	RouteGeneration int64  `json:"route_generation"`
	HealthState     string `json:"health_state"`
}

type GatewayAliasApplied struct {
	ID              string `json:"id"`
	RouteGeneration int64  `json:"route_generation"`
	ACLGeneration   int64  `json:"acl_generation"`
	State           string `json:"state"`
	ErrorCode       string `json:"error_code"`
}

type GatewayAdminPeerApplied struct {
	ID         string `json:"id"`
	Generation int64  `json:"generation"`
	State      string `json:"state"`
}

func (repository *Repository) GatewayFabricGenerations(ctx context.Context) (desired, applied int64, state, errorCode string, err error) {
	if repository == nil || repository.Database == nil {
		return 0, 0, "", "", errors.New("management database is required")
	}
	err = repository.Database.QueryRowContext(ctx, `
SELECT desired_generation,applied_generation,state,last_error_code
FROM management_fabric_generations WHERE singleton_id=1`).Scan(&desired, &applied, &state, &errorCode)
	if err != nil || desired < 1 || applied < 0 || applied > desired || !validFabricState(state) {
		return 0, 0, "", "", errors.New("management fabric generation state is invalid")
	}
	return desired, applied, state, errorCode, nil
}

func (repository *Repository) CaptureGatewayAppliedState(ctx context.Context) (GatewayAppliedSnapshot, error) {
	if repository == nil || repository.Database == nil {
		return GatewayAppliedSnapshot{}, errors.New("management database is required")
	}
	tx, err := repository.Database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return GatewayAppliedSnapshot{}, err
	}
	defer tx.Rollback()
	var snapshot GatewayAppliedSnapshot
	if err := tx.QueryRowContext(ctx, `SELECT applied_generation,state,last_error_code FROM management_fabric_generations WHERE singleton_id=1`).Scan(&snapshot.Generation, &snapshot.State, &snapshot.ErrorCode); err != nil {
		return GatewayAppliedSnapshot{}, errors.New("read management fabric applied state failed")
	}
	if snapshot.Generation < 0 || !validFabricState(snapshot.State) {
		return GatewayAppliedSnapshot{}, errors.New("management fabric applied state is invalid")
	}
	if err := scanAppliedRows(ctx, tx, `SELECT id,COALESCE(selected_uplink_id,''),applied_route_generation,applied_acl_generation,state,last_error_code FROM management_links ORDER BY id`, func(rows *sql.Rows) error {
		var item GatewayLinkAppliedState
		if err := rows.Scan(&item.ID, &item.SelectedUplinkID, &item.RouteGeneration, &item.ACLGeneration, &item.State, &item.ErrorCode); err != nil {
			return err
		}
		snapshot.Links = append(snapshot.Links, item)
		return nil
	}); err != nil {
		return GatewayAppliedSnapshot{}, err
	}
	if err := scanAppliedRows(ctx, tx, `SELECT id,applied_route_generation,health_state FROM management_resources ORDER BY id`, func(rows *sql.Rows) error {
		var item GatewayResourceApplied
		if err := rows.Scan(&item.ID, &item.RouteGeneration, &item.HealthState); err != nil {
			return err
		}
		snapshot.Resources = append(snapshot.Resources, item)
		return nil
	}); err != nil {
		return GatewayAppliedSnapshot{}, err
	}
	if err := scanAppliedRows(ctx, tx, `SELECT id,applied_route_generation,applied_acl_generation,state,last_error_code FROM management_resource_publications ORDER BY id`, func(rows *sql.Rows) error {
		var item GatewayAliasApplied
		if err := rows.Scan(&item.ID, &item.RouteGeneration, &item.ACLGeneration, &item.State, &item.ErrorCode); err != nil {
			return err
		}
		snapshot.Aliases = append(snapshot.Aliases, item)
		return nil
	}); err != nil {
		return GatewayAppliedSnapshot{}, err
	}
	if err := scanAppliedRows(ctx, tx, `SELECT id,applied_generation,state FROM management_admin_vps_peers ORDER BY id`, func(rows *sql.Rows) error {
		var item GatewayAdminPeerApplied
		if err := rows.Scan(&item.ID, &item.Generation, &item.State); err != nil {
			return err
		}
		snapshot.AdminPeers = append(snapshot.AdminPeers, item)
		return nil
	}); err != nil {
		return GatewayAppliedSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return GatewayAppliedSnapshot{}, err
	}
	return snapshot, nil
}

func scanAppliedRows(ctx context.Context, tx *sql.Tx, query string, scan func(*sql.Rows) error) error {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// MarkGatewayHostPlanApplied is the only success commit for the Gateway host
// transaction.  The conditional generation update rejects a plan that became
// stale while root was configuring the host.
func (repository *Repository) MarkGatewayHostPlanApplied(ctx context.Context, plan GatewayHostPlan, now time.Time) error {
	if repository == nil || repository.Database == nil || ValidateGatewayHostPlan(plan) != nil {
		return errors.New("valid Gateway host plan and database are required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `
UPDATE management_fabric_generations
SET applied_generation=?,state='APPLIED',last_error_code='',updated_at=?
WHERE singleton_id=1 AND desired_generation=?`, plan.Generation, stamp, plan.Generation)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("management fabric generation changed during host apply")
	}
	linkIDs := make(map[string]struct{}, len(plan.Links))
	resourceIDs := make(map[string]struct{}, len(plan.Aliases))
	publicationIDs := make(map[string]struct{}, len(plan.Aliases))
	for _, link := range plan.Links {
		linkIDs[link.LinkID] = struct{}{}
		result, err = tx.ExecContext(ctx, `
UPDATE management_links
SET selected_uplink_id=?,applied_route_generation=desired_route_generation,
    applied_acl_generation=desired_acl_generation,state='CONNECTING',last_error_code='',updated_at=?
WHERE id=? AND enabled=1`, link.UplinkID, stamp, link.LinkID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return fmt.Errorf("management link %s changed during host apply", link.LinkID)
		}
	}
	for _, alias := range plan.Aliases {
		resourceIDs[alias.ResourceID] = struct{}{}
		publicationIDs[alias.PublicationID] = struct{}{}
	}
	for id := range resourceIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE management_resources SET applied_route_generation=desired_route_generation,health_state='UNKNOWN',updated_at=? WHERE id=? AND enabled=1`, stamp, id); err != nil {
			return err
		}
	}
	for id := range publicationIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE management_resource_publications SET applied_route_generation=desired_route_generation,applied_acl_generation=desired_acl_generation,state='APPLIED',last_error_code='',updated_at=? WHERE id=?`, stamp, id); err != nil {
			return err
		}
	}
	for id := range linkIDs {
		if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_vps_peers
SET applied_generation=desired_generation,state='ACTIVE',updated_at=?
WHERE state!='REVOKED' AND vps_id=(SELECT vps_id FROM management_links WHERE id=?)`, stamp, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (repository *Repository) RestoreGatewayAppliedState(ctx context.Context, snapshot GatewayAppliedSnapshot, now time.Time) error {
	if repository == nil || repository.Database == nil || snapshot.Generation < 0 || !validFabricState(snapshot.State) {
		return errors.New("valid Gateway applied snapshot and database are required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE management_fabric_generations SET applied_generation=?,state=?,last_error_code=?,updated_at=? WHERE singleton_id=1`, snapshot.Generation, snapshot.State, snapshot.ErrorCode, stamp); err != nil {
		return err
	}
	for _, item := range snapshot.Links {
		if _, err := tx.ExecContext(ctx, `UPDATE management_links SET selected_uplink_id=NULLIF(?,''),applied_route_generation=?,applied_acl_generation=?,state=?,last_error_code=?,updated_at=? WHERE id=?`, item.SelectedUplinkID, item.RouteGeneration, item.ACLGeneration, item.State, item.ErrorCode, stamp, item.ID); err != nil {
			return err
		}
	}
	for _, item := range snapshot.Resources {
		if _, err := tx.ExecContext(ctx, `UPDATE management_resources SET applied_route_generation=?,health_state=?,updated_at=? WHERE id=?`, item.RouteGeneration, item.HealthState, stamp, item.ID); err != nil {
			return err
		}
	}
	for _, item := range snapshot.Aliases {
		if _, err := tx.ExecContext(ctx, `UPDATE management_resource_publications SET applied_route_generation=?,applied_acl_generation=?,state=?,last_error_code=?,updated_at=? WHERE id=?`, item.RouteGeneration, item.ACLGeneration, item.State, item.ErrorCode, stamp, item.ID); err != nil {
			return err
		}
	}
	for _, item := range snapshot.AdminPeers {
		if _, err := tx.ExecContext(ctx, `UPDATE management_admin_vps_peers SET applied_generation=?,state=?,updated_at=? WHERE id=?`, item.Generation, item.State, stamp, item.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (repository *Repository) MarkGatewayHostPlanFailed(ctx context.Context, generation int64, code string, now time.Time) error {
	if repository == nil || repository.Database == nil || generation < 1 || !safeIdentifier.MatchString(code) {
		return errors.New("valid management generation and error code are required")
	}
	_, err := repository.Database.ExecContext(ctx, `
UPDATE management_fabric_generations SET state='PENDING_RETRY',last_error_code=?,updated_at=?
WHERE singleton_id=1 AND desired_generation=?`, code, now.UTC().Format(time.RFC3339Nano), generation)
	return err
}

func validFabricState(value string) bool {
	return value == "PENDING" || value == "APPLIED" || value == "PARTIAL" || value == "PENDING_RETRY" || value == "ROLLED_BACK"
}
