package managementfabric

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

const resourceSelect = `
SELECT id,site_id,name,resource_kind,access_profile,local_destination,enabled,
       advanced_scope_acknowledged,desired_route_generation,applied_route_generation,
       health_state,health_reason_code,COALESCE(last_probe_at,''),last_probe_route_generation,
       probe_interface,probe_gateway,health_probe_address,created_at,updated_at
FROM management_resources`

func (repository *Repository) CreateResource(ctx context.Context, input ResourceInput) (Resource, error) {
	input = normalizedResourceInput(input)
	if repository == nil || repository.Database == nil || ValidateResourceInput(input) != nil {
		return Resource{}, errors.New("valid management resource input and database are required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Resource{}, err
	}
	defer tx.Rollback()
	var siteID string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM management_sites WHERE is_local=1 AND identity_state='ACTIVE'").Scan(&siteID); err != nil {
		return Resource{}, errors.New("active local management site is required")
	}
	state, reason := resetResourceHealth(input.Enabled, input.AccessProfile)
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO management_resources(
    id,site_id,name,resource_kind,access_profile,local_destination,enabled,
    advanced_scope_acknowledged,health_probe_address,health_state,health_reason_code,created_at,updated_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, input.ID, siteID, input.Name, input.Kind, input.AccessProfile,
		input.LocalDestination, boolInt(input.Enabled), boolInt(input.AdvancedScopeAcknowledged), input.HealthProbeAddress,
		state, reason, now, now); err != nil {
		return Resource{}, fmt.Errorf("create management resource: %w", err)
	}
	if err := replaceResourcePortsTx(ctx, tx, input.ID, input.Ports); err != nil {
		return Resource{}, err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return Resource{}, err
	}
	if err := tx.Commit(); err != nil {
		return Resource{}, err
	}
	return repository.GetResource(ctx, input.ID)
}

func (repository *Repository) GetResource(ctx context.Context, id string) (Resource, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return Resource{}, store.ErrNotFound
	}
	item, err := scanResource(repository.Database.QueryRowContext(ctx, resourceSelect+" WHERE id=?", id))
	if err != nil {
		return Resource{}, err
	}
	item.Ports, err = listResourcePorts(ctx, repository.Database, id)
	item.ExternalPrerequisites = ResourceExternalPrerequisites(item.AccessProfile)
	return item, err
}

func (repository *Repository) UpdateResource(ctx context.Context, id string, input ResourceInput) (Resource, error) {
	input.ID = id
	input = normalizedResourceInput(input)
	if repository == nil || repository.Database == nil || ValidateResourceInput(input) != nil {
		return Resource{}, errors.New("valid management resource update is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Resource{}, err
	}
	defer tx.Rollback()
	current, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id=?", id))
	if err != nil {
		return Resource{}, err
	}
	current.Ports, err = listResourcePorts(ctx, tx, id)
	if err != nil {
		return Resource{}, err
	}
	configurationChanged := current.Kind != input.Kind || current.AccessProfile != input.AccessProfile ||
		current.LocalDestination != input.LocalDestination || current.Enabled != input.Enabled ||
		current.HealthProbeAddress != input.HealthProbeAddress ||
		current.AdvancedScopeAcknowledged != input.AdvancedScopeAcknowledged || !sameResourcePorts(current.Ports, input.Ports)
	if !configurationChanged && current.Name == input.Name {
		if err := tx.Commit(); err != nil {
			return Resource{}, err
		}
		return repository.GetResource(ctx, id)
	}
	if configurationChanged {
		if err := validateExistingACLPortsTx(ctx, tx, id, input.Ports); err != nil {
			return Resource{}, err
		}
	}
	now := repository.now().Format(time.RFC3339Nano)
	if !configurationChanged {
		if _, err := tx.ExecContext(ctx, "UPDATE management_resources SET name=?,updated_at=? WHERE id=?", input.Name, now, id); err != nil {
			return Resource{}, err
		}
	} else {
		state, reason := resetResourceHealth(input.Enabled, input.AccessProfile)
		if _, err := tx.ExecContext(ctx, `
UPDATE management_resources
SET name=?,resource_kind=?,access_profile=?,local_destination=?,health_probe_address=?,enabled=?,advanced_scope_acknowledged=?,
    desired_route_generation=desired_route_generation+1,health_state=?,health_reason_code=?,
    last_probe_at=NULL,last_probe_route_generation=0,probe_interface='',probe_gateway='',updated_at=?
WHERE id=?`, input.Name, input.Kind, input.AccessProfile, input.LocalDestination, input.HealthProbeAddress, boolInt(input.Enabled),
			boolInt(input.AdvancedScopeAcknowledged), state, reason, now, id); err != nil {
			return Resource{}, fmt.Errorf("update management resource: %w", err)
		}
		if err := replaceResourcePortsTx(ctx, tx, id, input.Ports); err != nil {
			return Resource{}, err
		}
		links, err := resourceLinkIDsTx(ctx, tx, id)
		if err != nil {
			return Resource{}, err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE management_resource_publications
SET desired_route_generation=desired_route_generation+1,desired_acl_generation=desired_acl_generation+1,
    state=CASE WHEN state='DISABLED' THEN 'DISABLED' ELSE 'PENDING' END,last_error_code='',updated_at=?
WHERE resource_id=?`, now, id); err != nil {
			return Resource{}, err
		}
		if err := bumpLinkGenerationsTx(ctx, tx, links, true, true, now); err != nil {
			return Resource{}, err
		}
		if err := advanceGeneration(ctx, tx, now); err != nil {
			return Resource{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Resource{}, err
	}
	return repository.GetResource(ctx, id)
}

func (repository *Repository) DeleteResource(ctx context.Context, id string) error {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return store.ErrNotFound
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM management_resources WHERE id=?", id).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return err
	}
	if enabled != 0 {
		return errors.New("management resource must be disabled before deletion")
	}
	links, err := resourceLinkIDsTx(ctx, tx, id)
	if err != nil {
		return err
	}
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "DELETE FROM management_resources WHERE id=?", id); err != nil {
		return err
	}
	if err := bumpLinkGenerationsTx(ctx, tx, links, true, true, now); err != nil {
		return err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) CreateResourcePublication(ctx context.Context, input ResourcePublicationInput) (ResourcePublication, error) {
	input = normalizedPublicationInput(input)
	if repository == nil || repository.Database == nil || validatePublicationIdentity(input) != nil {
		return ResourcePublication{}, errors.New("valid resource publication input is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ResourcePublication{}, err
	}
	defer tx.Rollback()
	if err := repository.validatePublicationTx(ctx, tx, input, ""); err != nil {
		return ResourcePublication{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	state := "PENDING"
	if !input.Enabled {
		state = "DISABLED"
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO management_resource_publications(id,resource_id,link_id,published_alias,state,created_at,updated_at)
VALUES(?,?,?,?,?,?,?)`, input.ID, input.ResourceID, input.LinkID, input.PublishedAlias, state, now, now); err != nil {
		return ResourcePublication{}, fmt.Errorf("create resource publication: %w", err)
	}
	if err := bumpLinkGenerationsTx(ctx, tx, []string{input.LinkID}, true, true, now); err != nil {
		return ResourcePublication{}, err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return ResourcePublication{}, err
	}
	if err := tx.Commit(); err != nil {
		return ResourcePublication{}, err
	}
	return repository.GetResourcePublication(ctx, input.ID)
}

func (repository *Repository) GetResourcePublication(ctx context.Context, id string) (ResourcePublication, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return ResourcePublication{}, store.ErrNotFound
	}
	return scanResourcePublication(repository.Database.QueryRowContext(ctx, `
SELECT id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,
       desired_acl_generation,applied_acl_generation,state,last_error_code,created_at,updated_at
FROM management_resource_publications WHERE id=?`, id))
}

func (repository *Repository) UpdateResourcePublication(ctx context.Context, id string, input ResourcePublicationInput) (ResourcePublication, error) {
	input.ID = id
	input = normalizedPublicationInput(input)
	if repository == nil || repository.Database == nil || validatePublicationIdentity(input) != nil {
		return ResourcePublication{}, errors.New("valid resource publication update is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ResourcePublication{}, err
	}
	defer tx.Rollback()
	current, err := scanResourcePublication(tx.QueryRowContext(ctx, `
SELECT id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,
       desired_acl_generation,applied_acl_generation,state,last_error_code,created_at,updated_at
FROM management_resource_publications WHERE id=?`, id))
	if err != nil {
		return ResourcePublication{}, err
	}
	if err := repository.validatePublicationTx(ctx, tx, input, id); err != nil {
		return ResourcePublication{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	state := "PENDING"
	if !input.Enabled {
		state = "DISABLED"
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE management_resource_publications
SET resource_id=?,link_id=?,published_alias=?,desired_route_generation=desired_route_generation+1,
    desired_acl_generation=desired_acl_generation+1,state=?,last_error_code='',updated_at=? WHERE id=?`,
		input.ResourceID, input.LinkID, input.PublishedAlias, state, now, id); err != nil {
		return ResourcePublication{}, err
	}
	if err := bumpLinkGenerationsTx(ctx, tx, []string{current.LinkID, input.LinkID}, true, true, now); err != nil {
		return ResourcePublication{}, err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return ResourcePublication{}, err
	}
	if err := tx.Commit(); err != nil {
		return ResourcePublication{}, err
	}
	return repository.GetResourcePublication(ctx, id)
}

func (repository *Repository) DeleteResourcePublication(ctx context.Context, id string) error {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return store.ErrNotFound
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var linkID, state string
	if err := tx.QueryRowContext(ctx, "SELECT link_id,state FROM management_resource_publications WHERE id=?", id).Scan(&linkID, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return err
	}
	if state != "DISABLED" {
		return errors.New("resource publication must be disabled before deletion")
	}
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "DELETE FROM management_resource_publications WHERE id=?", id); err != nil {
		return err
	}
	if err := bumpLinkGenerationsTx(ctx, tx, []string{linkID}, true, true, now); err != nil {
		return err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) CreateResourceACL(ctx context.Context, input ResourceACLInput) (ResourceACL, error) {
	input = normalizedACLInput(input)
	if repository == nil || repository.Database == nil || validateACLIdentity(input) != nil {
		return ResourceACL{}, errors.New("valid resource ACL input is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ResourceACL{}, err
	}
	defer tx.Rollback()
	if err := repository.validateACLTx(ctx, tx, input); err != nil {
		return ResourceACL{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO management_resource_acl(id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,1,?,?)`, input.ID, input.AdminID, input.ResourceID, input.Protocol, input.PortStart, input.PortEnd, boolInt(input.Enabled), now, now); err != nil {
		return ResourceACL{}, fmt.Errorf("create resource ACL: %w", err)
	}
	links, err := resourceLinkIDsTx(ctx, tx, input.ResourceID)
	if err != nil {
		return ResourceACL{}, err
	}
	if err := bumpLinkGenerationsTx(ctx, tx, links, false, true, now); err != nil {
		return ResourceACL{}, err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return ResourceACL{}, err
	}
	if err := tx.Commit(); err != nil {
		return ResourceACL{}, err
	}
	return repository.GetResourceACL(ctx, input.ID)
}

func (repository *Repository) GetResourceACL(ctx context.Context, id string) (ResourceACL, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return ResourceACL{}, store.ErrNotFound
	}
	return scanResourceACL(repository.Database.QueryRowContext(ctx, `
SELECT id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at
FROM management_resource_acl WHERE id=?`, id))
}

func (repository *Repository) UpdateResourceACL(ctx context.Context, id string, input ResourceACLInput) (ResourceACL, error) {
	input.ID = id
	input = normalizedACLInput(input)
	if repository == nil || repository.Database == nil || validateACLIdentity(input) != nil {
		return ResourceACL{}, errors.New("valid resource ACL update is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ResourceACL{}, err
	}
	defer tx.Rollback()
	current, err := scanResourceACL(tx.QueryRowContext(ctx, `
SELECT id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at
FROM management_resource_acl WHERE id=?`, id))
	if err != nil {
		return ResourceACL{}, err
	}
	if err := repository.validateACLTx(ctx, tx, input); err != nil {
		return ResourceACL{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
UPDATE management_resource_acl
SET admin_id=?,resource_id=?,protocol=?,port_start=?,port_end=?,enabled=?,generation=generation+1,updated_at=?
WHERE id=?`, input.AdminID, input.ResourceID, input.Protocol, input.PortStart, input.PortEnd, boolInt(input.Enabled), now, id); err != nil {
		return ResourceACL{}, err
	}
	oldLinks, err := resourceLinkIDsTx(ctx, tx, current.ResourceID)
	if err != nil {
		return ResourceACL{}, err
	}
	newLinks, err := resourceLinkIDsTx(ctx, tx, input.ResourceID)
	if err != nil {
		return ResourceACL{}, err
	}
	if err := bumpLinkGenerationsTx(ctx, tx, append(oldLinks, newLinks...), false, true, now); err != nil {
		return ResourceACL{}, err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return ResourceACL{}, err
	}
	if err := tx.Commit(); err != nil {
		return ResourceACL{}, err
	}
	return repository.GetResourceACL(ctx, id)
}

func (repository *Repository) DeleteResourceACL(ctx context.Context, id string) error {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return store.ErrNotFound
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var resourceID string
	var enabled int
	if err := tx.QueryRowContext(ctx, "SELECT resource_id,enabled FROM management_resource_acl WHERE id=?", id).Scan(&resourceID, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return err
	}
	if enabled != 0 {
		return errors.New("resource ACL must be disabled before deletion")
	}
	links, err := resourceLinkIDsTx(ctx, tx, resourceID)
	if err != nil {
		return err
	}
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "DELETE FROM management_resource_acl WHERE id=?", id); err != nil {
		return err
	}
	if err := bumpLinkGenerationsTx(ctx, tx, links, false, true, now); err != nil {
		return err
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) LoadResourceProbeSpec(ctx context.Context, id string) (ResourceProbeSpec, error) {
	resource, err := repository.GetResource(ctx, id)
	if err != nil {
		return ResourceProbeSpec{}, err
	}
	if !resource.Enabled {
		return ResourceProbeSpec{}, errors.New("disabled management resource cannot be probed")
	}
	spec := ResourceProbeSpec{
		ResourceID: id, Kind: resource.Kind, AccessProfile: resource.AccessProfile,
		LocalDestination: resource.LocalDestination, HealthProbeAddress: resource.HealthProbeAddress,
		RouteGeneration: resource.DesiredRouteGeneration,
		Ports:           append([]ResourcePort(nil), resource.Ports...),
	}
	switch resource.AccessProfile {
	case ProfileGatewayOnly:
		spec.AllowedInterfaces = []string{"lo"}
	case ProfileKeeneticWAN, ProfileKeeneticWANRouted:
		spec.AllowedInterfaces, err = repository.interfaceNamesForRoles(ctx, []string{"LAN_MEMBER", "MANAGEMENT", "SHARED_ONE_ARM"}, false)
	case ProfileDedicatedLAN:
		spec.AllowedInterfaces, err = repository.interfaceNamesForRoles(ctx, []string{"MANAGEMENT"}, true)
	case ProfileWireGuardRouter:
		spec.AllowedInterfaces = []string{"wg-ingress"}
		spec.ExpectedWireGuardPrefix, err = repository.wireGuardResourcePrefix(ctx, resource)
	default:
		err = errors.New("management resource access profile is unsupported")
	}
	if err != nil {
		return ResourceProbeSpec{}, err
	}
	sort.Strings(spec.AllowedInterfaces)
	return spec, nil
}

func (repository *Repository) RecordResourceProbe(ctx context.Context, result ResourceProbeResult) error {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(result.ResourceID) ||
		result.RouteGeneration < 1 || !validResourceHealth(result.State) || !safeIdentifier.MatchString(result.ReasonCode) ||
		result.CheckedAt == "" || len(result.Interface) > 15 || len(result.Gateway) > 64 {
		return errors.New("valid management resource probe result is required")
	}
	if result.Interface != "" && !validLinuxInterface(result.Interface) {
		return errors.New("management resource probe interface is invalid")
	}
	if result.Gateway != "" {
		address, err := netip.ParseAddr(result.Gateway)
		if err != nil || !address.Is4() || !address.IsPrivate() {
			return errors.New("management resource probe gateway is invalid")
		}
	}
	checked, err := time.Parse(time.RFC3339Nano, result.CheckedAt)
	if err != nil || checked.IsZero() {
		return errors.New("management resource probe timestamp is invalid")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	var generation int64
	var oldState string
	if err := tx.QueryRowContext(ctx, "SELECT enabled,desired_route_generation,health_state FROM management_resources WHERE id=?", result.ResourceID).Scan(&enabled, &generation, &oldState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return err
	}
	if enabled != 1 || generation != result.RouteGeneration {
		return store.ErrStaleGeneration
	}
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
UPDATE management_resources
SET health_state=?,health_reason_code=?,last_probe_at=?,last_probe_route_generation=?,
    probe_interface=?,probe_gateway=?,updated_at=?
WHERE id=? AND enabled=1 AND desired_route_generation=?`, result.State, result.ReasonCode,
		checked.UTC().Format(time.RFC3339Nano), result.RouteGeneration, result.Interface, result.Gateway,
		now, result.ResourceID, result.RouteGeneration); err != nil {
		return err
	}
	projectionChanged := (oldState == "HEALTHY") != (result.State == "HEALTHY")
	if projectionChanged {
		links, err := resourceLinkIDsTx(ctx, tx, result.ResourceID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE management_resource_publications
SET desired_route_generation=desired_route_generation+1,desired_acl_generation=desired_acl_generation+1,
    state=CASE WHEN state='DISABLED' THEN 'DISABLED' ELSE 'PENDING' END,last_error_code='',updated_at=?
WHERE resource_id=?`, now, result.ResourceID); err != nil {
			return err
		}
		if err := bumpLinkGenerationsTx(ctx, tx, links, true, true, now); err != nil {
			return err
		}
		if err := advanceGeneration(ctx, tx, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func normalizedResourceInput(input ResourceInput) ResourceInput {
	input.ID = strings.TrimSpace(input.ID)
	input.Name = strings.TrimSpace(input.Name)
	input.Kind = strings.TrimSpace(input.Kind)
	input.AccessProfile = strings.TrimSpace(input.AccessProfile)
	input.LocalDestination = strings.TrimSpace(input.LocalDestination)
	input.HealthProbeAddress = strings.TrimSpace(input.HealthProbeAddress)
	input.Ports = append([]ResourcePort(nil), input.Ports...)
	sort.Slice(input.Ports, func(i, j int) bool {
		if input.Ports[i].Protocol != input.Ports[j].Protocol {
			return input.Ports[i].Protocol < input.Ports[j].Protocol
		}
		if input.Ports[i].PortStart != input.Ports[j].PortStart {
			return input.Ports[i].PortStart < input.Ports[j].PortStart
		}
		return input.Ports[i].PortEnd < input.Ports[j].PortEnd
	})
	return input
}

func normalizedPublicationInput(input ResourcePublicationInput) ResourcePublicationInput {
	input.ID, input.ResourceID, input.LinkID = strings.TrimSpace(input.ID), strings.TrimSpace(input.ResourceID), strings.TrimSpace(input.LinkID)
	input.PublishedAlias = strings.TrimSpace(input.PublishedAlias)
	return input
}

func normalizedACLInput(input ResourceACLInput) ResourceACLInput {
	input.ID, input.AdminID, input.ResourceID = strings.TrimSpace(input.ID), strings.TrimSpace(input.AdminID), strings.TrimSpace(input.ResourceID)
	input.Protocol = strings.TrimSpace(input.Protocol)
	return input
}

func resetResourceHealth(enabled bool, profile string) (string, string) {
	if !enabled {
		return "UNKNOWN", "RESOURCE_DISABLED"
	}
	if profile == ProfileGatewayOnly {
		return "UNKNOWN", "RESOURCE_PROBE_REQUIRED"
	}
	return "WAITING_EXTERNAL_CONFIGURATION", "EXTERNAL_CONFIGURATION_REQUIRED"
}

func validResourceHealth(value string) bool {
	return value == "UNKNOWN" || value == "WAITING_EXTERNAL_CONFIGURATION" || value == "HEALTHY" || value == "DEGRADED" || value == "FAILED"
}

func sameResourcePorts(left, right []ResourcePort) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]ResourcePort(nil), left...)
	right = append([]ResourcePort(nil), right...)
	sort.Slice(left, func(i, j int) bool { return fmt.Sprint(left[i]) < fmt.Sprint(left[j]) })
	sort.Slice(right, func(i, j int) bool { return fmt.Sprint(right[i]) < fmt.Sprint(right[j]) })
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func replaceResourcePortsTx(ctx context.Context, tx *sql.Tx, resourceID string, ports []ResourcePort) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM management_resource_ports WHERE resource_id=?", resourceID); err != nil {
		return err
	}
	for _, port := range ports {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO management_resource_ports(resource_id,protocol,port_start,port_end) VALUES(?,?,?,?)`,
			resourceID, port.Protocol, port.PortStart, port.PortEnd); err != nil {
			return fmt.Errorf("store management resource port: %w", err)
		}
	}
	return nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listResourcePorts(ctx context.Context, database queryer, resourceID string) ([]ResourcePort, error) {
	rows, err := database.QueryContext(ctx, `
SELECT protocol,port_start,port_end FROM management_resource_ports
WHERE resource_id=? ORDER BY protocol,port_start,port_end`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ResourcePort, 0)
	for rows.Next() {
		var item ResourcePort
		if err := rows.Scan(&item.Protocol, &item.PortStart, &item.PortEnd); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func validateExistingACLPortsTx(ctx context.Context, tx *sql.Tx, resourceID string, ports []ResourcePort) error {
	rows, err := tx.QueryContext(ctx, `SELECT protocol,port_start,port_end FROM management_resource_acl WHERE resource_id=? AND enabled=1`, resourceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var protocol string
		var start, end int
		if err := rows.Scan(&protocol, &start, &end); err != nil {
			return err
		}
		if !resourcePortsAllow(ports, protocol, start, end) {
			return errors.New("disable or narrow existing ACL rules before removing their resource ports")
		}
	}
	return rows.Err()
}

func resourceLinkIDsTx(ctx context.Context, tx *sql.Tx, resourceID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT link_id FROM management_resource_publications WHERE resource_id=?", resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func bumpLinkGenerationsTx(ctx context.Context, tx *sql.Tx, ids []string, route, acl bool, now string) error {
	unique := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		unique[id] = struct{}{}
	}
	for id := range unique {
		query := "UPDATE management_links SET updated_at=?"
		if route {
			query += ",desired_route_generation=desired_route_generation+1"
		}
		if acl {
			query += ",desired_acl_generation=desired_acl_generation+1"
		}
		query += " WHERE id=?"
		if _, err := tx.ExecContext(ctx, query, now, id); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicationIdentity(input ResourcePublicationInput) error {
	if !safeIdentifier.MatchString(input.ID) || !safeIdentifier.MatchString(input.ResourceID) || !safeIdentifier.MatchString(input.LinkID) {
		return errors.New("resource publication identifiers are invalid")
	}
	return nil
}

func (repository *Repository) validatePublicationTx(ctx context.Context, tx *sql.Tx, input ResourcePublicationInput, excludedID string) error {
	var kind, destination, siteID, linkSiteID, pool string
	if err := tx.QueryRowContext(ctx, "SELECT resource_kind,local_destination,site_id FROM management_resources WHERE id=?", input.ResourceID).Scan(&kind, &destination, &siteID); err != nil {
		return errors.New("resource publication references an unavailable resource")
	}
	if err := tx.QueryRowContext(ctx, `
SELECT l.site_id,v.resource_alias_pool FROM management_links AS l JOIN vps_nodes AS v ON v.id=l.vps_id WHERE l.id=?`, input.LinkID).Scan(&linkSiteID, &pool); err != nil || linkSiteID != siteID {
		return errors.New("resource publication must use a link from the resource site")
	}
	local, err := parseResourceDestination(kind, destination)
	if err != nil {
		return err
	}
	alias, err := canonicalPrivatePrefix(input.PublishedAlias, 8, 32)
	if err != nil || (kind == ResourceLocalSubnet && alias.Bits() != local.Bits()) || (kind != ResourceLocalSubnet && alias.Bits() != 32) {
		return errors.New("resource publication alias size is invalid")
	}
	aliasPool, err := canonicalPrivatePrefix(pool, 8, 30)
	if err != nil || alias.Bits() < aliasPool.Bits() || !aliasPool.Contains(alias.Addr()) {
		return errors.New("resource publication alias is outside the selected VPS alias pool")
	}
	if err := repository.rejectPublicationAliasCollisionsTx(ctx, tx, alias, excludedID); err != nil {
		return err
	}
	return nil
}

func (repository *Repository) rejectPublicationAliasCollisionsTx(ctx context.Context, tx *sql.Tx, candidate netip.Prefix, excludedID string) error {
	for _, reserved := range repository.ReservedPrefixes {
		prefix, err := canonicalPrefix(reserved.CIDR)
		if err != nil || candidate.Overlaps(prefix) {
			return fmt.Errorf("resource alias overlaps reserved prefix %s", reserved.Owner)
		}
	}
	queries := []struct {
		query string
		args  []any
	}{
		{"SELECT published_alias FROM management_resource_publications WHERE id<>?", []any{excludedID}},
		{"SELECT management_subnet FROM management_links", nil},
		{"SELECT admin_address_pool FROM vps_nodes", nil},
		{"SELECT subnet FROM management_admin_contour", nil},
		{"SELECT subnet_cidr FROM wireguard_ingress_servers", nil},
		{"SELECT ipv4_cidr FROM uplinks WHERE ipv4_cidr IS NOT NULL AND ipv4_cidr<>''", nil},
		{"SELECT configured_ipv4_cidr FROM uplinks WHERE configured_ipv4_cidr IS NOT NULL AND configured_ipv4_cidr<>''", nil},
		{"SELECT CASE WHEN resource_kind='LOCAL_SUBNET' THEN local_destination ELSE local_destination||'/32' END FROM management_resources", nil},
	}
	for _, item := range queries {
		rows, err := tx.QueryContext(ctx, item.query, item.args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			prefix, err := canonicalPrefix(raw)
			if err != nil || candidate.Overlaps(prefix) {
				rows.Close()
				return errors.New("resource publication alias overlaps an existing route or address scope")
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func validateACLIdentity(input ResourceACLInput) error {
	if !safeIdentifier.MatchString(input.ID) || !safeIdentifier.MatchString(input.AdminID) || !safeIdentifier.MatchString(input.ResourceID) {
		return errors.New("resource ACL identifiers are invalid")
	}
	return validateProtocolPorts(input.Protocol, input.PortStart, input.PortEnd)
}

func (repository *Repository) validateACLTx(ctx context.Context, tx *sql.Tx, input ResourceACLInput) error {
	var adminExists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_admins WHERE id=? AND state!='REVOKED'", input.AdminID).Scan(&adminExists); err != nil || adminExists != 1 {
		return errors.New("resource ACL administrator is unavailable")
	}
	ports, err := listResourcePorts(ctx, tx, input.ResourceID)
	if err != nil || !resourcePortsAllow(ports, input.Protocol, input.PortStart, input.PortEnd) {
		return errors.New("resource ACL exceeds the declared resource ports")
	}
	if input.Enabled {
		var available int
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM management_admin_vps_peers AS ap
JOIN management_links AS l ON l.vps_id=ap.vps_id
JOIN management_resource_publications AS p ON p.link_id=l.id AND p.resource_id=?
WHERE ap.admin_id=? AND ap.state IN ('CONFIGURED','ACTIVE') AND p.state!='DISABLED'`, input.ResourceID, input.AdminID).Scan(&available); err != nil || available == 0 {
			return errors.New("enabled resource ACL requires a publication on an administrator VPS")
		}
	}
	return nil
}

func (repository *Repository) interfaceNamesForRoles(ctx context.Context, roles []string, dedicatedOnly bool) ([]string, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(roles)), ",")
	args := make([]any, len(roles))
	for index := range roles {
		args[index] = roles[index]
	}
	query := `
SELECT DISTINCT n.current_ifname
FROM network_interfaces AS n
JOIN interface_role_assignments AS r ON r.network_interface_id=n.id
WHERE n.current_ifname IS NOT NULL AND n.current_ifname<>'' AND r.state='ACTIVE'
  AND r.role IN (` + placeholders + `)`
	if dedicatedOnly {
		query += ` AND NOT EXISTS (
SELECT 1 FROM interface_role_assignments AS x
WHERE x.network_interface_id=n.id AND x.role IN ('ETHERNET_UPLINK','HILINK_UPLINK'))`
	}
	rows, err := repository.Database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if validLinuxInterface(name) {
			result = append(result, name)
		}
	}
	return result, rows.Err()
}

func (repository *Repository) wireGuardResourcePrefix(ctx context.Context, resource Resource) (string, error) {
	target, err := parseResourceDestination(resource.Kind, resource.LocalDestination)
	if err != nil {
		return "", err
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT r.cidr
FROM wireguard_ingress_peer_routes AS r
JOIN wireguard_ingress_peers AS p ON p.id=r.peer_id
JOIN wireguard_ingress_servers AS s ON s.id=p.server_id
WHERE s.enabled=1 AND s.interface_name='wg-ingress' AND p.enabled=1 AND p.revoked_at IS NULL
  AND p.peer_kind='ROUTER_ROUTED' AND r.direction='INGRESS'`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var match string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return "", err
		}
		prefix, err := canonicalPrivatePrefix(raw, 8, 32)
		if err == nil && prefixContainsPrefix(prefix, target) {
			if match != "" {
				return "", errors.New("multiple ROUTER_ROUTED peers claim the management resource")
			}
			match = prefix.String()
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if match == "" {
		return "", errors.New("no enabled ROUTER_ROUTED peer contains the management resource")
	}
	return match, nil
}

func prefixContainsPrefix(parent, child netip.Prefix) bool {
	return parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}

func scanResource(scanner rowScanner) (Resource, error) {
	var item Resource
	var enabled, acknowledged int
	if err := scanner.Scan(&item.ID, &item.SiteID, &item.Name, &item.Kind, &item.AccessProfile,
		&item.LocalDestination, &enabled, &acknowledged, &item.DesiredRouteGeneration,
		&item.AppliedRouteGeneration, &item.HealthState, &item.HealthReasonCode, &item.LastProbeAt,
		&item.LastProbeRouteGeneration, &item.ProbeInterface, &item.ProbeGateway,
		&item.HealthProbeAddress, &item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Resource{}, store.ErrNotFound
		}
		return Resource{}, err
	}
	item.Enabled, item.AdvancedScopeAcknowledged = enabled != 0, acknowledged != 0
	return item, nil
}

func scanResourcePublication(scanner rowScanner) (ResourcePublication, error) {
	var item ResourcePublication
	if err := scanner.Scan(&item.ID, &item.ResourceID, &item.LinkID, &item.PublishedAlias,
		&item.DesiredRouteGeneration, &item.AppliedRouteGeneration, &item.DesiredACLGeneration,
		&item.AppliedACLGeneration, &item.State, &item.LastErrorCode, &item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ResourcePublication{}, store.ErrNotFound
		}
		return ResourcePublication{}, err
	}
	item.Enabled = item.State != "DISABLED"
	return item, nil
}

func scanResourceACL(scanner rowScanner) (ResourceACL, error) {
	var item ResourceACL
	var enabled int
	if err := scanner.Scan(&item.ID, &item.AdminID, &item.ResourceID, &item.Protocol,
		&item.PortStart, &item.PortEnd, &enabled, &item.Generation, &item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ResourceACL{}, store.ErrNotFound
		}
		return ResourceACL{}, err
	}
	item.Enabled = enabled != 0
	return item, nil
}
