// Package webapi exposes the authenticated Gateway VPN API and embedded UI.
package webapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	runtimepkg "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/directprobe"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/hostboot"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/modemrecovery"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/power"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/removal"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/traffic"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/updateautomation"
	"gateway-vpn/internal/updateremote"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/watchdog"
	"gateway-vpn/internal/wgingress"
	wireguardpkg "gateway-vpn/internal/wireguard"
	qrcode "github.com/skip2/go-qrcode"
)

const sessionCookieName = "gateway_vpn_session"

//go:embed static/*
var staticFiles embed.FS

type Dependencies struct {
	Database                *sql.DB
	Auth                    auth.Service
	State                   *state.Repository
	Modems                  *modem.Repository
	Uplinks                 *uplink.Repository
	Discoveries             *hilink.DiscoveryRegistry
	WireGuardRuntime        *wireguardpkg.RuntimeStore
	WireGuardConfigPath     string
	WireGuardSync           WireGuardSynchronizer
	WireGuardIngress        *wgingress.Repository
	WireGuardIngressAdmin   WireGuardIngressController
	ManagementFabric        *managementfabric.Repository
	ManagementFabricAdmin   ManagementFabricController
	ModemRuntime            ModemRuntime
	ModemRecovery           ModemRecoveryController
	ModemReconcile          func(context.Context) (hilink.CycleResult, error)
	ModemPathProbe          ModemPathProber
	DirectPathProbe         DirectPathProber
	PathOperations          PathOperator
	PathActivator           ManualPathActivator
	Subscriptions           *subscription.Repository
	Nodes                   *subscription.NodeRepository
	Paths                   *pathmatrix.Repository
	Targets                 *bypass.Repository
	Matchers                *subscription.MatcherRepository
	SubscriptionRefresh     SubscriptionRefresher
	SubscriptionDispatch    SubscriptionRefreshDispatcher
	AccessPolicy            *accesspolicy.Repository
	DirectPaths             *accesspolicy.DirectPathRepository
	NodePreferences         *accesspolicy.PreferenceRepository
	Operations              *operations.Repository
	BootIDReader            func() (string, error)
	SubscriptionSecretRoot  string
	SubscriptionPayloadRoot string
	NetworkBroker           NetworkBroker
	NetworkCandidate        func(context.Context, string) (networkapply.Candidate, error)
	NetworkInterface        string
	NetworkLANAddress       string
	Reconcile               func(context.Context) (any, error)
	PeriodicHealth          *health.PeriodicRepository
	PeriodicHealthConfig    candidateruntime.PeriodicConfig
	ProbeBudget             ProbeBudgetReader
	Logging                 *loggingpkg.Controller
	LoggingSync             LoggingSynchronizer
	Journal                 JournalReader
	Diagnostics             DiagnosticBundler
	Backups                 SnapshotManager
	PortableBackups         PortableBackupManager
	Restores                RestoreStager
	RestoreApply            RestoreApplyTrigger
	Updates                 UpdateStager
	RemoteUpdates           RemoteUpdateSource
	UpdateApply             UpdateApplyTrigger
	UpdatePolicy            *updatepkg.AutomationPolicyRepository
	UpdateAutomation        UpdateAutomationStatusReader
	UpdateRestorePoints     UpdateRestorePointController
	Watchdog                *watchdog.Repository
	WatchdogStatus          WatchdogStatusReader
	Power                   PowerController
	Removal                 RemovalController
	Now                     func() time.Time
}

type WatchdogStatusReader interface {
	Read() (watchdog.Status, error)
}

type PowerController interface {
	PowerCapabilities(context.Context) (power.Capabilities, error)
	ExecutePower(context.Context, power.Command) error
}

type RemovalController interface {
	UninstallImpact(context.Context) (removal.Impact, error)
	DispatchUninstall(context.Context, removal.Request) error
}

type ProbeBudgetReader interface {
	Snapshot(string) scheduler.ModemUsage
	Limits() scheduler.Limits
}

type LoggingSynchronizer interface {
	SyncLogging(context.Context) error
}

type JournalReader interface {
	QueryLogs(context.Context, loggingpkg.JournalQuery) (loggingpkg.JournalPage, error)
}

type DiagnosticBundler interface {
	Describe(context.Context) (diagnostics.Description, error)
	Build(context.Context) (diagnostics.Bundle, error)
}

type SnapshotManager interface {
	Inventory(context.Context) ([]backup.InventoryItem, error)
	Create(context.Context, backup.Kind) (backup.Snapshot, error)
}

type PortableBackupManager interface {
	Build(context.Context, string) (backup.PortableArtifact, error)
	Open(backup.PortableArtifact) (io.ReadCloser, error)
	Remove(backup.PortableArtifact) error
}

type RestoreStager interface {
	Stage(context.Context, io.Reader, string) (backup.RestoreOperation, error)
	Status() (backup.RestoreOperation, bool, error)
	AuthorizeApply(string) (backup.RestoreOperation, error)
	Discard(context.Context, string) error
}

type RestoreApplyTrigger interface {
	ApplyPendingRestore(context.Context) error
}

type UpdateStager interface {
	Stage(context.Context, io.Reader) (updatepkg.Operation, error)
	Status() (updatepkg.Operation, bool, error)
	Discard(context.Context, string) error
}

type UpdateApplyTrigger interface {
	ApplyPendingUpdate(context.Context) error
	UpdateStatus(context.Context) (networkapply.UpdateTransactionStatus, error)
}

type UpdateAutomationStatusReader interface {
	Status(context.Context) (updateautomation.Status, error)
}

type UpdateRestorePointController interface {
	RestorePointInventory(context.Context) ([]updatepkg.RestorePoint, error)
	DeleteRestorePoint(context.Context, string) error
	PruneRestorePoints(context.Context, updatepkg.RestorePointPolicy) ([]string, error)
	RollbackToRestorePoint(context.Context, string) error
}

type RemoteUpdateSource interface {
	Check(context.Context, string) (updateremote.Available, error)
	CheckMihomo(context.Context, string) (updateremote.MihomoAvailable, error)
	StageChannel(context.Context, string) (updatepkg.Operation, error)
	StageMihomoChannel(context.Context, string) (updatepkg.Operation, error)
	StageExact(context.Context, string) (updatepkg.Operation, error)
}

type NetworkBroker interface {
	Stage(context.Context, networkapply.Candidate) (networkapply.Prepared, error)
	Apply(context.Context, string) error
	Confirm(context.Context, string, networkapply.ConfirmEvidence) error
}

type TopologyNetworkBroker interface {
	PreviewTopology(context.Context, networkapply.Candidate) (networkapply.TopologyPreview, error)
}

type SubscriptionRefresher interface {
	RefreshOne(context.Context, string, bool) (subscription.RefreshResult, error)
	ReclassifyOne(context.Context, string) (subscription.RefreshResult, error)
}

type SubscriptionRefreshDispatcher interface {
	Enqueue(context.Context, string, string) (subscription.DispatchResult, error)
}

type WireGuardSynchronizer interface {
	SyncWireGuard(context.Context) error
}

type WireGuardIngressController interface {
	SyncWireGuardIngress(context.Context) error
	UpdateWireGuardIngressServer(context.Context, wgingress.ServerUpdate) (wgingress.Server, error)
	RotateWireGuardIngressServer(context.Context) (wgingress.Server, error)
	CreateWireGuardIngressPeer(context.Context, wgingress.PeerCreate) (wgingress.Peer, error)
	UpdateWireGuardIngressPeer(context.Context, string, wgingress.PeerUpdate) (wgingress.Peer, error)
	RevokeWireGuardIngressPeer(context.Context, string) (wgingress.Peer, error)
	DeleteWireGuardIngressPeer(context.Context, string) error
	RotateWireGuardIngressPeer(context.Context, string) (wgingress.Peer, error)
	ProbeWireGuardIngressPeer(context.Context, string) (wgingress.Peer, error)
	ExportWireGuardIngressPeer(context.Context, string) (wgingress.ExportedConfig, error)
}

type ManagementFabricController interface {
	SyncManagementFabric(context.Context) error
	ManagementFabricStatus(context.Context) (networkapply.ManagementFabricStatus, error)
	ProbeManagementResource(context.Context, string) (managementfabric.ResourceProbeResult, error)
	ConfigureAdminContour(context.Context, managementfabric.AdminContourRequest) (managementfabric.AdminContour, error)
	RotateAdminContourIdentity(context.Context) (managementfabric.AdminContour, error)
}

type ModemRuntime interface {
	BlockPath(context.Context) error
	SyncRouting(context.Context) error
	SyncWireGuard(context.Context) error
}

type ModemRecoveryController interface {
	Request(context.Context, string, string) (modemrecovery.Result, error)
	Snapshot(context.Context, string, int) (modemrecovery.Snapshot, error)
	UpdatePolicy(context.Context, string, modemrecovery.PolicyUpdate) (modemrecovery.Policy, error)
}

type ModemPathProber interface {
	RequalifyModem(context.Context, string) (candidateruntime.RequalificationResult, error)
}

type DirectPathProber interface {
	ProbeAllNow(context.Context) (directprobe.CycleResult, error)
}

type PathOperator interface {
	ProbeNode(context.Context, string, string) (candidateruntime.PathOperationResult, error)
	QualifyNode(context.Context, string, string) (candidateruntime.PathOperationResult, error)
	QualifyPath(context.Context, string) (candidateruntime.PathOperationResult, error)
}

type ManualPathActivator interface {
	ActivateExact(context.Context, string, string) (reconcile.Result, error)
}

type Server struct {
	dependencies          Dependencies
	handler               http.Handler
	startedAt             time.Time
	matcherPreviewSecret  []byte
	journalLimiter        *journalRateLimiter
	metricsLimiter        *journalRateLimiter
	diagnosticLimiter     *diagnosticRateLimiter
	snapshotLimiter       *diagnosticRateLimiter
	portableBackupLimiter *diagnosticRateLimiter
	updateLimiter         *diagnosticRateLimiter
	maintenanceMutex      sync.Mutex
	maintenanceMutations  int
	powerPending          bool
	secretGrantMutex      sync.Mutex
	secretGrants          map[string]secretExportGrant
}

type secretExportGrant struct {
	PeerID      string
	SessionHash string
	ExpiresAt   time.Time
}

type contextKey string

const principalKey contextKey = "principal"

func New(dependencies Dependencies) (*Server, error) {
	if dependencies.Database == nil || dependencies.Auth.Database == nil || dependencies.State == nil || dependencies.Modems == nil || dependencies.Subscriptions == nil || dependencies.Nodes == nil || dependencies.Paths == nil || dependencies.Targets == nil || dependencies.Matchers == nil {
		return nil, errors.New("complete Web API dependencies are required")
	}
	if dependencies.AccessPolicy == nil {
		dependencies.AccessPolicy = accesspolicy.NewRepository(dependencies.Database)
	}
	if dependencies.DirectPaths == nil {
		dependencies.DirectPaths = accesspolicy.NewDirectPathRepository(dependencies.Database)
	}
	if dependencies.NodePreferences == nil {
		dependencies.NodePreferences = accesspolicy.NewPreferenceRepository(dependencies.Database)
	}
	if dependencies.Operations == nil {
		dependencies.Operations = operations.NewRepository(dependencies.Database)
	}
	if dependencies.UpdatePolicy == nil {
		dependencies.UpdatePolicy = &updatepkg.AutomationPolicyRepository{Database: dependencies.Database}
	}
	if dependencies.BootIDReader == nil {
		dependencies.BootIDReader = func() (string, error) { return hostboot.Read("") }
	}
	previewSecret := make([]byte, 32)
	if _, err := rand.Read(previewSecret); err != nil {
		return nil, errors.New("initialize matcher preview protection failed")
	}
	startedAt := time.Now().UTC()
	if dependencies.Now != nil {
		startedAt = dependencies.Now().UTC()
	}
	server := &Server{dependencies: dependencies, startedAt: startedAt, matcherPreviewSecret: previewSecret, journalLimiter: newJournalRateLimiter(), metricsLimiter: newJournalRateLimiter(), diagnosticLimiter: newDiagnosticRateLimiter(), snapshotLimiter: newDiagnosticRateLimiter(), portableBackupLimiter: newDiagnosticRateLimiter(), updateLimiter: newDiagnosticRateLimiter(), secretGrants: make(map[string]secretExportGrant)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", server.login)
	mux.Handle("POST /api/v1/auth/logout", server.protected(http.HandlerFunc(server.logout)))
	mux.Handle("GET /api/v1/auth/session", server.protected(http.HandlerFunc(server.session)))
	mux.Handle("PUT /api/v1/auth/password", server.protected(http.HandlerFunc(server.changePassword)))
	mux.Handle("GET /api/v1/auth/users", server.protected(http.HandlerFunc(server.users)))
	mux.Handle("POST /api/v1/auth/users", server.protected(http.HandlerFunc(server.createUser)))
	mux.Handle("PATCH /api/v1/auth/users/{id}", server.protected(http.HandlerFunc(server.updateUser)))
	mux.Handle("DELETE /api/v1/auth/users/{id}", server.protected(http.HandlerFunc(server.deleteUser)))
	mux.Handle("PUT /api/v1/auth/users/{id}/password", server.protected(http.HandlerFunc(server.resetUserPassword)))
	mux.Handle("GET /api/v1/auth/sessions", server.protected(http.HandlerFunc(server.sessions)))
	mux.Handle("DELETE /api/v1/auth/sessions/{id}", server.protected(http.HandlerFunc(server.revokeSession)))
	mux.Handle("GET /api/v1/gateway/status", server.protected(http.HandlerFunc(server.gatewayStatus)))
	mux.Handle("GET /api/v1/gateway/diagnostics", server.protected(http.HandlerFunc(server.diagnosticDescription)))
	mux.Handle("GET /api/v1/system/runtime-metrics", server.protected(http.HandlerFunc(server.runtimeMetrics)))
	mux.Handle("GET /api/v1/wireguard/status", server.protected(http.HandlerFunc(server.wireGuardStatus)))
	mux.Handle("GET /api/v1/management-fabric", server.protected(http.HandlerFunc(server.managementFabricDashboard)))
	mux.Handle("PUT /api/v1/management-fabric/vps/priorities", server.protected(http.HandlerFunc(server.reorderManagementVPS)))
	mux.Handle("PATCH /api/v1/management-fabric/vps/{id}", server.protected(http.HandlerFunc(server.updateManagementVPS)))
	mux.Handle("PATCH /api/v1/management-fabric/links/{id}", server.protected(http.HandlerFunc(server.updateManagementLink)))
	mux.Handle("PUT /api/v1/management-fabric/admin-contour", server.protected(http.HandlerFunc(server.configureManagementAdminContour)))
	mux.Handle("POST /api/v1/management-fabric/admin-contour/rotate", server.protected(http.HandlerFunc(server.rotateManagementAdminContour)))
	mux.Handle("POST /api/v1/management-fabric/admin-relays", server.protected(http.HandlerFunc(server.createManagementAdminRelay)))
	mux.Handle("PUT /api/v1/management-fabric/admin-relays/{id}", server.protected(http.HandlerFunc(server.updateManagementAdminRelay)))
	mux.Handle("DELETE /api/v1/management-fabric/admin-relays/{id}", server.protected(http.HandlerFunc(server.deleteManagementAdminRelay)))
	mux.Handle("POST /api/v1/management-fabric/admin-tunnels", server.protected(http.HandlerFunc(server.createManagementAdminTunnel)))
	mux.Handle("POST /api/v1/management-fabric/admin-tunnels/{id}/revoke", server.protected(http.HandlerFunc(server.revokeManagementAdminTunnel)))
	mux.Handle("DELETE /api/v1/management-fabric/admin-tunnels/{id}", server.protected(http.HandlerFunc(server.deleteManagementAdminTunnel)))
	mux.Handle("PUT /api/v1/management-fabric/admins/{admin_id}/vps/{vps_id}/trust-mode", server.protected(http.HandlerFunc(server.updateManagementAdminTrustMode)))
	mux.Handle("POST /api/v1/management-fabric/sync", server.protected(http.HandlerFunc(server.syncManagementFabric)))
	mux.Handle("POST /api/v1/management-fabric/resources", server.protected(http.HandlerFunc(server.createManagementResource)))
	mux.Handle("PUT /api/v1/management-fabric/resources/{id}", server.protected(http.HandlerFunc(server.updateManagementResource)))
	mux.Handle("DELETE /api/v1/management-fabric/resources/{id}", server.protected(http.HandlerFunc(server.deleteManagementResource)))
	mux.Handle("POST /api/v1/management-fabric/resources/{id}/probe", server.protected(http.HandlerFunc(server.probeManagementResource)))
	mux.Handle("POST /api/v1/management-fabric/publications", server.protected(http.HandlerFunc(server.createManagementResourcePublication)))
	mux.Handle("PUT /api/v1/management-fabric/publications/{id}", server.protected(http.HandlerFunc(server.updateManagementResourcePublication)))
	mux.Handle("DELETE /api/v1/management-fabric/publications/{id}", server.protected(http.HandlerFunc(server.deleteManagementResourcePublication)))
	mux.Handle("POST /api/v1/management-fabric/acl", server.protected(http.HandlerFunc(server.createManagementResourceACL)))
	mux.Handle("PUT /api/v1/management-fabric/acl/{id}", server.protected(http.HandlerFunc(server.updateManagementResourceACL)))
	mux.Handle("DELETE /api/v1/management-fabric/acl/{id}", server.protected(http.HandlerFunc(server.deleteManagementResourceACL)))
	mux.Handle("GET /api/v1/settings/wireguard", server.protected(http.HandlerFunc(server.wireGuardSettings)))
	mux.Handle("PUT /api/v1/settings/wireguard", server.protected(http.HandlerFunc(server.updateWireGuardSettings)))
	mux.Handle("GET /api/v1/wireguard-ingress", server.protected(http.HandlerFunc(server.wireGuardIngressServer)))
	mux.Handle("PUT /api/v1/wireguard-ingress", server.protected(http.HandlerFunc(server.updateWireGuardIngressServer)))
	mux.Handle("POST /api/v1/wireguard-ingress/rotate", server.protected(http.HandlerFunc(server.rotateWireGuardIngressServer)))
	mux.Handle("GET /api/v1/wireguard-ingress/peers", server.protected(http.HandlerFunc(server.wireGuardIngressPeers)))
	mux.Handle("POST /api/v1/wireguard-ingress/peers", server.protected(http.HandlerFunc(server.createWireGuardIngressPeer)))
	mux.Handle("PATCH /api/v1/wireguard-ingress/peers/{id}", server.protected(http.HandlerFunc(server.updateWireGuardIngressPeer)))
	mux.Handle("DELETE /api/v1/wireguard-ingress/peers/{id}", server.protected(http.HandlerFunc(server.deleteWireGuardIngressPeer)))
	mux.Handle("POST /api/v1/wireguard-ingress/peers/{id}/revoke", server.protected(http.HandlerFunc(server.revokeWireGuardIngressPeer)))
	mux.Handle("POST /api/v1/wireguard-ingress/peers/{id}/rotate", server.protected(http.HandlerFunc(server.rotateWireGuardIngressPeer)))
	mux.Handle("POST /api/v1/wireguard-ingress/peers/{id}/probe", server.protected(http.HandlerFunc(server.probeWireGuardIngressPeer)))
	mux.Handle("POST /api/v1/wireguard-ingress/peers/{id}/reauth", server.protected(http.HandlerFunc(server.reauthWireGuardIngressPeer)))
	mux.Handle("GET /api/v1/wireguard-ingress/peers/{id}/config", server.protected(http.HandlerFunc(server.wireGuardIngressPeerConfig)))
	mux.Handle("GET /api/v1/wireguard-ingress/peers/{id}/qrcode", server.protected(http.HandlerFunc(server.wireGuardIngressPeerQRCode)))
	mux.Handle("POST /api/v1/gateway/reconcile", server.protected(http.HandlerFunc(server.reconcile)))
	mux.Handle("GET /api/v1/access-methods", server.protected(http.HandlerFunc(server.accessMethods)))
	mux.Handle("PUT /api/v1/access-methods/priorities", server.protected(http.HandlerFunc(server.reorderAccessMethods)))
	mux.Handle("PATCH /api/v1/access-methods/{id}", server.protected(http.HandlerFunc(server.updateAccessMethod)))
	mux.Handle("POST /api/v1/access-methods/direct-only", server.protected(http.HandlerFunc(server.enableTemporaryDirectOnly)))
	mux.Handle("DELETE /api/v1/access-methods/direct-only", server.protected(http.HandlerFunc(server.disableTemporaryDirectOnly)))
	mux.Handle("GET /api/v1/settings/access-policy", server.protected(http.HandlerFunc(server.accessPolicySettings)))
	mux.Handle("PUT /api/v1/settings/access-policy", server.protected(http.HandlerFunc(server.updateAccessPolicySettings)))
	mux.Handle("GET /api/v1/uplinks", server.protected(http.HandlerFunc(server.uplinks)))
	mux.Handle("PUT /api/v1/uplinks/priorities", server.protected(http.HandlerFunc(server.reorderUplinks)))
	mux.Handle("POST /api/v1/uplinks/ethernet", server.protected(http.HandlerFunc(server.createEthernetUplink)))
	mux.Handle("GET /api/v1/uplinks/{id}/impact", server.protected(http.HandlerFunc(server.uplinkImpact)))
	mux.Handle("POST /api/v1/uplinks/{id}/enable", server.protected(http.HandlerFunc(server.enableEthernetUplink)))
	mux.Handle("POST /api/v1/uplinks/{id}/disable", server.protected(http.HandlerFunc(server.disableEthernetUplink)))
	mux.Handle("POST /api/v1/uplinks/{id}/replace-interface", server.protected(http.HandlerFunc(server.replaceEthernetInterface)))
	mux.Handle("PUT /api/v1/uplinks/{id}/network", server.protected(http.HandlerFunc(server.updateEthernetNetwork)))
	mux.Handle("DELETE /api/v1/uplinks/{id}", server.protected(http.HandlerFunc(server.deleteEthernetUplink)))
	mux.Handle("GET /api/v1/network/interfaces", server.protected(http.HandlerFunc(server.networkInterfaces)))
	mux.Handle("GET /api/v1/network/topology", server.protected(http.HandlerFunc(server.networkTopology)))
	mux.Handle("POST /api/v1/network/topology/preview", server.protected(http.HandlerFunc(server.previewNetworkTopology)))
	mux.Handle("POST /api/v1/network/topology/apply", server.protected(http.HandlerFunc(server.applyNetworkTopology)))
	mux.Handle("GET /api/v1/modems", server.protected(http.HandlerFunc(server.modems)))
	mux.Handle("PUT /api/v1/modems/priorities", server.protected(http.HandlerFunc(server.reorderModems)))
	mux.Handle("PATCH /api/v1/modems/{id}", server.protected(http.HandlerFunc(server.updateModem)))
	mux.Handle("POST /api/v1/modems/{id}/enable", server.protected(http.HandlerFunc(server.enableModem)))
	mux.Handle("POST /api/v1/modems/{id}/disable", server.protected(http.HandlerFunc(server.disableModem)))
	mux.Handle("POST /api/v1/modems/{id}/probe", server.protected(http.HandlerFunc(server.probeModem)))
	mux.Handle("POST /api/v1/modems/{id}/recover", server.protected(http.HandlerFunc(server.recoverModem)))
	mux.Handle("GET /api/v1/modems/{id}/recovery", server.protected(http.HandlerFunc(server.modemRecovery)))
	mux.Handle("PUT /api/v1/modems/{id}/recovery", server.protected(http.HandlerFunc(server.updateModemRecovery)))
	mux.Handle("POST /api/v1/modems/{id}/replace-identity", server.protected(http.HandlerFunc(server.replaceModemIdentity)))
	mux.Handle("DELETE /api/v1/modems/{id}", server.protected(http.HandlerFunc(server.forgetModem)))
	mux.Handle("GET /api/v1/modems/discovered", server.protected(http.HandlerFunc(server.discoveredModems)))
	mux.Handle("POST /api/v1/modems/{discovery_id}/adopt", server.protected(http.HandlerFunc(server.adoptModem)))
	mux.Handle("GET /api/v1/subscriptions", server.protected(http.HandlerFunc(server.subscriptions)))
	mux.Handle("POST /api/v1/subscriptions", server.protected(http.HandlerFunc(server.createSubscription)))
	mux.Handle("PUT /api/v1/subscriptions/priorities", server.protected(http.HandlerFunc(server.reorderSubscriptions)))
	mux.Handle("PATCH /api/v1/subscriptions/{id}", server.protected(http.HandlerFunc(server.updateSubscription)))
	mux.Handle("POST /api/v1/subscriptions/{id}/enable", server.protected(http.HandlerFunc(server.enableSubscription)))
	mux.Handle("POST /api/v1/subscriptions/{id}/disable", server.protected(http.HandlerFunc(server.disableSubscription)))
	mux.Handle("DELETE /api/v1/subscriptions/{id}", server.protected(http.HandlerFunc(server.deleteSubscription)))
	mux.Handle("POST /api/v1/subscriptions/{id}/refresh", server.protected(http.HandlerFunc(server.refreshSubscription)))
	mux.Handle("POST /api/v1/subscriptions/refresh", server.protected(http.HandlerFunc(server.refreshSubscriptions)))
	mux.Handle("GET /api/v1/nodes", server.protected(http.HandlerFunc(server.nodes)))
	mux.Handle("PATCH /api/v1/nodes/{id}", server.protected(http.HandlerFunc(server.updateNode)))
	mux.Handle("PUT /api/v1/subscriptions/{id}/nodes/priorities", server.protected(http.HandlerFunc(server.reorderPreferredNodes)))
	mux.Handle("GET /api/v1/paths/matrix", server.protected(http.HandlerFunc(server.matrix)))
	mux.Handle("GET /api/v1/paths/{id}/nodes", server.protected(http.HandlerFunc(server.pathNodes)))
	mux.Handle("POST /api/v1/paths/{id}/qualify", server.protected(http.HandlerFunc(server.qualifyPath)))
	mux.Handle("POST /api/v1/paths/{id}/activate", server.protected(http.HandlerFunc(server.activatePath)))
	mux.Handle("POST /api/v1/paths/{id}/nodes/{node_id}/probe", server.protected(http.HandlerFunc(server.probePathNode)))
	mux.Handle("POST /api/v1/paths/{id}/nodes/{node_id}/qualify", server.protected(http.HandlerFunc(server.qualifyPathNode)))
	mux.Handle("GET /api/v1/paths/{id}/nodes/{node_id}/targets", server.protected(http.HandlerFunc(server.pathNodeTargets)))
	mux.Handle("GET /api/v1/bypass-targets", server.protected(http.HandlerFunc(server.targets)))
	mux.Handle("POST /api/v1/bypass-targets", server.protected(http.HandlerFunc(server.createTarget)))
	mux.Handle("PUT /api/v1/bypass-targets/priorities", server.protected(http.HandlerFunc(server.reorderTargets)))
	mux.Handle("PATCH /api/v1/bypass-targets/{id}", server.protected(http.HandlerFunc(server.updateTarget)))
	mux.Handle("DELETE /api/v1/bypass-targets/{id}", server.protected(http.HandlerFunc(server.deleteTarget)))
	mux.Handle("POST /api/v1/bypass-targets/{id}/probe", server.protected(http.HandlerFunc(server.probeTarget)))
	mux.Handle("GET /api/v1/node-matchers", server.protected(http.HandlerFunc(server.matchers)))
	mux.Handle("POST /api/v1/node-matchers", server.protected(http.HandlerFunc(server.createMatcher)))
	mux.Handle("PUT /api/v1/node-matchers/priorities", server.protected(http.HandlerFunc(server.reorderMatchers)))
	mux.Handle("PATCH /api/v1/node-matchers/{id}", server.protected(http.HandlerFunc(server.updateMatcher)))
	mux.Handle("DELETE /api/v1/node-matchers/{id}", server.protected(http.HandlerFunc(server.deleteMatcher)))
	mux.Handle("POST /api/v1/node-matchers/preview", server.protected(http.HandlerFunc(server.previewMatcher)))
	mux.Handle("GET /api/v1/events", server.protected(http.HandlerFunc(server.events)))
	mux.Handle("GET /api/v1/operations", server.protected(http.HandlerFunc(server.operations)))
	mux.Handle("GET /api/v1/operations/{id}", server.protected(http.HandlerFunc(server.operation)))
	mux.Handle("DELETE /api/v1/operations/completed", server.protected(http.HandlerFunc(server.clearCompletedOperations)))
	mux.Handle("GET /api/v1/health/periodic", server.protected(http.HandlerFunc(server.periodicHealth)))
	mux.Handle("GET /api/v1/settings/logging", server.protected(http.HandlerFunc(server.loggingSettings)))
	mux.Handle("PUT /api/v1/settings/logging", server.protected(http.HandlerFunc(server.updateLoggingSettings)))
	mux.Handle("GET /api/v1/settings/watchdog", server.protected(http.HandlerFunc(server.watchdogSettings)))
	mux.Handle("PUT /api/v1/settings/watchdog", server.protected(http.HandlerFunc(server.updateWatchdogSettings)))
	mux.Handle("GET /api/v1/system/watchdog", server.protected(http.HandlerFunc(server.watchdogStatus)))
	mux.Handle("GET /api/v1/system/power/capabilities", server.protected(http.HandlerFunc(server.systemPowerCapabilities)))
	mux.Handle("POST /api/v1/system/reboot", server.protected(http.HandlerFunc(server.rebootSystem)))
	mux.Handle("POST /api/v1/system/shutdown", server.protected(http.HandlerFunc(server.shutdownSystem)))
	mux.Handle("POST /api/v1/system/power-cycle", server.protected(http.HandlerFunc(server.powerCycleSystem)))
	mux.Handle("GET /api/v1/system/uninstall/impact", server.protected(http.HandlerFunc(server.uninstallImpact)))
	mux.Handle("POST /api/v1/system/uninstall", server.protected(http.HandlerFunc(server.uninstallSystem)))
	mux.Handle("GET /api/v1/logs", server.protected(http.HandlerFunc(server.logs)))
	mux.Handle("POST /api/v1/system/diagnostics", server.protected(http.HandlerFunc(server.downloadDiagnostics)))
	mux.Handle("GET /api/v1/system/backups", server.protected(http.HandlerFunc(server.backupInventory)))
	mux.Handle("POST /api/v1/system/backups/snapshot", server.protected(http.HandlerFunc(server.createDatabaseSnapshot)))
	mux.Handle("POST /api/v1/system/backup", server.protected(http.HandlerFunc(server.downloadEncryptedBackup)))
	mux.Handle("GET /api/v1/system/restore", server.protected(http.HandlerFunc(server.restoreStatus)))
	mux.Handle("POST /api/v1/system/restore", server.protected(http.HandlerFunc(server.stageRestore)))
	mux.Handle("DELETE /api/v1/system/restore", server.protected(http.HandlerFunc(server.discardRestore)))
	mux.Handle("POST /api/v1/system/restore/apply", server.protected(http.HandlerFunc(server.applyRestore)))
	mux.Handle("GET /api/v1/system/update", server.protected(http.HandlerFunc(server.updateStatus)))
	mux.Handle("POST /api/v1/system/update", server.protected(http.HandlerFunc(server.stageUpdate)))
	mux.Handle("DELETE /api/v1/system/update", server.protected(http.HandlerFunc(server.discardUpdate)))
	mux.Handle("POST /api/v1/system/update/apply", server.protected(http.HandlerFunc(server.applyUpdate)))
	mux.Handle("GET /api/v1/system/update/available", server.protected(http.HandlerFunc(server.availableUpdate)))
	mux.Handle("GET /api/v1/system/update/mihomo/available", server.protected(http.HandlerFunc(server.availableMihomoUpdate)))
	mux.Handle("POST /api/v1/system/update/remote", server.protected(http.HandlerFunc(server.stageRemoteUpdate)))
	mux.Handle("GET /api/v1/system/update/automation", server.protected(http.HandlerFunc(server.updateAutomationStatus)))
	mux.Handle("GET /api/v1/settings/software-update", server.protected(http.HandlerFunc(server.softwareUpdatePolicy)))
	mux.Handle("PUT /api/v1/settings/software-update", server.protected(http.HandlerFunc(server.updateSoftwareUpdatePolicy)))
	mux.Handle("GET /api/v1/system/update/restore-points", server.protected(http.HandlerFunc(server.updateRestorePoints)))
	mux.Handle("POST /api/v1/system/update/restore-points/{id}/rollback", server.protected(http.HandlerFunc(server.rollbackToUpdateRestorePoint)))
	mux.Handle("DELETE /api/v1/system/update/restore-points/{id}", server.protected(http.HandlerFunc(server.deleteUpdateRestorePoint)))
	mux.Handle("POST /api/v1/system/update/restore-points/prune", server.protected(http.HandlerFunc(server.pruneUpdateRestorePoints)))
	mux.Handle("GET /api/v1/traffic/current", server.protected(http.HandlerFunc(server.trafficCurrent)))
	mux.Handle("GET /api/v1/traffic/daily", server.protected(http.HandlerFunc(server.trafficDaily)))
	mux.Handle("GET /api/v1/traffic/monthly", server.protected(http.HandlerFunc(server.trafficMonthly)))
	mux.Handle("GET /api/v1/traffic/export.csv", server.protected(http.HandlerFunc(server.trafficCSV)))
	mux.Handle("POST /api/v1/settings/network/apply", server.protected(http.HandlerFunc(server.stageNetworkApply)))
	mux.Handle("GET /api/v1/settings/network", server.protected(http.HandlerFunc(server.networkSettings)))
	mux.Handle("GET /api/v1/settings/network/apply/{id}", server.protected(http.HandlerFunc(server.networkApplyStatus)))
	mux.Handle("POST /api/v1/settings/network/apply/{id}/confirm", server.protected(http.HandlerFunc(server.confirmNetworkApply)))
	assets, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, fmt.Errorf("prepare embedded Web UI: %w", err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	server.handler = securityHeaders(mux)
	return server, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func (server *Server) login(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	session, err := server.dependencies.Auth.Login(request.Context(), input.Username, input.Password, request.RemoteAddr+"\x00"+request.UserAgent())
	if err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			writer.Header().Set("Retry-After", "2")
			writeError(writer, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "Слишком много попыток входа")
			return
		}
		writeError(writer, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Неверное имя пользователя или пароль")
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: session.Token, Path: "/", Expires: session.ExpiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(writer, http.StatusOK, map[string]any{"user_id": session.UserID, "user": session.Username, "session_id": session.ID, "csrf_token": session.CSRFToken, "must_change_password": session.MustChangePassword, "expires_at": session.ExpiresAt.UTC().Format(time.RFC3339Nano)})
}

func (server *Server) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
			return
		}
		principal, err := server.dependencies.Auth.Authenticate(request.Context(), cookie.Value)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "SESSION_INVALID", "Сессия истекла или отозвана")
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions {
			if err := server.dependencies.Auth.ValidateCSRF(principal, request.Header.Get("X-CSRF-Token")); err != nil {
				writeError(writer, http.StatusForbidden, "CSRF_INVALID", "Недействительный CSRF-токен")
				return
			}
		}
		if principal.MustChangePassword && request.URL.Path != "/api/v1/auth/password" && request.URL.Path != "/api/v1/auth/logout" && request.URL.Path != "/api/v1/auth/session" {
			writeError(writer, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Перед продолжением необходимо заменить временный пароль")
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), principalKey, principal)))
	})
}

func (server *Server) logout(writer http.ResponseWriter, request *http.Request) {
	cookie, _ := request.Cookie(sessionCookieName)
	if cookie != nil {
		_ = server.dependencies.Auth.Revoke(request.Context(), cookie.Value)
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) session(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	csrf, err := server.dependencies.Auth.RotateCSRF(request.Context(), principal)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"user_id": principal.UserID, "user": principal.Username, "session_id": principal.SessionHash, "csrf_token": csrf, "must_change_password": principal.MustChangePassword, "expires_at": principal.ExpiresAt.UTC().Format(time.RFC3339Nano)})
}

func (server *Server) changePassword(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		CurrentPassword      string `json:"current_password"`
		NewPassword          string `json:"new_password"`
		PasswordConfirmation string `json:"password_confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if input.NewPassword != input.PasswordConfirmation {
		writeError(writer, http.StatusBadRequest, "PASSWORD_CONFIRMATION_MISMATCH", "Новый пароль и подтверждение не совпадают")
		return
	}
	if err := server.dependencies.Auth.ChangePassword(request.Context(), principal, input.CurrentPassword, input.NewPassword); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "CURRENT_PASSWORD_INVALID", "Текущий пароль указан неверно")
		case errors.Is(err, auth.ErrPasswordUnchanged):
			writeError(writer, http.StatusBadRequest, "PASSWORD_UNCHANGED", "Новый пароль должен отличаться от текущего")
		case errors.Is(err, auth.ErrCredentialsChanged):
			writeError(writer, http.StatusConflict, "CREDENTIALS_CHANGED", "Пароль уже был изменён; войдите снова")
		default:
			writeAuthManagementError(writer, err)
		}
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) users(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Auth.ListUsers(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "authorization_model": "all_local_users_are_administrators"})
}

func (server *Server) createUser(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		Username             string `json:"username"`
		Password             string `json:"password"`
		PasswordConfirmation string `json:"password_confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if input.Password != input.PasswordConfirmation {
		writeError(writer, http.StatusBadRequest, "PASSWORD_CONFIRMATION_MISMATCH", "Пароль и подтверждение не совпадают")
		return
	}
	item, err := server.dependencies.Auth.CreateUser(request.Context(), principal, input.Username, input.Password)
	if err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, item)
}

func (server *Server) updateUser(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		Username *string `json:"username"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	item, err := server.dependencies.Auth.UpdateUser(request.Context(), principal, request.PathValue("id"), auth.UpdateUserInput{Username: input.Username, Enabled: input.Enabled})
	if err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (server *Server) deleteUser(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("X-Confirm-Destructive") != "delete-disabled-user" {
		writeError(writer, http.StatusConflict, "CONFIRM_USER_DELETE", "Удаление отключённого пользователя требует подтверждения")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.Auth.DeleteUser(request.Context(), principal, request.PathValue("id")); err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) resetUserPassword(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		Password             string `json:"password"`
		PasswordConfirmation string `json:"password_confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if input.Password != input.PasswordConfirmation {
		writeError(writer, http.StatusBadRequest, "PASSWORD_CONFIRMATION_MISMATCH", "Пароль и подтверждение не совпадают")
		return
	}
	if err := server.dependencies.Auth.ResetPassword(request.Context(), principal, request.PathValue("id"), input.Password); err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) sessions(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	items, err := server.dependencies.Auth.ListSessions(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	payload := make([]map[string]any, 0, len(items))
	for _, item := range items {
		payload = append(payload, map[string]any{
			"id": item.ID, "user_id": item.UserID, "username": item.Username,
			"created_at": item.CreatedAt, "expires_at": item.ExpiresAt, "last_seen_at": item.LastSeenAt,
			"current": item.ID == principal.SessionHash,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": payload})
}

func (server *Server) revokeSession(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	sessionID := request.PathValue("id")
	if err := server.dependencies.Auth.RevokeSession(request.Context(), principal, sessionID); err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	if sessionID == principal.SessionHash {
		http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) gatewayStatus(writer http.ResponseWriter, request *http.Request) {
	snapshot, err := server.dependencies.State.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"gateway_state": snapshot.GatewayState, "path_state": snapshot.PathState,
		"active_uplink_id": snapshot.ActiveUplinkID,
		"active_modem_id":  snapshot.ActiveModemID, "active_path_id": snapshot.ActivePathID,
		"active_direct_path_id": snapshot.ActiveDirectPathID,
		"active_method_id":      snapshot.ActiveMethodID, "active_method_kind": snapshot.ActiveMethodKind,
		"active_quality_class":   snapshot.ActiveQualityClass,
		"management_uplink_id":   snapshot.ManagementUplinkID,
		"management_modem_id":    snapshot.ManagementModemID,
		"active_subscription_id": snapshot.ActiveSubscriptionID, "active_node_id": snapshot.ActiveNodeID,
		"config_generation":            snapshot.ConfigGeneration,
		"policy_transition_generation": snapshot.PolicyTransitionGeneration,
		"policy_transition_started_at": snapshot.PolicyTransitionStartedAt,
		"policy_transition_deadline":   snapshot.PolicyTransitionDeadline,
		"updated_at":                   snapshot.UpdatedAt,
	})
}

func (server *Server) runtimeMetrics(writer http.ResponseWriter, request *http.Request) {
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok || principal.SessionHash == "" {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if allowed, retry := server.metricsLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "RUNTIME_METRICS_RATE_LIMITED", "Слишком много запросов runtime metrics")
		return
	}
	var memory runtimepkg.MemStats
	runtimepkg.ReadMemStats(&memory)
	now := server.now()
	uptime := now.Sub(server.startedAt)
	if uptime < 0 {
		uptime = 0
	}
	response := map[string]any{
		"schema_version":             1,
		"collected_at":               now.Format(time.RFC3339Nano),
		"uptime_seconds":             int64(uptime / time.Second),
		"goroutines":                 runtimepkg.NumGoroutine(),
		"heap_alloc_bytes":           memory.HeapAlloc,
		"heap_inuse_bytes":           memory.HeapInuse,
		"stack_inuse_bytes":          memory.StackInuse,
		"go_runtime_sys_bytes":       memory.Sys,
		"mallocs_total":              memory.Mallocs,
		"frees_total":                memory.Frees,
		"live_heap_objects":          memory.Mallocs - memory.Frees,
		"gc_cycles_total":            memory.NumGC,
		"gc_pause_total_nanoseconds": memory.PauseTotalNs,
	}
	process := readProcessMetrics()
	if process.RSSBytes != nil {
		response["process_rss_bytes"] = *process.RSSBytes
	}
	if process.OpenFileDescriptors != nil {
		response["open_file_descriptors"] = *process.OpenFileDescriptors
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) wireGuardStatus(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "WireGuard runtime не подключён")
		return
	}
	runtimeState, err := server.dependencies.WireGuardRuntime.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	items, err := server.dependencies.Modems.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	modemStates := make([]map[string]any, 0, len(items))
	for _, item := range items {
		modemStates = append(modemStates, map[string]any{
			"id": item.ID, "number": item.DisplayNumber, "name": item.Name,
			"priority": item.Priority, "enabled": item.Enabled, "state": item.State,
			"management_reachability_state": item.ManagementReachabilityState,
		})
	}
	status := "DISCONNECTED"
	if runtimeState.CurrentModemID != "" {
		status = "ACTIVE"
	}
	if runtimeState.CandidateModemID != "" {
		status = "PROBING"
	}
	handshakeStale := runtimeState.CurrentModemID != ""
	var handshakeAgeSeconds int64
	if lastHandshake, parseErr := time.Parse(time.RFC3339Nano, runtimeState.LastHandshakeAt); parseErr == nil {
		age := server.now().Sub(lastHandshake)
		if age < 0 {
			age = 0
		}
		handshakeAgeSeconds = int64(age / time.Second)
		handshakeStale = age > 3*time.Minute
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"status": status, "current_modem_id": runtimeState.CurrentModemID,
		"candidate_modem_id": runtimeState.CandidateModemID, "route_modem_id": runtimeState.RouteModemID,
		"endpoint_ip": runtimeState.EndpointIP, "probe_started_at": runtimeState.ProbeStartedAt,
		"last_switch_at": runtimeState.LastSwitchAt, "last_handshake_at": runtimeState.LastHandshakeAt,
		"handshake_age_seconds": handshakeAgeSeconds, "handshake_stale": handshakeStale,
		"modems": modemStates,
	})
}

func (server *Server) managementFabricDashboard(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Управление несколькими VPS не подключено")
		return
	}
	dashboard, err := server.dependencies.ManagementFabric.Dashboard(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	hostStatus := networkapply.ManagementFabricStatus{}
	hostQueryState := "NOT_AVAILABLE"
	if server.dependencies.ManagementFabricAdmin != nil {
		hostQueryState = "AVAILABLE"
		if status, err := server.dependencies.ManagementFabricAdmin.ManagementFabricStatus(request.Context()); err == nil {
			hostStatus = status
		} else {
			hostQueryState = "TEMPORARILY_UNAVAILABLE"
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"fabric": dashboard, "host_status": hostStatus, "host_status_query_state": hostQueryState,
		"apply_available": server.dependencies.ManagementFabricAdmin != nil,
		"model":           "many_to_many_all_enabled_links_simultaneous",
	})
}

func (server *Server) reorderManagementVPS(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Управление несколькими VPS не подключено")
		return
	}
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.ManagementFabric.ReorderVPS(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) updateManagementVPS(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Управление несколькими VPS не подключено")
		return
	}
	var input struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	item, err := server.dependencies.ManagementFabric.UpdateVPS(request.Context(), request.PathValue("id"), managementfabric.UpdateVPSInput{Name: input.Name, Enabled: input.Enabled})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"id": item.ID, "updated": true, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) updateManagementLink(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Управление несколькими VPS не подключено")
		return
	}
	var input struct {
		Enabled             bool   `json:"enabled"`
		UplinkPolicy        string `json:"uplink_policy"`
		PinnedUplinkID      string `json:"pinned_uplink_id"`
		PersistentKeepalive int    `json:"persistent_keepalive"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	item, err := server.dependencies.ManagementFabric.UpdateLink(request.Context(), request.PathValue("id"), managementfabric.UpdateLinkInput{
		Enabled: input.Enabled, UplinkPolicy: input.UplinkPolicy,
		PinnedUplinkID: input.PinnedUplinkID, PersistentKeepalive: input.PersistentKeepalive,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"id": item.ID, "updated": true, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) configureManagementAdminContour(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabricAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_APPLY_NOT_AVAILABLE", "Root-контроллер wg-admin не подключён")
		return
	}
	var input managementfabric.AdminContourRequest
	if err := decodeJSON(request, &input); err != nil || managementfabric.ValidateAdminContourRequest(input) != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_CONTOUR_REQUEST_INVALID", "Укажите непересекающуюся private IPv4-подсеть и адрес Gateway внутри неё")
		return
	}
	item, err := server.dependencies.ManagementFabricAdmin.ConfigureAdminContour(request.Context(), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (server *Server) rotateManagementAdminContour(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabricAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_APPLY_NOT_AVAILABLE", "Root-контроллер wg-admin не подключён")
		return
	}
	var input struct {
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil || input.Confirmation != "ЗАМЕНИТЬ КЛЮЧ WG-ADMIN" {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusConflict, "ADMIN_CONTOUR_ROTATION_CONFIRMATION_INVALID", "Контрольная фраза для замены ключа не совпадает")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		input.Password, input.Confirmation = "", ""
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			writer.Header().Set("Retry-After", "2")
			writeError(writer, http.StatusTooManyRequests, "REAUTH_RATE_LIMITED", "Слишком много неверных попыток; повторите позже")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "REAUTH_FAILED", "Текущий пароль указан неверно")
		default:
			writeInternalError(writer, err)
		}
		return
	}
	input.Password, input.Confirmation = "", ""
	item, err := server.dependencies.ManagementFabricAdmin.RotateAdminContourIdentity(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "ADMIN_CONTOUR_ROTATION_FAILED", "Ключ wg-admin не заменён; прежняя identity сохранена или восстановлена")
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (server *Server) createManagementAdminRelay(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.AdminRelayInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_RELAY_REQUEST_INVALID", "Некорректные параметры UDP relay")
		return
	}
	item, err := server.dependencies.ManagementFabric.CreateAdminRelay(request.Context(), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"relay": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) updateManagementAdminRelay(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.AdminRelayInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_RELAY_REQUEST_INVALID", "Некорректные параметры UDP relay")
		return
	}
	item, err := server.dependencies.ManagementFabric.UpdateAdminRelay(request.Context(), request.PathValue("id"), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"relay": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) deleteManagementAdminRelay(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil || request.Header.Get("X-Confirm-Destructive") != "delete-disabled-admin-relay" {
		writeError(writer, http.StatusConflict, "ADMIN_RELAY_DELETE_CONFIRMATION_REQUIRED", "Сначала отключите relay и подтвердите удаление")
		return
	}
	if err := server.dependencies.ManagementFabric.DeleteAdminRelay(request.Context(), request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	_ = server.requestManagementFabricSync(request.Context())
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) createManagementAdminTunnel(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.AdminTunnelInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_TUNNEL_REQUEST_INVALID", "Некорректные параметры inner WireGuard peer")
		return
	}
	item, err := server.dependencies.ManagementFabric.CreateAdminTunnel(request.Context(), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"tunnel": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) revokeManagementAdminTunnel(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil || request.Header.Get("X-Confirm-Destructive") != "revoke-admin-tunnel" {
		writeError(writer, http.StatusConflict, "ADMIN_TUNNEL_REVOKE_CONFIRMATION_REQUIRED", "Отзыв inner tunnel требует подтверждения")
		return
	}
	item, err := server.dependencies.ManagementFabric.RevokeAdminTunnel(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"tunnel": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) deleteManagementAdminTunnel(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil || request.Header.Get("X-Confirm-Destructive") != "delete-revoked-admin-tunnel" {
		writeError(writer, http.StatusConflict, "ADMIN_TUNNEL_DELETE_CONFIRMATION_REQUIRED", "Удалить можно только отозванный inner tunnel после подтверждения")
		return
	}
	if err := server.dependencies.ManagementFabric.DeleteAdminTunnel(request.Context(), request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	_ = server.requestManagementFabricSync(request.Context())
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) updateManagementAdminTrustMode(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input struct {
		TrustMode string `json:"trust_mode"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_TRUST_MODE_REQUEST_INVALID", "Некорректный trust mode")
		return
	}
	if err := server.dependencies.ManagementFabric.SetAdminTrustMode(request.Context(), request.PathValue("admin_id"), request.PathValue("vps_id"), input.TrustMode); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"updated": true, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) syncManagementFabric(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabricAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_APPLY_NOT_AVAILABLE", "Применение Management Fabric не подключено")
		return
	}
	if err := server.dependencies.ManagementFabricAdmin.SyncManagementFabric(request.Context()); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "MANAGEMENT_FABRIC_SYNC_FAILED", "Применение не завершено; watchdog повторит безопасную попытку")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) requestManagementFabricSync(ctx context.Context) string {
	if server.dependencies.ManagementFabricAdmin == nil {
		return "NOT_AVAILABLE"
	}
	if err := server.dependencies.ManagementFabricAdmin.SyncManagementFabric(ctx); err != nil {
		return "RETRY_PENDING"
	}
	return "SYNCED"
}

func (server *Server) wireGuardSettings(writer http.ResponseWriter, request *http.Request) {
	if !filepath.IsAbs(server.dependencies.WireGuardConfigPath) {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "WireGuard configuration не подключена")
		return
	}
	configuration, err := wireguardpkg.LoadConfig(server.dependencies.WireGuardConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(writer, http.StatusOK, map[string]any{
			"configured": false, "interface_name": "wg-mgmt", "address": "10.80.0.2/32",
			"allowed_ips": []string{"10.80.0.0/24"}, "endpoint_port": 51821, "persistent_keepalive": 25, "handshake_timeout_seconds": 45,
		})
		return
	}
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"configured": true, "interface_name": configuration.InterfaceName, "address": configuration.Address,
		"peer_public_key": configuration.PeerPublicKey, "endpoint": configuration.Endpoint,
		"allowed_ips": configuration.AllowedIPs, "persistent_keepalive": configuration.PersistentKeepalive,
		"handshake_timeout_seconds": int(wireguardpkg.HandshakeTimeout(configuration) / time.Second),
	})
}

func (server *Server) wireGuardIngressServer(writer http.ResponseWriter, request *http.Request) {
	item, err := server.loadWireGuardIngressServer(request.Context())
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"server": item})
}

func (server *Server) updateWireGuardIngressServer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	var input wgingress.ServerUpdate
	if err := decodeJSON(request, &input); err != nil || wgingress.ValidateServerUpdate(input) != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_SERVER", "Проверьте подсеть, endpoint, порт, интерфейсы и topology mode")
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.UpdateWireGuardIngressServer(request.Context(), input)
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"server": item})
}

func (server *Server) rotateWireGuardIngressServer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	var input struct {
		PasswordConfirmation string `json:"password_confirmation"`
		Confirmation         string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil || input.Confirmation != "ROTATE_WIREGUARD_SERVER_KEY" {
		writeError(writer, http.StatusBadRequest, "CONFIRMATION_REQUIRED", "Требуется точное подтверждение ROTATE_WIREGUARD_SERVER_KEY")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.PasswordConfirmation); err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.RotateWireGuardIngressServer(request.Context())
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"server": item})
}

func (server *Server) wireGuardIngressPeers(writer http.ResponseWriter, request *http.Request) {
	if _, err := server.loadWireGuardIngressServer(request.Context()); err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	items, err := server.dependencies.WireGuardIngress.ListPeers(request.Context())
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) createWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	var input wgingress.PeerCreate
	if err := decodeJSON(request, &input); err != nil || wgingress.ValidatePeerCreate(input) != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_PEER", "Проверьте тип, ключ, адреса, маршруты и политику клиента")
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.CreateWireGuardIngressPeer(request.Context(), input)
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"peer": item})
}

func (server *Server) updateWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	var input wgingress.PeerUpdate
	if err := decodeJSON(request, &input); err != nil || wgingress.ValidatePeerUpdate(input) != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_PEER", "Проверьте параметры WireGuard-клиента")
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.UpdateWireGuardIngressPeer(request.Context(), request.PathValue("id"), input)
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"peer": item})
}

func (server *Server) revokeWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "revoke-wireguard-peer" {
		writeError(writer, http.StatusBadRequest, "CONFIRMATION_REQUIRED", "Требуется подтверждение отзыва клиента")
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.RevokeWireGuardIngressPeer(request.Context(), request.PathValue("id"))
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"peer": item})
}

func (server *Server) deleteWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "delete-revoked-wireguard-peer" {
		writeError(writer, http.StatusBadRequest, "CONFIRMATION_REQUIRED", "Удалить можно только уже отозванного клиента после явного подтверждения")
		return
	}
	if err := server.dependencies.WireGuardIngressAdmin.DeleteWireGuardIngressPeer(request.Context(), request.PathValue("id")); err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) rotateWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	var input struct {
		PasswordConfirmation string `json:"password_confirmation"`
		Confirmation         string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil || input.Confirmation != "ROTATE_WIREGUARD_CLIENT_KEY" {
		writeError(writer, http.StatusBadRequest, "CONFIRMATION_REQUIRED", "Требуется точное подтверждение ROTATE_WIREGUARD_CLIENT_KEY")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.PasswordConfirmation); err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.RotateWireGuardIngressPeer(request.Context(), request.PathValue("id"))
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"peer": item})
}

func (server *Server) probeWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngressAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	item, err := server.dependencies.WireGuardIngressAdmin.ProbeWireGuardIngressPeer(request.Context(), request.PathValue("id"))
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"peer": item})
}

func (server *Server) reauthWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.WireGuardIngress == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление входящим WireGuard не подключено")
		return
	}
	peer, err := server.dependencies.WireGuardIngress.GetPeer(request.Context(), request.PathValue("id"))
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	if peer.KeyMode != "MANAGED" || peer.RevokedAt != "" {
		writeError(writer, http.StatusConflict, "PRIVATE_CONFIG_UNAVAILABLE", "Gateway не хранит private key этого клиента")
		return
	}
	var input struct {
		PasswordConfirmation string `json:"password_confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Укажите текущий пароль")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.PasswordConfirmation); err != nil {
		writeAuthManagementError(writer, err)
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeInternalError(writer, err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256([]byte(token))
	expires := server.now().Add(90 * time.Second)
	server.secretGrantMutex.Lock()
	for key, grant := range server.secretGrants {
		if !grant.ExpiresAt.After(server.now()) {
			delete(server.secretGrants, key)
		}
	}
	server.secretGrants[hex.EncodeToString(digest[:])] = secretExportGrant{PeerID: peer.ID, SessionHash: principal.SessionHash, ExpiresAt: expires}
	server.secretGrantMutex.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"reauth_token": token, "expires_at": expires.Format(time.RFC3339Nano), "single_use": true})
}

func (server *Server) wireGuardIngressPeerConfig(writer http.ResponseWriter, request *http.Request) {
	configuration, peer, err := server.exportWireGuardIngressPeer(request)
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/wireguard-profile; charset=utf-8")
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": configuration.Filename}))
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if peer.KeyMode == "EXTERNAL" {
		writer.Header().Set("X-Gateway-VPN-Key-Mode", "external-template")
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, configuration.Content)
}

func (server *Server) wireGuardIngressPeerQRCode(writer http.ResponseWriter, request *http.Request) {
	configuration, peer, err := server.exportWireGuardIngressPeer(request)
	if err != nil {
		writeWireGuardIngressError(writer, err)
		return
	}
	if peer.KeyMode != "MANAGED" {
		writeError(writer, http.StatusConflict, "PRIVATE_CONFIG_UNAVAILABLE", "QR доступен только для managed client key")
		return
	}
	png, err := qrcode.Encode(configuration.Content, qrcode.Medium, 384)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "image/png")
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": strings.TrimSuffix(configuration.Filename, ".conf") + "-qr.png"}))
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(png)
}

func (server *Server) exportWireGuardIngressPeer(request *http.Request) (wgingress.ExportedConfig, wgingress.Peer, error) {
	if server.dependencies.WireGuardIngress == nil || server.dependencies.WireGuardIngressAdmin == nil {
		return wgingress.ExportedConfig{}, wgingress.Peer{}, errors.New("WireGuard ingress controller is unavailable")
	}
	peer, err := server.dependencies.WireGuardIngress.GetPeer(request.Context(), request.PathValue("id"))
	if err != nil {
		return wgingress.ExportedConfig{}, wgingress.Peer{}, err
	}
	if peer.KeyMode == "MANAGED" {
		principal := request.Context().Value(principalKey).(auth.Principal)
		if !server.consumeSecretGrant(request.Header.Get("X-Reauth-Token"), principal.SessionHash, peer.ID) {
			return wgingress.ExportedConfig{}, wgingress.Peer{}, errors.New("fresh single-use reauthentication is required")
		}
	}
	configuration, err := server.dependencies.WireGuardIngressAdmin.ExportWireGuardIngressPeer(request.Context(), peer.ID)
	return configuration, peer, err
}

func (server *Server) consumeSecretGrant(token, sessionHash, peerID string) bool {
	if token == "" || sessionHash == "" || peerID == "" {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(digest[:])
	server.secretGrantMutex.Lock()
	defer server.secretGrantMutex.Unlock()
	grant, exists := server.secretGrants[key]
	delete(server.secretGrants, key)
	return exists && grant.PeerID == peerID && grant.SessionHash == sessionHash && grant.ExpiresAt.After(server.now())
}

func (server *Server) loadWireGuardIngressServer(ctx context.Context) (wgingress.Server, error) {
	if server.dependencies.WireGuardIngress == nil || server.dependencies.WireGuardIngressAdmin == nil {
		return wgingress.Server{}, errors.New("WireGuard ingress controller is unavailable")
	}
	item, err := server.dependencies.WireGuardIngress.GetServer(ctx)
	if errors.Is(err, store.ErrNotFound) {
		if syncErr := server.dependencies.WireGuardIngressAdmin.SyncWireGuardIngress(ctx); syncErr != nil {
			return wgingress.Server{}, syncErr
		}
		return server.dependencies.WireGuardIngress.GetServer(ctx)
	}
	return item, err
}

func writeWireGuardIngressError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, http.StatusNotFound, "NOT_FOUND", "WireGuard-клиент не найден")
	case strings.Contains(err.Error(), "reauthentication"):
		writeError(writer, http.StatusForbidden, "REAUTH_REQUIRED", "Для выдачи private-key конфигурации повторно подтвердите пароль")
	default:
		writeError(writer, http.StatusConflict, "WIREGUARD_INGRESS_REJECTED", "Настройка отклонена безопасной проверкой или не применилась")
	}
}

func (server *Server) updateWireGuardSettings(writer http.ResponseWriter, request *http.Request) {
	if !filepath.IsAbs(server.dependencies.WireGuardConfigPath) || server.dependencies.WireGuardSync == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "WireGuard configuration не подключена")
		return
	}
	var input struct {
		PrivateKey          string `json:"private_key"`
		PeerPublicKey       string `json:"peer_public_key"`
		Endpoint            string `json:"endpoint"`
		PersistentKeepalive int    `json:"persistent_keepalive"`
		HandshakeTimeout    int    `json:"handshake_timeout_seconds"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if input.PrivateKey == "" {
		current, err := wireguardpkg.LoadConfig(server.dependencies.WireGuardConfigPath)
		if errors.Is(err, os.ErrNotExist) {
			writeError(writer, http.StatusBadRequest, "PRIVATE_KEY_REQUIRED", "Private key обязателен при первой настройке")
			return
		}
		if err != nil {
			writeInternalError(writer, err)
			return
		}
		input.PrivateKey = current.PrivateKey
	}
	configuration := wireguardpkg.Config{
		InterfaceName: "wg-mgmt", Address: "10.80.0.2/32", PrivateKey: input.PrivateKey,
		PeerPublicKey: input.PeerPublicKey, Endpoint: input.Endpoint,
		AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: input.PersistentKeepalive,
		HandshakeTimeout: input.HandshakeTimeout,
	}
	if err := wireguardpkg.ValidateConfig(configuration); err != nil {
		writeError(writer, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}
	if err := wireguardpkg.SaveConfig(server.dependencies.WireGuardConfigPath, configuration); err != nil {
		writeInternalError(writer, err)
		return
	}
	syncState := "PROBING_REQUESTED"
	if err := server.dependencies.WireGuardSync.SyncWireGuard(request.Context()); err != nil {
		syncState = "RETRY_PENDING"
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"configured": true, "sync_state": syncState})
}

func (server *Server) reconcile(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Reconcile == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Reconciler не подключён")
		return
	}
	result, err := server.dependencies.Reconcile(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) accessMethods(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.AccessPolicy.ListMethods(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	snapshot, err := server.dependencies.State.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	runtime, err := server.dependencies.AccessPolicy.GetSelectionRuntime(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]any{
			"id": item.ID, "kind": item.Kind, "subscription_id": item.SubscriptionID,
			"name": item.Name, "enabled": item.Enabled, "priority": item.Priority,
			"immutable": item.Immutable, "active": snapshot.PathState == state.PathActive && snapshot.ActiveMethodID == item.ID,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": result, "active_method_id": snapshot.ActiveMethodID,
		"path_state": snapshot.PathState, "quality_class": snapshot.ActiveQualityClass,
		"temporary_direct_only": runtime.TemporaryDirectOnly,
	})
}

func (server *Server) reorderAccessMethods(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.AccessPolicy.ReorderEnabled(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"convergence": server.convergeAccessPolicy(request.Context())})
}

func (server *Server) updateAccessMethod(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(request, &input); err != nil || input.Enabled == nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Поле enabled обязательно")
		return
	}
	id := request.PathValue("id")
	methods, err := server.dependencies.AccessPolicy.ListMethods(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	var current *accesspolicy.Method
	for index := range methods {
		if methods[index].ID == id {
			current = &methods[index]
			break
		}
	}
	if current == nil {
		writeDomainError(writer, store.ErrNotFound)
		return
	}
	if !*input.Enabled && current.Enabled {
		if err := server.blockActiveAccessMethod(request.Context(), id, "ACTIVE_ACCESS_METHOD_DISABLED"); err != nil {
			writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось безопасно закрыть активный способ доступа")
			return
		}
	}
	if err := server.dependencies.AccessPolicy.SetMethodEnabled(request.Context(), id, *input.Enabled); err != nil {
		writeDomainError(writer, err)
		return
	}
	qualification := "NOT_REQUIRED"
	if *input.Enabled && current.Kind == accesspolicy.MethodSubscription {
		qualification = server.requalifyReadyModems(request.Context())
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"enabled": *input.Enabled, "qualification": qualification, "convergence": server.convergeAccessPolicy(request.Context())})
}

func (server *Server) accessPolicySettings(writer http.ResponseWriter, request *http.Request) {
	policy, err := server.dependencies.AccessPolicy.GetPolicy(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"policy": policy,
		"limits": map[string]any{
			"failure_hold_seconds_max":    300,
			"recovery_stable_seconds_max": 3600,
			"switch_cooldown_seconds_max": 3600,
		},
	})
}

func (server *Server) updateAccessPolicySettings(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		StartupBlockUntilQualified bool  `json:"startup_block_until_qualified"`
		DirectServiceRefresh       bool  `json:"direct_service_refresh_enabled"`
		FailureHoldSeconds         int64 `json:"failure_hold_seconds"`
		RecoveryStableSeconds      int64 `json:"recovery_stable_seconds"`
		SwitchCooldownSeconds      int64 `json:"switch_cooldown_seconds"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	policy, err := server.dependencies.AccessPolicy.UpdatePolicy(request.Context(), accesspolicy.PolicyUpdate{
		StartupBlockUntilQualified: input.StartupBlockUntilQualified,
		DirectServiceRefresh:       input.DirectServiceRefresh,
		FailureHoldSeconds:         input.FailureHoldSeconds,
		RecoveryStableSeconds:      input.RecoveryStableSeconds,
		SwitchCooldownSeconds:      input.SwitchCooldownSeconds,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"policy": policy, "convergence": server.convergeAccessPolicy(request.Context())})
}

func (server *Server) enableTemporaryDirectOnly(writer http.ResponseWriter, request *http.Request) {
	bootID, err := server.dependencies.BootIDReader()
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BOOT_ID_UNAVAILABLE", "Не удалось безопасно определить текущую загрузку системы")
		return
	}
	snapshot, err := server.dependencies.State.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	if snapshot.PathState == state.PathActive && snapshot.ActiveMethodKind == accesspolicy.MethodSubscription {
		if err := server.blockActiveAccessMethod(request.Context(), snapshot.ActiveMethodID, "TEMPORARY_DIRECT_ONLY_ENABLED"); err != nil {
			writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось закрыть VPN-путь перед временным прямым режимом")
			return
		}
	}
	if err := server.dependencies.AccessPolicy.SetTemporaryDirectOnly(request.Context(), true, bootID); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"temporary_direct_only": true, "resets_after_reboot": true, "convergence": server.convergeAccessPolicy(request.Context())})
}

func (server *Server) disableTemporaryDirectOnly(writer http.ResponseWriter, request *http.Request) {
	if err := server.dependencies.AccessPolicy.SetTemporaryDirectOnly(request.Context(), false, ""); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"temporary_direct_only": false, "convergence": server.convergeAccessPolicy(request.Context())})
}

func (server *Server) blockActiveAccessMethod(ctx context.Context, methodID, reason string) error {
	snapshot, err := server.dependencies.State.Get(ctx)
	if err != nil {
		return err
	}
	if snapshot.PathState != state.PathActive || snapshot.ActiveMethodID != methodID {
		return nil
	}
	if server.dependencies.ModemRuntime == nil {
		return errors.New("data-plane blocker is unavailable")
	}
	if err := server.dependencies.ModemRuntime.BlockPath(ctx); err != nil {
		return err
	}
	_, _, err = server.dependencies.State.Block(ctx, state.GatewayBlocked, reason)
	return err
}

func (server *Server) convergeAccessPolicy(ctx context.Context) string {
	if server.dependencies.Reconcile == nil {
		return "RETRY_PENDING"
	}
	if _, err := server.dependencies.Reconcile(ctx); err != nil {
		return "RETRY_PENDING"
	}
	return "COMPLETE"
}

type uplinkReadItem struct {
	ID                          string         `json:"id"`
	Number                      int64          `json:"number"`
	Type                        string         `json:"type"`
	Name                        string         `json:"name"`
	Enabled                     bool           `json:"enabled"`
	Priority                    int64          `json:"priority"`
	NetworkInterfaceID          string         `json:"network_interface_id"`
	InterfaceName               string         `json:"interface_name"`
	AddressMode                 string         `json:"address_mode"`
	IPv4CIDR                    string         `json:"ipv4_cidr"`
	Gateway                     string         `json:"gateway"`
	DNS                         []string       `json:"dns"`
	ConfiguredIPv4CIDR          string         `json:"configured_ipv4_cidr"`
	ConfiguredGateway           string         `json:"configured_gateway"`
	ConfiguredDNS               []string       `json:"configured_dns"`
	MTU                         int64          `json:"mtu"`
	RoutingTableID              int64          `json:"routing_table_id"`
	Fwmark                      int64          `json:"fwmark"`
	RouteGeneration             int64          `json:"route_generation"`
	DesiredGeneration           int64          `json:"desired_generation"`
	ObservedGeneration          int64          `json:"observed_generation"`
	State                       string         `json:"state"`
	ReadinessReason             string         `json:"readiness_reason"`
	LastSeenAt                  string         `json:"last_seen_at"`
	StableSince                 string         `json:"stable_since"`
	OperatorLabel               string         `json:"operator_label,omitempty"`
	ObservedOperator            string         `json:"observed_operator,omitempty"`
	ModemState                  string         `json:"modem_state,omitempty"`
	TelemetryState              string         `json:"telemetry_state,omitempty"`
	ManagementReachabilityState string         `json:"management_reachability_state,omitempty"`
	Paths                       []pathReadItem `json:"paths"`
}

type networkInterfaceRoleReadItem struct {
	Role               string `json:"role"`
	UplinkID           string `json:"uplink_id,omitempty"`
	DesiredGeneration  int64  `json:"desired_generation"`
	ObservedGeneration int64  `json:"observed_generation"`
	State              string `json:"state"`
}

type networkInterfaceReadItem struct {
	ID               string                         `json:"id"`
	IdentityKind     string                         `json:"identity_kind"`
	MaskedMAC        string                         `json:"masked_mac"`
	TopologyPath     string                         `json:"topology_path"`
	InterfaceName    string                         `json:"interface_name"`
	Driver           string                         `json:"driver"`
	Vendor           string                         `json:"vendor"`
	Model            string                         `json:"model"`
	CarrierState     string                         `json:"carrier_state"`
	Addresses        []string                       `json:"addresses"`
	ObservedAt       string                         `json:"observed_at"`
	ReplacementForID string                         `json:"replacement_for_interface_id"`
	Roles            []networkInterfaceRoleReadItem `json:"roles"`
}

func (server *Server) uplinks(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Инвентарь физических выходов не подключён")
		return
	}
	stored, err := server.dependencies.Uplinks.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	paths, err := server.readAccessPaths(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	pathsByUplink := make(map[string][]pathReadItem, len(stored))
	for _, path := range paths {
		pathsByUplink[path.UplinkID] = append(pathsByUplink[path.UplinkID], path)
	}
	result := make([]uplinkReadItem, 0, len(stored))
	for _, item := range stored {
		var dns []string
		if err := json.Unmarshal([]byte(item.DNSJSON), &dns); err != nil {
			writeInternalError(writer, fmt.Errorf("decode DNS for uplink %s: %w", item.ID, err))
			return
		}
		var configuredDNS []string
		if err := json.Unmarshal([]byte(item.ConfiguredDNSJSON), &configuredDNS); err != nil {
			writeInternalError(writer, fmt.Errorf("decode configured DNS for uplink %s: %w", item.ID, err))
			return
		}
		view := uplinkReadItem{
			ID: item.ID, Number: item.DisplayNumber, Type: item.Type, Name: item.Name,
			Enabled: item.Enabled, Priority: item.Priority,
			NetworkInterfaceID: item.NetworkInterfaceID, InterfaceName: item.CurrentIfname,
			AddressMode: item.AddressMode, IPv4CIDR: item.IPv4CIDR, Gateway: item.Gateway,
			DNS: dns, ConfiguredIPv4CIDR: item.ConfiguredIPv4CIDR,
			ConfiguredGateway: item.ConfiguredGateway, ConfiguredDNS: configuredDNS,
			MTU: item.MTU, RoutingTableID: item.RoutingTableID, Fwmark: item.Fwmark,
			RouteGeneration: item.RouteGeneration, DesiredGeneration: item.DesiredGeneration,
			ObservedGeneration: item.ObservedGeneration, State: item.State,
			ReadinessReason: item.ReadinessReason,
			LastSeenAt:      item.LastSeenAt, StableSince: item.StableSince,
			Paths: pathsByUplink[item.ID],
		}
		if item.Type == uplink.TypeHiLink {
			details, err := server.dependencies.Uplinks.GetHiLink(request.Context(), item.ID)
			if err != nil {
				writeInternalError(writer, err)
				return
			}
			view.OperatorLabel = details.OperatorLabel
			view.ObservedOperator = details.ObservedOperator
			view.ModemState = details.ModemState
			view.TelemetryState = details.TelemetryState
			view.ManagementReachabilityState = details.ManagementReachabilityState
		}
		result = append(result, view)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
}

func (server *Server) reorderUplinks(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil || server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление физическими выходами не подключено")
		return
	}
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.Uplinks.ReorderEnabled(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) uplinkImpact(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil || server.dependencies.State == nil || server.dependencies.Database == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Предварительная оценка физического выхода не подключена")
		return
	}
	operation := strings.ToUpper(strings.TrimSpace(request.URL.Query().Get("operation")))
	if operation != "DISABLE" && operation != "DELETE" {
		writeError(writer, http.StatusBadRequest, "INVALID_OPERATION", "Поддерживается предварительная оценка DISABLE или DELETE")
		return
	}
	item, err := server.dependencies.Uplinks.Get(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if item.Type != uplink.TypeEthernet {
		writeError(writer, http.StatusConflict, "UPLINK_TYPE_INVALID", "Эта оценка предназначена для Ethernet-выхода")
		return
	}
	snapshot, err := server.dependencies.State.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	var vpnPaths, directPaths, readyAlternatives int64
	if err := server.dependencies.Database.QueryRowContext(request.Context(), "SELECT COUNT(*) FROM subscription_uplink_paths WHERE uplink_id=?", item.ID).Scan(&vpnPaths); err != nil {
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.Database.QueryRowContext(request.Context(), "SELECT COUNT(*) FROM direct_uplink_paths WHERE uplink_id=?", item.ID).Scan(&directPaths); err != nil {
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.Database.QueryRowContext(request.Context(), "SELECT COUNT(*) FROM uplinks WHERE id<>? AND enabled=1 AND state='UPLINK_READY'", item.ID).Scan(&readyAlternatives); err != nil {
		writeInternalError(writer, err)
		return
	}
	active := snapshot.ActiveUplinkID == item.ID
	allowed := true
	blockedReason := ""
	if operation == "DELETE" && item.Enabled {
		allowed, blockedReason = false, "DISABLE_FIRST"
	}
	if operation == "DELETE" && active {
		allowed, blockedReason = false, "ACTIVE_UPLINK"
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"uplink_id": item.ID, "operation": operation, "active": active,
		"enabled": item.Enabled, "state": item.State, "readiness_reason": item.ReadinessReason,
		"affected_vpn_paths": vpnPaths, "affected_direct_paths": directPaths,
		"ready_alternative_uplinks":   readyAlternatives,
		"will_close_current_path":     active,
		"internet_may_be_blocked":     active && readyAlternatives == 0,
		"expected_desired_generation": item.DesiredGeneration,
		"allowed":                     allowed, "blocked_reason": blockedReason,
	})
}

func (server *Server) enableEthernetUplink(writer http.ResponseWriter, request *http.Request) {
	server.setEthernetUplinkEnabled(writer, request, true)
}

func (server *Server) disableEthernetUplink(writer http.ResponseWriter, request *http.Request) {
	server.setEthernetUplinkEnabled(writer, request, false)
}

func (server *Server) setEthernetUplinkEnabled(writer http.ResponseWriter, request *http.Request, enabled bool) {
	if server.dependencies.Uplinks == nil || server.dependencies.ModemRuntime == nil || server.dependencies.State == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление Ethernet-выходами не подключено")
		return
	}
	var input struct {
		ExpectedDesiredGeneration int64 `json:"expected_desired_generation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	id := request.PathValue("id")
	if !enabled {
		snapshot, err := server.dependencies.State.Get(request.Context())
		if err != nil {
			writeInternalError(writer, err)
			return
		}
		if snapshot.ActiveUplinkID == id {
			if err := server.dependencies.ModemRuntime.BlockPath(request.Context()); err != nil {
				writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось безопасно закрыть активный путь")
				return
			}
			if _, _, err := server.dependencies.State.Block(request.Context(), state.GatewayBlocked, "ACTIVE_ETHERNET_UPLINK_DISABLED"); err != nil {
				writeInternalError(writer, err)
				return
			}
		}
	}
	updated, err := server.dependencies.Uplinks.SetEthernetEnabled(request.Context(), id, uplink.SetEthernetEnabledInput{
		Enabled: enabled, ExpectedDesiredGeneration: input.ExpectedDesiredGeneration,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"enabled": updated.Enabled, "desired_generation": updated.DesiredGeneration,
		"state": updated.State, "convergence": server.convergeModemRuntime(request.Context()),
	})
}

func (server *Server) networkInterfaces(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Инвентарь сетевых интерфейсов не подключён")
		return
	}
	stored, err := server.dependencies.Uplinks.ListInterfaces(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	result := make([]networkInterfaceReadItem, 0, len(stored))
	for _, item := range stored {
		var addresses []string
		if err := json.Unmarshal([]byte(item.AddressesJSON), &addresses); err != nil {
			writeInternalError(writer, fmt.Errorf("decode addresses for network interface %s: %w", item.ID, err))
			return
		}
		roles := make([]networkInterfaceRoleReadItem, 0, len(item.Roles))
		for _, role := range item.Roles {
			roles = append(roles, networkInterfaceRoleReadItem{
				Role: role.Role, UplinkID: role.UplinkID, DesiredGeneration: role.DesiredGeneration,
				ObservedGeneration: role.ObservedGeneration, State: role.State,
			})
		}
		result = append(result, networkInterfaceReadItem{
			ID: item.ID, IdentityKind: item.StableIdentityKind, MaskedMAC: maskMAC(item.PermanentMAC),
			TopologyPath: item.TopologyPath, InterfaceName: item.CurrentIfname,
			Driver: item.Driver, Vendor: item.Vendor, Model: item.Model,
			CarrierState: item.CarrierState, Addresses: addresses, ObservedAt: item.ObservedAt,
			ReplacementForID: item.ReplacementForID, Roles: roles,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
}

func maskMAC(value string) string {
	hardware, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hardware) < 6 {
		return ""
	}
	normalized := hardware.String()
	parts := strings.Split(normalized, ":")
	if len(parts) != 6 {
		return ""
	}
	return "xx:xx:xx:" + strings.Join(parts[3:], ":")
}

func (server *Server) modems(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Modems.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	paths, err := server.readAccessPaths(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	pathsByModem := make(map[string][]pathReadItem, len(items))
	for _, path := range paths {
		pathsByModem[path.ModemID] = append(pathsByModem[path.ModemID], path)
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		modemPaths := pathsByModem[item.ID]
		recoveryState, recoveryReason, recoveryFailure := "NOT_AVAILABLE", "", ""
		if server.dependencies.ModemRecovery != nil {
			if recoverySnapshot, snapshotErr := server.dependencies.ModemRecovery.Snapshot(request.Context(), item.ID, 1); snapshotErr == nil {
				recoveryState, recoveryReason, recoveryFailure = recoverySnapshot.Runtime.State, recoverySnapshot.Runtime.LastOutcomeCode, recoverySnapshot.Runtime.FailureReason
			}
		}
		var directPath any
		for index := range modemPaths {
			if modemPaths[index].Kind == accesspolicy.MethodDirect {
				directPath = modemPaths[index]
				break
			}
		}
		result = append(result, map[string]any{
			"id": item.ID, "number": item.DisplayNumber, "name": item.Name,
			"operator_label": item.OperatorLabel, "observed_operator": item.ObservedOperator,
			"enabled": item.Enabled, "priority": item.Priority, "interface_name": item.InterfaceName,
			"management_cidr": item.ManagementCIDR, "gateway": item.Gateway, "mtu": item.MTU,
			"routing_table_id": item.RoutingTableID, "fwmark": item.Fwmark,
			"state": item.State, "telemetry_state": item.TelemetryState,
			"management_reachability_state": item.ManagementReachabilityState,
			"last_seen_at":                  item.LastSeenAt, "stable_since": item.StableSince,
			"recovery_state": recoveryState, "recovery_reason": recoveryReason, "physical_failure": recoveryFailure,
			"subnet_conflict": modemSubnetConflictView(item, items),
			"direct_path":     directPath, "paths": modemPaths,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
}

func modemSubnetConflictView(current modem.Modem, items []modem.Modem) any {
	if current.State != modem.StateSubnetConflict {
		return nil
	}
	prefix, err := netip.ParsePrefix(current.ManagementCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return map[string]any{"reason_code": "OBSERVED_SUBNET_INVALID", "conflicts": []any{}}
	}
	conflicts := make([]map[string]any, 0)
	for _, other := range items {
		if other.ID == current.ID || !other.Enabled || other.ManagementCIDR == "" {
			continue
		}
		otherPrefix, parseErr := netip.ParsePrefix(other.ManagementCIDR)
		if parseErr != nil || !otherPrefix.Addr().Is4() || !prefix.Overlaps(otherPrefix) {
			continue
		}
		conflicts = append(conflicts, map[string]any{
			"modem_id": other.ID, "number": other.DisplayNumber, "name": other.Name,
			"interface_name": other.InterfaceName, "management_cidr": other.ManagementCIDR, "gateway": other.Gateway,
		})
	}
	reason := "OVERLAPS_GATEWAY_NETWORK"
	if len(conflicts) != 0 {
		reason = "OVERLAPS_OTHER_MODEM"
	}
	managementURL := ""
	if gateway, parseErr := netip.ParseAddr(current.Gateway); parseErr == nil && gateway.Is4() {
		managementURL = "http://" + gateway.String() + "/"
	}
	return map[string]any{
		"reason_code": reason, "observed_cidr": current.ManagementCIDR,
		"suggested_management_url": managementURL, "conflicts": conflicts,
	}
}

func (server *Server) discoveredModems(writer http.ResponseWriter, _ *http.Request) {
	if server.dependencies.Discoveries == nil {
		writeJSON(writer, http.StatusOK, map[string]any{"items": []hilink.DiscoveryView{}})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": server.dependencies.Discoveries.List()})
}

func (server *Server) adoptModem(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Discoveries == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Обнаружение модемов не подключено")
		return
	}
	var input struct {
		Name          string `json:"name"`
		OperatorLabel string `json:"operator_label"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	created, err := server.dependencies.Discoveries.Adopt(request.Context(), request.PathValue("discovery_id"), newID("modem"), input.Name, input.OperatorLabel)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(writer, http.StatusNotFound, "DISCOVERY_NOT_FOUND", "Обнаруженный модем больше не доступен")
			return
		}
		writeError(writer, http.StatusConflict, "MODEM_ADOPTION_FAILED", "Модем не удалось принять")
		return
	}
	if err := server.dependencies.Paths.ReconcileCells(request.Context()); err != nil {
		writeInternalError(writer, err)
		return
	}
	_, _ = server.reconcileModemInventory(request.Context())
	convergence := server.convergeModemRuntime(request.Context())
	writeJSON(writer, http.StatusCreated, map[string]any{"id": created.ID, "number": created.DisplayNumber, "name": created.Name, "state": created.State, "convergence": convergence})
}

func (server *Server) updateModem(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Name          string `json:"name"`
		OperatorLabel string `json:"operator_label"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.Modems.Update(request.Context(), request.PathValue("id"), modem.UpdateInput{Name: input.Name, OperatorLabel: input.OperatorLabel}); err != nil {
		writeDomainError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) reorderModems(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Modem runtime не подключён")
		return
	}
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if server.dependencies.Uplinks == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Общий приоритет физических выходов не подключён")
		return
	}
	if err := server.dependencies.Uplinks.ReorderEnabledType(request.Context(), uplink.TypeHiLink, input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) enableModem(writer http.ResponseWriter, request *http.Request) {
	server.setModemEnabled(writer, request, true)
}

func (server *Server) disableModem(writer http.ResponseWriter, request *http.Request) {
	server.setModemEnabled(writer, request, false)
}

func (server *Server) setModemEnabled(writer http.ResponseWriter, request *http.Request, enabled bool) {
	if server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Modem runtime не подключён")
		return
	}
	id := request.PathValue("id")
	current, err := server.dependencies.Modems.Get(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !enabled {
		snapshot, snapshotErr := server.dependencies.State.Get(request.Context())
		if snapshotErr != nil {
			writeInternalError(writer, snapshotErr)
			return
		}
		if snapshot.ActiveUplinkID == id {
			if err := server.dependencies.ModemRuntime.BlockPath(request.Context()); err != nil {
				writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось безопасно закрыть активный путь")
				return
			}
			if _, _, err := server.dependencies.State.Block(request.Context(), state.GatewayBlocked, "ACTIVE_MODEM_DISABLED"); err != nil {
				writeInternalError(writer, err)
				return
			}
		}
	}
	if err := server.dependencies.Modems.SetEnabled(request.Context(), id, enabled); err != nil {
		writeDomainError(writer, err)
		return
	}
	if enabled && !current.Enabled {
		_, _ = server.reconcileModemInventory(request.Context())
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"enabled": enabled, "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) probeModem(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRuntime == nil || server.dependencies.ModemReconcile == nil || server.dependencies.ModemPathProbe == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Modem runtime не подключён")
		return
	}
	id := request.PathValue("id")
	current, err := server.dependencies.Modems.Get(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !current.Enabled {
		writeError(writer, http.StatusConflict, "MODEM_DISABLED", "Отключённый модем нельзя проверить")
		return
	}
	result, err := server.reconcileModemInventory(request.Context())
	if err != nil {
		writeError(writer, http.StatusBadGateway, "MODEM_PROBE_FAILED", "Проверка модема не завершена")
		return
	}
	ready := containsString(result.ReadyModems, id)
	qualification := "MODEM_NOT_READY"
	var checked, qualified, failed int
	if ready {
		probe, probeErr := server.dependencies.ModemPathProbe.RequalifyModem(request.Context(), id)
		if probeErr != nil {
			qualification = "RETRY_PENDING"
		} else {
			qualification = "COMPLETE"
			checked, qualified, failed = probe.SubscriptionsChecked, probe.Qualified, probe.Failed
		}
	}
	_ = server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "INFO", Type: "MODEM_PROBE_REQUESTED", ModemID: id, Details: map[string]any{"ready": ready, "inventory_error": result.Errors[id] != "", "qualification": qualification, "subscriptions_checked": checked, "qualified": qualified, "failed": failed}})
	writeJSON(writer, http.StatusAccepted, map[string]any{"ready": ready, "qualification": qualification, "subscriptions_checked": checked, "qualified": qualified, "failed": failed, "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) recoverModem(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRuntime == nil || server.dependencies.ModemReconcile == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Modem runtime не подключён")
		return
	}
	id := request.PathValue("id")
	current, err := server.dependencies.Modems.Get(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !current.Enabled {
		writeError(writer, http.StatusConflict, "MODEM_DISABLED", "Отключённый модем не восстанавливается автоматически")
		return
	}
	result, err := server.reconcileModemInventory(request.Context())
	if err != nil {
		writeJSON(writer, http.StatusAccepted, map[string]any{"recovery": "OBSERVATION_RETRY_PENDING", "reason_code": "PHYSICAL_STATE_NOT_CONFIRMED", "convergence": server.convergeModemRuntime(request.Context())})
		return
	}
	reason := result.PhysicalFailures[id]
	if server.dependencies.ModemRecovery == nil {
		writeJSON(writer, http.StatusAccepted, map[string]any{"recovery": "CONTROLLER_NOT_AVAILABLE", "ready": containsString(result.ReadyModems, id), "convergence": server.convergeModemRuntime(request.Context())})
		return
	}
	recovery, recoveryErr := server.dependencies.ModemRecovery.Request(request.Context(), id, reason)
	if recoveryErr != nil && !errors.Is(recoveryErr, modemrecovery.ErrNoPhysicalFailure) {
		writeDomainError(writer, recoveryErr)
		return
	}
	if recovery.Action != "" && recovery.Status == modemrecovery.AttemptSucceeded {
		result, _ = server.reconcileModemInventory(request.Context())
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"recovery": recovery, "ready": containsString(result.ReadyModems, id), "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) modemRecovery(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRecovery == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Восстановление модемов не подключено")
		return
	}
	limit, err := parsePageLimit(request, 20)
	if err != nil || limit > 100 {
		writeError(writer, http.StatusBadRequest, "INVALID_LIMIT", "limit должен быть от 1 до 100")
		return
	}
	snapshot, err := server.dependencies.ModemRecovery.Snapshot(request.Context(), request.PathValue("id"), limit)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}

func (server *Server) updateModemRecovery(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRecovery == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Восстановление модемов не подключено")
		return
	}
	var input modemrecovery.PolicyUpdate
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	policy, err := server.dependencies.ModemRecovery.UpdatePolicy(request.Context(), request.PathValue("id"), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"policy": policy})
}

func (server *Server) replaceModemIdentity(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Discoveries == nil || server.dependencies.ModemRuntime == nil || server.dependencies.ModemReconcile == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Обнаружение модемов не подключено")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "replace-modem-identity" {
		writeError(writer, http.StatusConflict, "CONFIRM_REPLACE_IDENTITY", "Замена identity требует явного подтверждения")
		return
	}
	id := request.PathValue("id")
	if server.dependencies.Discoveries.IsConnected(id) {
		writeError(writer, http.StatusConflict, "MODEM_STILL_CONNECTED", "Старый модем всё ещё подключён")
		return
	}
	var input struct {
		DiscoveryID string `json:"discovery_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.Discoveries.ReplaceIdentity(request.Context(), input.DiscoveryID, id); err != nil {
		writeDomainError(writer, err)
		return
	}
	_, _ = server.reconcileModemInventory(request.Context())
	writeJSON(writer, http.StatusAccepted, map[string]any{"identity": "REPLACED", "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) forgetModem(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Modem runtime не подключён")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "forget-offline-modem" {
		writeError(writer, http.StatusConflict, "CONFIRM_FORGET_MODEM", "Удаление модема требует явного подтверждения")
		return
	}
	id := request.PathValue("id")
	if server.dependencies.Discoveries != nil && server.dependencies.Discoveries.IsConnected(id) {
		writeError(writer, http.StatusConflict, "MODEM_STILL_CONNECTED", "Подключённый модем нельзя удалить")
		return
	}
	if err := server.dependencies.Modems.Forget(request.Context(), id); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"forgotten": true, "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) reconcileModemInventory(ctx context.Context) (hilink.CycleResult, error) {
	if server.dependencies.ModemReconcile == nil {
		return hilink.CycleResult{}, errors.New("modem reconciler is unavailable")
	}
	result, err := server.dependencies.ModemReconcile(ctx)
	if err == nil && server.dependencies.Discoveries != nil {
		server.dependencies.Discoveries.Replace(result.Matches)
	}
	return result, err
}

func (server *Server) convergeModemRuntime(ctx context.Context) string {
	if server.dependencies.ModemRuntime == nil {
		return "NOT_AVAILABLE"
	}
	failed := false
	if err := server.dependencies.ModemRuntime.SyncRouting(ctx); err != nil {
		failed = true
	}
	if err := server.dependencies.ModemRuntime.SyncWireGuard(ctx); err != nil {
		failed = true
	}
	if server.dependencies.Reconcile != nil {
		if _, err := server.dependencies.Reconcile(ctx); err != nil {
			failed = true
		}
	}
	if failed {
		return "RETRY_PENDING"
	}
	return "SYNCED"
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type subscriptionInput struct {
	Name                            string `json:"name"`
	SourceURL                       string `json:"source_url"`
	AutoRefresh                     bool   `json:"auto_refresh"`
	RefreshIntervalSeconds          int64  `json:"refresh_interval_seconds"`
	FallbackWhenNamedCandidatesFail bool   `json:"fallback_when_named_candidates_fail"`
}

func (server *Server) createSubscription(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.SubscriptionRefresh == nil || !filepath.IsAbs(server.dependencies.SubscriptionSecretRoot) {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Subscription runtime не подключён")
		return
	}
	var input subscriptionInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := validateSubscriptionInput(input, true); err != nil {
		writeError(writer, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}
	interval := time.Duration(input.RefreshIntervalSeconds) * time.Second
	id := newID("subscription")
	secretRef := filepath.Join(server.dependencies.SubscriptionSecretRoot, id+".url")
	if err := subscription.SaveURLSecret(server.dependencies.SubscriptionSecretRoot, secretRef, input.SourceURL); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_SUBSCRIPTION_URL", err.Error())
		return
	}
	created, err := server.dependencies.Subscriptions.Create(request.Context(), subscription.CreateInput{ID: id, Name: input.Name, SourceType: "url", SourceSecretRef: secretRef, RefreshInterval: interval})
	if err != nil {
		_ = subscription.DeleteURLSecret(server.dependencies.SubscriptionSecretRoot, secretRef)
		writeDomainError(writer, err)
		return
	}
	if err := server.dependencies.Subscriptions.Update(request.Context(), id, subscription.UpdateInput{Name: input.Name, AutoRefresh: input.AutoRefresh, RefreshInterval: interval, FallbackWhenNamedCandidatesFail: input.FallbackWhenNamedCandidatesFail}); err != nil {
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.Paths.ReconcileCells(request.Context()); err != nil {
		writeInternalError(writer, err)
		return
	}
	refreshState := "COMPLETE"
	refresh, refreshErr := server.dependencies.SubscriptionRefresh.RefreshOne(request.Context(), id, true)
	if refreshErr != nil {
		refreshState = "RETRY_PENDING"
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"id": created.ID, "name": created.Name, "number": created.DisplayNumber, "refresh": refreshState, "version_id": refresh.VersionID})
}

func (server *Server) updateSubscription(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.SubscriptionRefresh == nil || !filepath.IsAbs(server.dependencies.SubscriptionSecretRoot) {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Subscription runtime не подключён")
		return
	}
	id := request.PathValue("id")
	current, err := server.dependencies.Subscriptions.Get(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	var input subscriptionInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := validateSubscriptionInput(input, false); err != nil {
		writeError(writer, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}
	interval := time.Duration(input.RefreshIntervalSeconds) * time.Second
	if input.SourceURL != "" {
		if err := subscription.SaveURLSecret(server.dependencies.SubscriptionSecretRoot, current.SourceSecretRef, input.SourceURL); err != nil {
			writeError(writer, http.StatusBadRequest, "INVALID_SUBSCRIPTION_URL", err.Error())
			return
		}
	}
	if err := server.dependencies.Subscriptions.Update(request.Context(), id, subscription.UpdateInput{Name: input.Name, AutoRefresh: input.AutoRefresh, RefreshInterval: interval, FallbackWhenNamedCandidatesFail: input.FallbackWhenNamedCandidatesFail}); err != nil {
		writeDomainError(writer, err)
		return
	}
	refreshState := "NOT_REQUESTED"
	var refresh subscription.RefreshResult
	if input.SourceURL != "" {
		refresh, err = server.dependencies.SubscriptionRefresh.RefreshOne(request.Context(), id, true)
		refreshState = "COMPLETE"
	} else if current.FallbackWhenNamedCandidatesFail != input.FallbackWhenNamedCandidatesFail {
		refresh, err = server.dependencies.SubscriptionRefresh.ReclassifyOne(request.Context(), id)
		refreshState = "RECLASSIFIED"
	}
	if err != nil {
		refreshState = "RETRY_PENDING"
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"refresh": refreshState, "version_id": refresh.VersionID, "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) reorderSubscriptions(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Subscription runtime не подключён")
		return
	}
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.Subscriptions.ReorderEnabled(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) enableSubscription(writer http.ResponseWriter, request *http.Request) {
	server.setSubscriptionEnabled(writer, request, true)
}

func (server *Server) disableSubscription(writer http.ResponseWriter, request *http.Request) {
	server.setSubscriptionEnabled(writer, request, false)
}

func (server *Server) setSubscriptionEnabled(writer http.ResponseWriter, request *http.Request, enabled bool) {
	if server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Subscription runtime не подключён")
		return
	}
	id := request.PathValue("id")
	current, err := server.dependencies.Subscriptions.Get(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !enabled {
		snapshot, snapshotErr := server.dependencies.State.Get(request.Context())
		if snapshotErr != nil {
			writeInternalError(writer, snapshotErr)
			return
		}
		if snapshot.ActiveSubscriptionID == id {
			if err := server.dependencies.ModemRuntime.BlockPath(request.Context()); err != nil {
				writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось безопасно закрыть активный путь")
				return
			}
			if _, _, err := server.dependencies.State.Block(request.Context(), state.GatewayBlocked, "ACTIVE_SUBSCRIPTION_DISABLED"); err != nil {
				writeInternalError(writer, err)
				return
			}
		}
	}
	if err := server.dependencies.Subscriptions.SetEnabled(request.Context(), id, enabled); err != nil {
		writeDomainError(writer, err)
		return
	}
	probeState := "NOT_REQUIRED"
	if enabled && !current.Enabled && current.ActiveVersionID != "" {
		probeState = server.requalifyReadyModems(request.Context())
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"enabled": enabled, "qualification": probeState, "convergence": server.convergeModemRuntime(request.Context())})
}

func validateSubscriptionInput(input subscriptionInput, requireURL bool) error {
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 128 {
		return errors.New("Имя подписки обязательно и ограничено 128 символами")
	}
	if input.RefreshIntervalSeconds < 60 || input.RefreshIntervalSeconds > int64((30*24*time.Hour)/time.Second) {
		return errors.New("Интервал обновления должен быть от 60 секунд до 30 дней")
	}
	if requireURL && strings.TrimSpace(input.SourceURL) == "" {
		return errors.New("URL подписки обязателен")
	}
	return nil
}

func (server *Server) deleteSubscription(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ModemRuntime == nil || !filepath.IsAbs(server.dependencies.SubscriptionSecretRoot) || !filepath.IsAbs(server.dependencies.SubscriptionPayloadRoot) {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Subscription runtime не подключён")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "delete-disabled-subscription" {
		writeError(writer, http.StatusConflict, "CONFIRM_DELETE_SUBSCRIPTION", "Удаление подписки требует явного подтверждения")
		return
	}
	id := request.PathValue("id")
	secretRef, err := server.dependencies.Subscriptions.Delete(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	cleanup := "COMPLETE"
	if err := subscription.DeleteURLSecret(server.dependencies.SubscriptionSecretRoot, secretRef); err != nil {
		cleanup = "SECRET_CLEANUP_REQUIRED"
	}
	if err := subscription.DeleteSubscriptionPayloads(server.dependencies.SubscriptionPayloadRoot, id); err != nil {
		cleanup = "PAYLOAD_CLEANUP_REQUIRED"
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"deleted": true, "cleanup": cleanup, "convergence": server.convergeModemRuntime(request.Context())})
}

func (server *Server) requalifyReadyModems(ctx context.Context) string {
	if server.dependencies.ModemPathProbe == nil {
		return "NOT_AVAILABLE"
	}
	items, err := server.dependencies.Modems.List(ctx)
	if err != nil {
		return "RETRY_PENDING"
	}
	activeModemID := ""
	if snapshot, snapshotErr := server.dependencies.State.Get(ctx); snapshotErr == nil && snapshot.PolicyTransitionActive() {
		activeModemID = snapshot.ActiveUplinkID
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].ID == activeModemID && items[j].ID != activeModemID
	})
	probed := 0
	failed := false
	for _, item := range items {
		if !item.Enabled || item.State != modem.StateReady {
			continue
		}
		probed++
		if _, err := server.dependencies.ModemPathProbe.RequalifyModem(ctx, item.ID); err != nil {
			failed = true
		}
	}
	if failed {
		return "RETRY_PENDING"
	}
	if probed == 0 {
		return "NO_READY_MODEMS"
	}
	if server.dependencies.Reconcile != nil {
		if _, err := server.dependencies.Reconcile(ctx); err != nil {
			return "RETRY_PENDING"
		}
	}
	if snapshot, err := server.dependencies.State.Get(ctx); err == nil && snapshot.PolicyTransitionActive() {
		return "VERIFYING_POLICY"
	}
	return "COMPLETE"
}

func (server *Server) subscriptions(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Subscriptions.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	paths, err := server.readAccessPaths(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	pathsBySubscription := make(map[string][]pathReadItem, len(items))
	directPaths := make([]pathReadItem, 0)
	for _, path := range paths {
		if path.Kind == accesspolicy.MethodDirect {
			directPaths = append(directPaths, path)
			continue
		}
		pathsBySubscription[path.SubscriptionID] = append(pathsBySubscription[path.SubscriptionID], path)
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]any{
			"id": item.ID, "number": item.DisplayNumber, "name": item.Name, "source_type": item.SourceType,
			"source_configured": item.SourceSecretRef != "", "enabled": item.Enabled,
			"priority": item.Priority, "auto_refresh": item.AutoRefresh,
			"refresh_interval_seconds":            item.RefreshIntervalSeconds,
			"fallback_when_named_candidates_fail": item.FallbackWhenNamedCandidatesFail,
			"status":                              item.Status, "active_version_id": item.ActiveVersionID,
			"last_refresh_at": item.LastRefreshAt, "last_success_at": item.LastSuccessAt,
			"paths": pathsBySubscription[item.ID],
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result, "direct_paths": directPaths})
}

func (server *Server) nodes(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Nodes.ListActive(request.Context(), request.URL.Query().Get("subscription_id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		modems := make([]map[string]any, 0, len(item.Modems))
		for _, status := range item.Modems {
			modems = append(modems, map[string]any{
				"path_id": status.PathID, "modem_id": status.ModemID, "modem_number": status.ModemNumber, "modem_name": status.ModemName,
				"path_state": status.PathState, "qualification_state": status.QualificationState,
				"latency_ms": status.LatencyMS, "failure_code": status.FailureCode, "expires_at": status.ExpiresAt,
				"current_evidence": status.CurrentEvidence,
			})
		}
		result = append(result, map[string]any{
			"id": item.ID, "version_id": item.VersionID,
			"subscription_id": item.SubscriptionID, "subscription_number": item.SubscriptionNumber, "subscription_name": item.SubscriptionName,
			"external_name": item.ExternalName, "proxy_type": item.ProxyType, "fingerprint": item.Fingerprint, "candidate": item.Enabled,
			"selection_override": item.SelectionOverride, "candidate_source": item.CandidateSource,
			"preferred_rank": item.PreferredRank, "user_label": item.UserLabel,
			"matched_matcher_id": item.MatchedMatcherID, "modems": modems,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
}

func (server *Server) updateNode(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		SelectionOverride string `json:"selection_override"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	subscriptionID, err := server.dependencies.Nodes.SetOverride(request.Context(), request.PathValue("id"), input.SelectionOverride)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"subscription_id": subscriptionID, "qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) reorderPreferredNodes(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	subscriptionID := request.PathValue("id")
	nodes, err := server.dependencies.Nodes.ListActive(request.Context(), subscriptionID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	byID := make(map[string]subscription.ActiveNode, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	fingerprints := make([]string, 0, len(input.IDs))
	seen := make(map[string]struct{}, len(input.IDs))
	for _, id := range input.IDs {
		node, exists := byID[id]
		if !exists || !node.Enabled || node.SelectionOverride == subscription.OverrideExclude {
			writeDomainError(writer, store.ErrPrioritySetMismatch)
			return
		}
		if _, duplicate := seen[id]; duplicate {
			writeDomainError(writer, store.ErrPrioritySetMismatch)
			return
		}
		seen[id] = struct{}{}
		fingerprints = append(fingerprints, node.Fingerprint)
	}
	if err := server.dependencies.NodePreferences.ReorderPreferred(request.Context(), subscriptionID, fingerprints); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"subscription_id": subscriptionID, "preferred_node_ids": input.IDs,
		"applies_on": "NEXT_QUALIFICATION_OR_FAILOVER", "active_path_preserved": true,
	})
}

func (server *Server) refreshSubscription(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.SubscriptionDispatch != nil {
		principal := request.Context().Value(principalKey).(auth.Principal)
		result, err := server.dependencies.SubscriptionDispatch.Enqueue(request.Context(), request.PathValue("id"), "USER:"+principal.Username)
		if err != nil {
			server.writeRefreshDispatchError(writer, err)
			return
		}
		writeJSON(writer, http.StatusAccepted, map[string]any{"operation_id": result.OperationID, "subscription_id": result.SubscriptionID, "joined": result.Joined})
		return
	}
	if server.dependencies.SubscriptionRefresh == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Обновление подписок не подключено")
		return
	}
	result, err := server.dependencies.SubscriptionRefresh.RefreshOne(request.Context(), request.PathValue("id"), true)
	if err != nil {
		switch {
		case errors.Is(err, subscription.ErrRefreshInProgress):
			writeError(writer, http.StatusConflict, "REFRESH_IN_PROGRESS", "Обновление подписки уже выполняется")
		case errors.Is(err, subscription.ErrSubscriptionDisabled):
			writeError(writer, http.StatusConflict, "SUBSCRIPTION_DISABLED", "Подписка отключена")
		case errors.Is(err, subscription.ErrSourceIsNotRefreshable):
			writeError(writer, http.StatusConflict, "SOURCE_NOT_REFRESHABLE", "Источник подписки нельзя обновить по URL")
		default:
			writeError(writer, http.StatusBadGateway, "REFRESH_FAILED", "Новая версия не прошла загрузку или проверку путей")
		}
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) refreshSubscriptions(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.SubscriptionDispatch == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Асинхронное обновление подписок не подключено")
		return
	}
	items, err := server.dependencies.Subscriptions.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	accepted := make([]map[string]any, 0, len(items))
	rejected := make([]map[string]any, 0)
	for _, item := range items {
		if item.SourceType != "url" {
			continue
		}
		result, enqueueErr := server.dependencies.SubscriptionDispatch.Enqueue(request.Context(), item.ID, "USER:"+principal.Username)
		if enqueueErr != nil {
			code := "REFRESH_REJECTED"
			if errors.Is(enqueueErr, subscription.ErrRefreshDispatcherBusy) {
				code = "DISPATCHER_BUSY"
			}
			rejected = append(rejected, map[string]any{"subscription_id": item.ID, "code": code})
			continue
		}
		accepted = append(accepted, map[string]any{"subscription_id": item.ID, "operation_id": result.OperationID, "joined": result.Joined})
	}
	status := http.StatusAccepted
	if len(accepted) == 0 && len(rejected) > 0 {
		status = http.StatusServiceUnavailable
	}
	writeJSON(writer, status, map[string]any{"accepted": accepted, "rejected": rejected})
}

func (server *Server) writeRefreshDispatchError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, subscription.ErrRefreshDispatcherBusy):
		writer.Header().Set("Retry-After", "2")
		writeError(writer, http.StatusServiceUnavailable, "REFRESH_QUEUE_BUSY", "Очередь обновлений занята; повторите запрос")
	case errors.Is(err, subscription.ErrSubscriptionDisabled):
		writeError(writer, http.StatusConflict, "SUBSCRIPTION_DISABLED", "Подписка отключена")
	case errors.Is(err, subscription.ErrSourceIsNotRefreshable):
		writeError(writer, http.StatusConflict, "SOURCE_NOT_REFRESHABLE", "Источник подписки нельзя обновить по URL")
	case errors.Is(err, store.ErrNotFound):
		writeDomainError(writer, err)
	default:
		writeError(writer, http.StatusServiceUnavailable, "REFRESH_DISPATCH_FAILED", "Не удалось поставить обновление в безопасную очередь")
	}
}

func (server *Server) matrix(writer http.ResponseWriter, request *http.Request) {
	items, err := server.readAccessPaths(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) pathNodes(writer http.ResponseWriter, request *http.Request) {
	limit, err := parsePageLimit(request, 50)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_PAGINATION", "Некорректный размер страницы")
		return
	}
	page, err := server.dependencies.Paths.ListPathNodes(request.Context(), request.PathValue("id"), limit, request.URL.Query().Get("after_node_id"), server.now())
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	items := make([]map[string]any, 0, len(page.Items))
	for _, item := range page.Items {
		reason := item.FailureCode
		if reason == "" {
			switch item.QualificationState {
			case pathmatrix.NodeBypassQualified:
				reason = "FRESH_QUALIFIED"
			case pathmatrix.EvidenceStale:
				reason = "RESULT_STALE"
			default:
				reason = item.QualificationState
			}
		}
		items = append(items, map[string]any{
			"path_id": item.PathID, "node_id": item.NodeID, "external_name": item.ExternalName,
			"proxy_type": item.ProxyType, "candidate_source": item.CandidateSource,
			"qualification_state": item.QualificationState, "reason_code": reason,
			"qualification_generation": item.QualificationGeneration, "route_generation": item.RouteGeneration,
			"expires_at": item.QualificationExpiresAt, "latency_ms": item.LatencyMS,
			"last_success_at": item.LastSuccessAt, "last_failure_at": item.LastFailureAt,
			"selected": item.Selected, "active": item.Active, "current_evidence": item.CurrentEvidence,
			"can_activate":        item.CurrentEvidence && item.QualificationState == pathmatrix.NodeBypassQualified,
			"target_result_count": item.TargetResultCount,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "next_after_node_id": page.NextAfterNodeID})
}

func (server *Server) pathNodeTargets(writer http.ResponseWriter, request *http.Request) {
	limit, err := parsePageLimit(request, 50)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_PAGINATION", "Некорректный размер страницы")
		return
	}
	cursor, err := decodeTargetCursor(request.URL.Query().Get("cursor"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_PAGINATION", "Некорректный cursor результатов")
		return
	}
	page, err := server.dependencies.Paths.ListNodeTargets(request.Context(), request.PathValue("id"), request.PathValue("node_id"), limit, cursor, server.now())
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	items := make([]map[string]any, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, map[string]any{
			"target_id": item.TargetID, "name": item.Name, "priority": item.Priority,
			"required": item.Required, "success_mode": item.SuccessMode, "state": item.State,
			"latency_ms": item.LatencyMS, "http_status": item.HTTPStatus,
			"error_code": item.ErrorCode, "checked_at": item.CheckedAt, "expires_at": item.ExpiresAt,
			"policy_generation": item.PolicyGeneration, "route_generation": item.RouteGeneration,
			"current_evidence": item.CurrentEvidence,
		})
	}
	nextCursor := ""
	if page.NextCursor != nil {
		nextCursor = encodeTargetCursor(*page.NextCursor)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor})
}

func (server *Server) qualifyPath(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.PathOperations == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Проверка путей не подключена")
		return
	}
	result, err := server.dependencies.PathOperations.QualifyPath(request.Context(), request.PathValue("id"))
	if err != nil {
		writePathOperationError(writer, err)
		return
	}
	response := pathOperationResponse(result, false)
	response["convergence"] = server.convergePathRuntime(request.Context())
	writeJSON(writer, http.StatusAccepted, response)
}

func (server *Server) probePathNode(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.PathOperations == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Проверка узлов не подключена")
		return
	}
	result, err := server.dependencies.PathOperations.ProbeNode(request.Context(), request.PathValue("id"), request.PathValue("node_id"))
	if err != nil {
		writePathOperationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, pathOperationResponse(result, true))
}

func (server *Server) qualifyPathNode(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.PathOperations == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Квалификация узлов не подключена")
		return
	}
	result, err := server.dependencies.PathOperations.QualifyNode(request.Context(), request.PathValue("id"), request.PathValue("node_id"))
	if err != nil {
		writePathOperationError(writer, err)
		return
	}
	response := pathOperationResponse(result, false)
	response["convergence"] = server.convergePathRuntime(request.Context())
	writeJSON(writer, http.StatusAccepted, response)
}

func (server *Server) activatePath(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.PathActivator == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Ручная активация пути не подключена")
		return
	}
	var input struct {
		NodeID string `json:"node_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result, err := server.dependencies.PathActivator.ActivateExact(request.Context(), request.PathValue("id"), input.NodeID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusConflict, "NODE_NOT_FRESH", "Узел не имеет свежего успешного результата в текущей политике и маршруте")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadGateway, "PATH_ACTIVATION_FAILED", "Безопасная активация пути не завершена; проверьте состояние Gateway")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"action": result.Action, "path_id": result.Candidate.PathID,
		"node_id": result.Candidate.NodeID, "uplink_id": result.Candidate.UplinkID,
		"modem_id":          result.Candidate.ModemID,
		"subscription_id":   result.Candidate.SubscriptionID,
		"policy_generation": result.Candidate.PolicyGeneration,
		"route_generation":  result.Candidate.RouteGeneration,
	})
}

func pathOperationResponse(operation candidateruntime.PathOperationResult, includeTargetResults bool) map[string]any {
	result := operation.Result
	response := map[string]any{
		"path_id": operation.PathID, "node_id": operation.NodeID,
		"authoritative": operation.Authoritative, "state": result.State,
		"transport_state": result.TransportState, "selected_node_id": result.SelectedNodeID,
		"candidate_nodes": result.CandidateNodes, "qualified_nodes": result.QualifiedNodes,
		"required_targets_passed": result.RequiredTargetsPassed,
		"required_targets_total":  result.RequiredTargetsTotal, "latency_ms": result.LatencyMS,
		"policy_generation": operation.PolicyGeneration, "route_generation": operation.RouteGeneration,
		"checked_at": operation.CheckedAt.UTC().Format(time.RFC3339Nano),
		"expires_at": operation.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	if !includeTargetResults || len(result.Nodes) == 0 {
		return response
	}
	node := result.Nodes[0]
	targets := make([]map[string]any, 0, len(node.Targets))
	for _, target := range node.Targets {
		targets = append(targets, map[string]any{
			"target_id": target.TargetID, "required": target.Required, "state": target.State,
			"latency_ms": target.LatencyMS, "http_status": target.HTTPStatus, "error_code": target.ErrorCode,
		})
	}
	response["node"] = map[string]any{
		"node_id": node.NodeID, "state": node.State, "latency_ms": node.AggregateLatencyMS,
		"required_passed": node.RequiredPassed, "required_total": node.RequiredTotal,
		"transport": map[string]any{"state": node.Transport.State, "latency_ms": node.Transport.LatencyMS, "http_status": node.Transport.HTTPStatus, "error_code": node.Transport.ErrorCode},
		"targets":   targets,
	}
	return response
}

func (server *Server) convergePathRuntime(ctx context.Context) string {
	if server.dependencies.Reconcile == nil {
		return "NOT_AVAILABLE"
	}
	result, err := server.dependencies.Reconcile(ctx)
	if err != nil {
		return "RETRY_PENDING"
	}
	if value, ok := result.(reconcile.Result); ok {
		return value.Action
	}
	return "COMPLETE"
}

func writePathOperationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, http.StatusNotFound, "NOT_FOUND", "Путь или узел не найден")
	case errors.Is(err, candidateruntime.ErrPathNotReady):
		writeError(writer, http.StatusConflict, "PATH_NOT_READY", "Модем или подписка выбранного пути не готовы")
	case errors.Is(err, candidateruntime.ErrNodeNotEligible):
		writeError(writer, http.StatusConflict, "NODE_NOT_ELIGIBLE", "Узел не входит в активный набор кандидатов подписки")
	case errors.Is(err, store.ErrStaleGeneration):
		writeError(writer, http.StatusConflict, "STALE_GENERATION", "Политика или маршрут изменились во время проверки")
	default:
		writeError(writer, http.StatusBadGateway, "PATH_OPERATION_FAILED", "Проверка пути не завершена; предыдущая рабочая конфигурация сохранена")
	}
}

func parsePageLimit(request *http.Request, defaultLimit int) (int, error) {
	limit := defaultLimit
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return 0, err
		}
		limit = parsed
	}
	if limit <= 0 || limit > 200 {
		return 0, errors.New("limit must be 1..200")
	}
	return limit, nil
}

func encodeTargetCursor(cursor pathmatrix.TargetCursor) string {
	value := strconv.FormatInt(cursor.Priority, 10) + "\n" + cursor.ID
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeTargetCursor(value string) (*pathmatrix.TargetCursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 512 {
		return nil, errors.New("target cursor is too long")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(string(decoded), "\n", 2)
	if len(parts) != 2 || parts[1] == "" || len(parts[1]) > 256 {
		return nil, errors.New("invalid target cursor")
	}
	priority, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || priority < 0 {
		return nil, errors.New("invalid target cursor priority")
	}
	return &pathmatrix.TargetCursor{Priority: priority, ID: parts[1]}, nil
}

func (server *Server) targets(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Targets.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

type targetInput struct {
	Name                  string `json:"name"`
	Kind                  string `json:"kind"`
	Value                 string `json:"value"`
	Enabled               bool   `json:"enabled"`
	Required              bool   `json:"required"`
	TargetClass           string `json:"target_class"`
	TimeoutSeconds        int64  `json:"timeout_seconds"`
	SuccessMode           string `json:"success_mode"`
	ExpectedStatus        string `json:"expected_status"`
	ExpectedBodySubstring string `json:"expected_body_substring"`
}

func (server *Server) createTarget(writer http.ResponseWriter, request *http.Request) {
	var input targetInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	created, err := server.dependencies.Targets.Create(request.Context(), bypass.CreateInput{ID: newID("target"), Name: input.Name, Kind: input.Kind, Value: input.Value, Required: input.Required, TargetClass: input.TargetClass, Timeout: time.Duration(input.TimeoutSeconds) * time.Second, SuccessMode: input.SuccessMode, ExpectedStatus: input.ExpectedStatus, ExpectedBodySubstring: input.ExpectedBodySubstring})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"target": created, "qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) updateTarget(writer http.ResponseWriter, request *http.Request) {
	var input targetInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	err := server.dependencies.Targets.Update(request.Context(), request.PathValue("id"), bypass.UpdateInput{Name: input.Name, Kind: input.Kind, Value: input.Value, Enabled: input.Enabled, Required: input.Required, TargetClass: input.TargetClass, Timeout: time.Duration(input.TimeoutSeconds) * time.Second, SuccessMode: input.SuccessMode, ExpectedStatus: input.ExpectedStatus, ExpectedBodySubstring: input.ExpectedBodySubstring, AllowNoRequired: confirmsNoRequiredTargets(request)})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) deleteTarget(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if err := server.dependencies.Targets.Delete(request.Context(), id, confirmsNoRequiredTargets(request)); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) reorderTargets(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.Targets.ReorderEnabled(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) probeTarget(writer http.ResponseWriter, request *http.Request) {
	target, err := server.dependencies.Targets.Get(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !target.Enabled {
		writeError(writer, http.StatusConflict, "TARGET_DISABLED", "Сначала включите сервер проверки")
		return
	}
	if target.TargetClass == bypass.TargetClassServiceEndpoint {
		writeError(writer, http.StatusConflict, "SERVICE_TARGET_SCOPE", "Служебная цель проверяется подсистемой обновлений и не определяет пользовательский доступ в Internet")
		return
	}
	if server.dependencies.DirectPathProbe == nil {
		writeError(writer, http.StatusNotImplemented, "DIRECT_PROBE_NOT_AVAILABLE", "Прямая проверка физических выходов не подключена")
		return
	}
	direct, err := server.dependencies.DirectPathProbe.ProbeAllNow(request.Context())
	if err != nil {
		writeError(writer, http.StatusBadGateway, "DIRECT_PROBE_FAILED", "Прямая проверка не завершена; ранее подтверждённое состояние сохранено")
		return
	}
	vpnQualification := "NOT_APPLICABLE"
	scope := "DIRECT_UPLINKS"
	if target.TargetClass == bypass.TargetClassGlobalRequired || target.TargetClass == bypass.TargetClassGlobalOptional {
		vpnQualification = server.requalifyReadyModems(request.Context())
		scope = "DIRECT_AND_VPN_ELIGIBLE_PATHS"
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"target_id": target.ID, "target_class": target.TargetClass, "scope": scope,
		"direct_probe": map[string]any{
			"eligible": direct.Due, "probed": direct.Probed, "published": direct.Published,
			"deferred_by_budget": direct.Deferred,
		},
		"vpn_qualification": vpnQualification,
		"convergence":       server.convergeAccessPolicy(request.Context()),
	})
}

func confirmsNoRequiredTargets(request *http.Request) bool {
	value := request.Header.Get("X-Confirm-Destructive")
	return value == "remove-last-required-target" || value == "delete-last-required-target"
}

func (server *Server) matchers(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Matchers.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

type matcherMutationInput struct {
	Pattern      string `json:"pattern"`
	Type         string `json:"type"`
	Enabled      bool   `json:"enabled"`
	PreviewToken string `json:"preview_token"`
}

func (server *Server) createMatcher(writer http.ResponseWriter, request *http.Request) {
	var input matcherMutationInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	previewInput := subscription.MatcherPreviewInput{Pattern: strings.TrimSpace(input.Pattern), Type: input.Type, Enabled: true}
	if input.Type == subscription.MatcherRegex && !server.validMatcherPreview(request.Context(), previewInput, input.PreviewToken) {
		writeError(writer, http.StatusConflict, "MATCHER_PREVIEW_REQUIRED", "Regex необходимо предварительно проверить на текущих VPN-серверах")
		return
	}
	created, err := server.dependencies.Matchers.Create(request.Context(), subscription.MatcherCreateInput{ID: newID("matcher"), Pattern: input.Pattern, Type: input.Type})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"matcher": created, "qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) updateMatcher(writer http.ResponseWriter, request *http.Request) {
	var input matcherMutationInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	previewInput := subscription.MatcherPreviewInput{ID: request.PathValue("id"), Pattern: strings.TrimSpace(input.Pattern), Type: input.Type, Enabled: input.Enabled}
	if input.Type == subscription.MatcherRegex && !server.validMatcherPreview(request.Context(), previewInput, input.PreviewToken) {
		writeError(writer, http.StatusConflict, "MATCHER_PREVIEW_REQUIRED", "Regex необходимо предварительно проверить на текущих VPN-серверах")
		return
	}
	if err := server.dependencies.Matchers.Update(request.Context(), request.PathValue("id"), subscription.MatcherUpdateInput{Pattern: input.Pattern, Type: input.Type, Enabled: input.Enabled}); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) deleteMatcher(writer http.ResponseWriter, request *http.Request) {
	if err := server.dependencies.Matchers.Delete(request.Context(), request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) reorderMatchers(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := server.dependencies.Matchers.ReorderEnabled(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"qualification": server.requalifyReadyModems(request.Context())})
}

func (server *Server) previewMatcher(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		MatcherID string `json:"matcher_id"`
		Pattern   string `json:"pattern"`
		Type      string `json:"type"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	previewInput := subscription.MatcherPreviewInput{ID: strings.TrimSpace(input.MatcherID), Pattern: strings.TrimSpace(input.Pattern), Type: input.Type, Enabled: enabled}
	items, token, err := server.buildMatcherPreview(request.Context(), previewInput)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "preview_token": token})
}

func (server *Server) validMatcherPreview(ctx context.Context, input subscription.MatcherPreviewInput, token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	_, expected, err := server.buildMatcherPreview(ctx, input)
	return err == nil && hmac.Equal([]byte(expected), []byte(strings.TrimSpace(token)))
}

func (server *Server) buildMatcherPreview(ctx context.Context, input subscription.MatcherPreviewInput) ([]subscription.MatcherPreviewSubscription, string, error) {
	items, err := server.dependencies.Matchers.Preview(ctx, input)
	if err != nil {
		return nil, "", err
	}
	current, err := server.dependencies.Matchers.List(ctx)
	if err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(struct {
		Input    subscription.MatcherPreviewInput
		Matchers []subscription.Matcher
		Items    []subscription.MatcherPreviewSubscription
	}{Input: input, Matchers: current, Items: items})
	if err != nil {
		return nil, "", errors.New("encode matcher preview proof failed")
	}
	mac := hmac.New(sha256.New, server.matcherPreviewSecret)
	_, _ = mac.Write(payload)
	return items, hex.EncodeToString(mac.Sum(nil)), nil
}

func (server *Server) reorder(writer http.ResponseWriter, request *http.Request, operation func(context.Context, []string) error) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := operation(request.Context(), input.IDs); err != nil {
		writeDomainError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) events(writer http.ResponseWriter, request *http.Request) {
	limit := 100
	before := int64(0)
	var err error
	if raw := request.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if err == nil {
		if raw := request.URL.Query().Get("before_id"); raw != "" {
			before, err = strconv.ParseInt(raw, 10, 64)
		}
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_PAGINATION", "Некорректная пагинация")
		return
	}
	items, err := server.dependencies.State.ListEvents(request.Context(), limit, before)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) operations(writer http.ResponseWriter, request *http.Request) {
	limit, err := parsePageLimit(request, 50)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_PAGINATION", "Некорректный размер списка операций")
		return
	}
	items, err := server.dependencies.Operations.List(request.Context(), limit)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, operationResponse(item, false))
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
}

func (server *Server) operation(writer http.ResponseWriter, request *http.Request) {
	item, err := server.dependencies.Operations.Get(request.Context(), request.PathValue("id"), true)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, operationResponse(item, true))
}

func (server *Server) clearCompletedOperations(writer http.ResponseWriter, request *http.Request) {
	limit, err := parsePageLimit(request, 200)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_PAGINATION", "Некорректный лимит очистки операций")
		return
	}
	deleted, err := server.dependencies.Operations.ClearCompleted(request.Context(), limit)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"deleted": deleted})
}

func operationResponse(item operations.Operation, includeSteps bool) map[string]any {
	result := map[string]any{
		"id": item.ID, "kind": item.Kind, "scope_type": item.ScopeType,
		"scope_id": item.ScopeID, "status": item.Status,
		"requested_by": item.RequestedBy, "summary_code": item.SummaryCode,
		"created_at": item.CreatedAt, "started_at": item.StartedAt,
		"finished_at": item.FinishedAt, "updated_at": item.UpdatedAt,
	}
	if !includeSteps {
		return result
	}
	steps := make([]map[string]any, 0, len(item.Steps))
	for _, step := range item.Steps {
		var details any = map[string]any{}
		if err := json.Unmarshal([]byte(step.DetailsJSON), &details); err != nil {
			details = map[string]any{}
		}
		steps = append(steps, map[string]any{
			"sequence": step.Sequence, "occurred_at": step.OccurredAt,
			"severity": step.Severity, "stage": step.Stage,
			"code": step.Code, "message": step.Message, "details": details,
		})
	}
	result["steps"] = steps
	return result
}

func (server *Server) periodicHealth(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.PeriodicHealth == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Периодические проверки путей не подключены")
		return
	}
	statuses, err := server.dependencies.PeriodicHealth.List(request.Context())
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	paths, err := server.dependencies.Paths.List(request.Context())
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	pathByID := make(map[string]pathmatrix.Cell, len(paths))
	for _, path := range paths {
		pathByID[path.ID] = path
	}
	items := make([]map[string]any, 0, len(statuses))
	for _, status := range statuses {
		path := pathByID[status.PathID]
		items = append(items, map[string]any{
			"path_id": status.PathID, "probe_class": status.ProbeClass,
			"modem_id": path.ModemID, "modem_number": path.ModemDisplayNumber, "modem_name": path.ModemName,
			"subscription_id": path.SubscriptionID, "subscription_name": path.SubscriptionName,
			"path_state": path.State, "next_probe_at": status.NextProbeAt, "last_probe_at": status.LastProbeAt,
			"last_result": status.LastResult, "consecutive_successes": status.Successes,
			"consecutive_failures": status.Failures, "deferred_reason": status.DeferredReason,
		})
	}
	config := server.dependencies.PeriodicHealthConfig
	response := map[string]any{
		"items": items,
		"config": map[string]any{
			"poll_interval_seconds":    int64(config.PollInterval / time.Second),
			"active_interval_seconds":  int64(config.ActiveInterval / time.Second),
			"standby_interval_seconds": int64(config.StandbyInterval / time.Second),
			"failure_threshold":        config.FailureThreshold, "success_threshold": config.SuccessThreshold,
			"jitter_percent": config.JitterPercent, "due_limit": config.DueLimit,
			"confirmation_limit": config.ConfirmationLimit,
		},
		"budgets": []map[string]any{},
	}
	if server.dependencies.ProbeBudget != nil {
		modems, err := server.dependencies.Modems.List(request.Context())
		if err != nil {
			writeDomainError(writer, err)
			return
		}
		budgets := make([]map[string]any, 0, len(modems))
		for _, item := range modems {
			usage := server.dependencies.ProbeBudget.Snapshot(item.ID)
			budgets = append(budgets, map[string]any{
				"modem_id": item.ID, "modem_number": item.DisplayNumber, "modem_name": item.Name,
				"day": usage.Day, "observed_bytes": usage.ObservedBytes, "reserved_bytes": usage.ReservedBytes,
				"requests": usage.Requests, "overage_bytes": usage.OverageBytes,
			})
		}
		limits := server.dependencies.ProbeBudget.Limits()
		response["budgets"] = budgets
		response["budget_policy"] = map[string]any{
			"daily_soft_limit_bytes": limits.DailySoftLimitBytes, "standby_limit_bytes": limits.StandbyLimitBytes,
			"active_failover_reserve_percent": limits.ActiveFailoverReservePercent,
			"max_concurrency":                 limits.MaxConcurrency, "max_concurrency_per_modem": limits.MaxConcurrencyPerModem,
			"max_requests_per_window":     limits.MaxRequestsPerWindow,
			"request_window_seconds":      int64(limits.RequestWindow / time.Second),
			"min_target_interval_seconds": int64(limits.MinTargetInterval / time.Second),
		}
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) loggingSettings(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Logging == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Настройки логирования не подключены")
		return
	}
	server.writeLoggingSettings(writer, request.Context(), server.dependencies.Logging.Snapshot(), "NOT_REQUESTED")
}

func (server *Server) watchdogSettings(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Watchdog == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Настройки самоконтроля не подключены")
		return
	}
	policy, err := server.dependencies.Watchdog.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"policy": policy,
		"limits": map[string]any{
			"check_interval_seconds_min":            watchdog.MinimumCheckIntervalSeconds,
			"check_interval_seconds_max":            watchdog.MaximumCheckIntervalSeconds,
			"failure_threshold_min":                 watchdog.MinimumFailureThreshold,
			"failure_threshold_max":                 watchdog.MaximumFailureThreshold,
			"success_threshold_min":                 watchdog.MinimumSuccessThreshold,
			"success_threshold_max":                 watchdog.MaximumSuccessThreshold,
			"restart_cooldown_seconds_min":          watchdog.MinimumRestartCooldown,
			"restart_cooldown_seconds_max":          watchdog.MaximumRestartCooldown,
			"max_restarts_per_component_min":        watchdog.MinimumRestartBudget,
			"max_restarts_per_component_max":        watchdog.MaximumRestartBudget,
			"restart_window_seconds_min":            watchdog.MinimumRestartWindow,
			"restart_window_seconds_max":            watchdog.MaximumRestartWindow,
			"reboot_after_critical_seconds_min":     watchdog.MinimumRebootCritical,
			"reboot_after_critical_seconds_max":     watchdog.MaximumRebootCritical,
			"max_reboots_per_24h_min":               watchdog.MinimumRebootBudget,
			"max_reboots_per_24h_max":               watchdog.MaximumRebootBudget,
			"reboot_grace_seconds_min":              watchdog.MinimumRebootGrace,
			"reboot_grace_seconds_max":              watchdog.MaximumRebootGrace,
			"worker_stale_seconds_min":              watchdog.MinimumWorkerStaleSeconds,
			"worker_stale_seconds_max":              watchdog.MaximumWorkerStaleSeconds,
			"wireguard_handshake_stale_seconds_min": watchdog.MinimumWGHandshakeStale,
			"wireguard_handshake_stale_seconds_max": watchdog.MaximumWGHandshakeStale,
			"backup_max_age_hours_min":              watchdog.MinimumBackupMaxAgeHours,
			"backup_max_age_hours_max":              watchdog.MaximumBackupMaxAgeHours,
			"database_wal_max_bytes_min":            watchdog.MinimumDatabaseWALBytes,
			"database_wal_max_bytes_max":            watchdog.MaximumDatabaseWALBytes,
			"minimum_disk_free_bytes_min":           watchdog.MinimumDiskFreeBytesFloor,
			"minimum_disk_free_bytes_max":           watchdog.MaximumDiskFreeBytesFloor,
			"minimum_memory_available_bytes_min":    watchdog.MinimumMemoryBytesFloor,
			"minimum_memory_available_bytes_max":    watchdog.MaximumMemoryBytesFloor,
			"minimum_resource_percent_min":          watchdog.MinimumResourcePercent,
			"minimum_resource_percent_max":          watchdog.MaximumResourcePercent,
		},
		"components": watchdogComponentSettings(),
		"invariants": map[string]any{
			"host_reboot_default":             false,
			"external_outage_can_reboot":      false,
			"arbitrary_units_or_commands":     false,
			"firewall_guard_disableable":      false,
			"durable_budgets_reset_on_update": false,
		},
	})
}

func (server *Server) watchdogStatus(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Watchdog == nil || server.dependencies.WatchdogStatus == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Самоконтроль не подключён")
		return
	}
	policy, err := server.dependencies.Watchdog.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	status, err := server.dependencies.WatchdogStatus.Read()
	if err == nil {
		err = status.ValidateFresh(server.now(), watchdog.MaximumStatusAge(policy))
	}
	if err != nil {
		writeJSON(writer, http.StatusOK, map[string]any{
			"runtime_state": "UNAVAILABLE", "error_code": "WATCHDOG_STATUS_UNAVAILABLE",
			"effective_policy": policy, "components": []watchdog.ComponentStatus{},
		})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"runtime_state": "AVAILABLE", "effective_policy": policy,
		"status": status, "components": status.Components,
	})
}

func watchdogComponentSettings() []map[string]any {
	result := make([]map[string]any, 0)
	for _, spec := range watchdog.ComponentSpecs() {
		modes := []string{watchdog.RecoveryModeMonitorOnly}
		if spec.Reconcileable {
			modes = append(modes, watchdog.RecoveryModeReconcile)
		}
		if spec.Restartable {
			modes = append(modes, watchdog.RecoveryModeRestart)
		}
		result = append(result, map[string]any{
			"id": spec.ID, "label": spec.Label, "allowed_recovery_modes": modes,
			"reboot_eligible": spec.RebootEligible,
		})
	}
	return result
}

func (server *Server) systemPowerCapabilities(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Power == nil {
		writeError(writer, http.StatusNotImplemented, "POWER_NOT_AVAILABLE", "Управление питанием не подключено")
		return
	}
	capabilities, err := server.dependencies.Power.PowerCapabilities(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "POWER_CAPABILITIES_UNAVAILABLE", "Не удалось безопасно определить возможности управления питанием")
		return
	}
	latest, exists, err := (power.Repository{Database: server.dependencies.Database}).Latest(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	response := map[string]any{"capabilities": capabilities, "latest_operation": nil}
	if exists {
		response["latest_operation"] = operationResponse(latest, true)
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) rebootSystem(writer http.ResponseWriter, request *http.Request) {
	server.executeSystemPower(writer, request, power.ActionReboot)
}

func (server *Server) shutdownSystem(writer http.ResponseWriter, request *http.Request) {
	server.executeSystemPower(writer, request, power.ActionShutdown)
}

func (server *Server) powerCycleSystem(writer http.ResponseWriter, request *http.Request) {
	server.executeSystemPower(writer, request, power.ActionRTCPowerCycle)
}

func (server *Server) executeSystemPower(writer http.ResponseWriter, request *http.Request, action power.Action) {
	if server.dependencies.Power == nil {
		writeError(writer, http.StatusNotImplemented, "POWER_NOT_AVAILABLE", "Управление питанием не подключено")
		return
	}
	var input struct {
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
		DelaySeconds int    `json:"delay_seconds"`
	}
	if err := decodeJSON(request, &input); err != nil || len(input.Password) > 1024 || len(input.Confirmation) > 64 {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный запрос управления питанием")
		return
	}
	command := power.Command{Action: action, DelaySeconds: input.DelaySeconds}
	if err := command.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_POWER_COMMAND", err.Error())
		return
	}
	if input.Confirmation != power.ExpectedConfirmation(action) {
		writeError(writer, http.StatusBadRequest, "POWER_CONFIRMATION_MISMATCH", "Введите точную показанную фразу подтверждения")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			writer.Header().Set("Retry-After", "2")
			writeError(writer, http.StatusTooManyRequests, "REAUTH_RATE_LIMITED", "Слишком много неверных попыток; повторите позже")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "REAUTH_FAILED", "Текущий пароль указан неверно")
		case errors.Is(err, auth.ErrInvalidSession):
			writeError(writer, http.StatusUnauthorized, "SESSION_INVALID", "Сессия истекла или отозвана")
		default:
			writeInternalError(writer, err)
		}
		return
	}
	if !server.reservePowerAction() {
		writeError(writer, http.StatusConflict, "POWER_BLOCKED_BY_MAINTENANCE", "Дождитесь завершения активной операции установки, обновления, восстановления, сети или резервного копирования")
		return
	}
	repository := power.Repository{Database: server.dependencies.Database}
	operation, err := repository.Start(request.Context(), principal.UserID, command)
	if err != nil {
		server.releasePowerAction()
		if errors.Is(err, power.ErrOperationInProgress) {
			writeError(writer, http.StatusConflict, "POWER_OPERATION_IN_PROGRESS", "Другая операция питания уже выполняется")
			return
		}
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.Power.ExecutePower(request.Context(), command); err != nil {
		server.releasePowerAction()
		reason := "POWER_ACTION_FAILED"
		status, code, message := http.StatusBadGateway, reason, "Команду питания не удалось безопасно отправить"
		switch {
		case errors.Is(err, power.ErrMaintenanceActive):
			reason, status, code, message = "POWER_BLOCKED_BY_MAINTENANCE", http.StatusConflict, "POWER_BLOCKED_BY_MAINTENANCE", "Сначала завершите установку, обновление, восстановление или безопасное применение сети"
		case errors.Is(err, power.ErrOperationInProgress):
			reason, status, code, message = "POWER_OPERATION_IN_PROGRESS", http.StatusConflict, "POWER_OPERATION_IN_PROGRESS", "Другая операция питания уже выполняется"
		case errors.Is(err, power.ErrUnavailable):
			reason, status, code, message = "POWER_ACTION_UNAVAILABLE", http.StatusConflict, "POWER_ACTION_UNAVAILABLE", "Эта операция питания недоступна на данном оборудовании"
		case errors.Is(err, power.ErrInvalidCommand):
			reason, status, code, message = "INVALID_POWER_COMMAND", http.StatusBadRequest, "INVALID_POWER_COMMAND", "Некорректные параметры операции питания"
		}
		_, _ = repository.Finish(request.Context(), operation.ID, false, reason)
		writeError(writer, status, code, message)
		return
	}
	finished, err := repository.Finish(request.Context(), operation.ID, true, "")
	if err != nil {
		// systemd already accepted the action. Do not claim it failed merely
		// because the host began shutting down before SQLite acknowledgement.
		writeJSON(writer, http.StatusAccepted, map[string]any{"operation_id": operation.ID, "action": action, "status": "DISPATCHED_STATUS_PENDING"})
		return
	}
	writeJSON(writer, http.StatusAccepted, operationResponse(finished, true))
}

func (server *Server) uninstallImpact(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Removal == nil {
		writeError(writer, http.StatusNotImplemented, "UNINSTALL_NOT_AVAILABLE", "Безопасное удаление не подключено")
		return
	}
	impact, err := server.dependencies.Removal.UninstallImpact(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "UNINSTALL_IMPACT_UNAVAILABLE", "Не удалось безопасно определить последствия удаления")
		return
	}
	repository := removal.Repository{Database: server.dependencies.Database}
	if !impact.Active {
		if _, err := repository.RecoverInterrupted(request.Context()); err != nil {
			writeInternalError(writer, err)
			return
		}
	}
	latest, exists, err := repository.Latest(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	response := map[string]any{"impact": impact, "latest_operation": nil}
	if exists {
		response["latest_operation"] = operationResponse(latest, true)
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) uninstallSystem(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Removal == nil {
		writeError(writer, http.StatusNotImplemented, "UNINSTALL_NOT_AVAILABLE", "Безопасное удаление не подключено")
		return
	}
	var input struct {
		Mode                     removal.Mode `json:"mode"`
		Password                 string       `json:"password"`
		Confirmation             string       `json:"confirmation"`
		AcknowledgeSessionLoss   bool         `json:"acknowledge_session_loss"`
		AcknowledgeNotFactory    bool         `json:"acknowledge_not_factory_reset"`
		AcknowledgePurgeDataLoss bool         `json:"acknowledge_purge_data_loss"`
		AcknowledgeExportHandled bool         `json:"acknowledge_export_handled"`
	}
	if err := decodeJSON(request, &input); err != nil || len(input.Password) > 1024 || len(input.Confirmation) > 64 {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный запрос удаления")
		return
	}
	probe := removal.Request{OperationID: "uninstall-" + strings.Repeat("0", 32), Mode: input.Mode}
	if err := probe.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_UNINSTALL_MODE", "Выберите сохранение данных или полное удаление")
		return
	}
	if input.Confirmation != removal.ExactConfirmation {
		writeError(writer, http.StatusBadRequest, "UNINSTALL_CONFIRMATION_MISMATCH", "Введите точную показанную фразу подтверждения")
		return
	}
	if !input.AcknowledgeSessionLoss || !input.AcknowledgeNotFactory {
		writeError(writer, http.StatusBadRequest, "UNINSTALL_WARNINGS_NOT_ACKNOWLEDGED", "Подтвердите разрыв доступа и границы восстановления ОС")
		return
	}
	if input.Mode == removal.ModePurgeData && (!input.AcknowledgePurgeDataLoss || !input.AcknowledgeExportHandled) {
		writeError(writer, http.StatusBadRequest, "UNINSTALL_PURGE_NOT_ACKNOWLEDGED", "Для полного удаления подтвердите потерю данных и завершите нужный экспорт")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			writer.Header().Set("Retry-After", "2")
			writeError(writer, http.StatusTooManyRequests, "REAUTH_RATE_LIMITED", "Слишком много неверных попыток; повторите позже")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "REAUTH_FAILED", "Текущий пароль указан неверно")
		case errors.Is(err, auth.ErrInvalidSession):
			writeError(writer, http.StatusUnauthorized, "SESSION_INVALID", "Сессия истекла или отозвана")
		default:
			writeInternalError(writer, err)
		}
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "UNINSTALL_BLOCKED_BY_MAINTENANCE", "Дождитесь завершения операции питания, установки, обновления, восстановления, сети или резервного копирования")
		return
	}
	repository := removal.Repository{Database: server.dependencies.Database}
	impact, err := server.dependencies.Removal.UninstallImpact(request.Context())
	if err != nil {
		server.endMaintenanceMutation()
		writeError(writer, http.StatusServiceUnavailable, "UNINSTALL_IMPACT_UNAVAILABLE", "Не удалось повторно проверить root guardian перед удалением")
		return
	}
	if impact.Active {
		server.endMaintenanceMutation()
		writeError(writer, http.StatusConflict, "UNINSTALL_OPERATION_IN_PROGRESS", "Root guardian уже выполняет удаление")
		return
	}
	if !impact.Available {
		server.endMaintenanceMutation()
		writeError(writer, http.StatusConflict, "UNINSTALL_UNAVAILABLE", "Fixed root guardian недоступен или не прошёл проверку")
		return
	}
	if _, err := repository.RecoverInterrupted(request.Context()); err != nil {
		server.endMaintenanceMutation()
		writeInternalError(writer, err)
		return
	}
	operation, err := repository.Start(request.Context(), principal.UserID, input.Mode)
	if err != nil {
		server.endMaintenanceMutation()
		if errors.Is(err, removal.ErrOperationInProgress) {
			writeError(writer, http.StatusConflict, "UNINSTALL_OPERATION_IN_PROGRESS", "Удаление уже выполняется")
			return
		}
		writeInternalError(writer, err)
		return
	}
	dispatch := removal.Request{OperationID: operation.ID, Mode: input.Mode}
	if err := server.dependencies.Removal.DispatchUninstall(request.Context(), dispatch); err != nil {
		server.endMaintenanceMutation()
		reason := "UNINSTALL_DISPATCH_FAILED"
		status, code, message := http.StatusBadGateway, reason, "Удаление не удалось безопасно передать root guardian"
		switch {
		case errors.Is(err, removal.ErrMaintenanceActive):
			reason, status, code, message = "UNINSTALL_BLOCKED_BY_MAINTENANCE", http.StatusConflict, "UNINSTALL_BLOCKED_BY_MAINTENANCE", "Сначала завершите установку, обновление, восстановление или безопасное применение сети"
		case errors.Is(err, removal.ErrOperationInProgress):
			reason, status, code, message = "UNINSTALL_OPERATION_IN_PROGRESS", http.StatusConflict, "UNINSTALL_OPERATION_IN_PROGRESS", "Root guardian уже выполняет удаление"
		case errors.Is(err, removal.ErrUnavailable):
			reason, status, code, message = "UNINSTALL_UNAVAILABLE", http.StatusConflict, "UNINSTALL_UNAVAILABLE", "Fixed root guardian недоступен или повреждён"
		case errors.Is(err, removal.ErrInvalidRequest):
			reason, status, code, message = "INVALID_UNINSTALL_REQUEST", http.StatusBadRequest, "INVALID_UNINSTALL_REQUEST", "Некорректный typed запрос удаления"
		}
		_, _ = repository.Finish(request.Context(), operation.ID, false, reason)
		writeError(writer, status, code, message)
		return
	}
	finished, err := repository.Finish(request.Context(), operation.ID, true, "")
	if err != nil {
		writeJSON(writer, http.StatusAccepted, map[string]any{
			"operation_id": operation.ID,
			"mode":         input.Mode,
			"status":       "DISPATCHED_STATUS_PENDING",
			"message":      "Root guardian принял удаление; WebUI и SSH сейчас станут недоступны",
		})
		return
	}
	writeJSON(writer, http.StatusAccepted, operationResponse(finished, true))
}

func (server *Server) diagnosticDescription(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Diagnostics == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Диагностический архив не подключён")
		return
	}
	description, err := server.dependencies.Diagnostics.Describe(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, description)
}

func (server *Server) downloadDiagnostics(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Diagnostics == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Диагностический архив не подключён")
		return
	}
	content, err := io.ReadAll(io.LimitReader(request.Body, 1))
	request.Body.Close()
	if err != nil || len(content) != 0 {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Запрос диагностического архива не принимает параметры")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok || principal.SessionHash == "" || principal.UserID == "" {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if allowed, retry := server.diagnosticLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "DIAGNOSTIC_RATE_LIMITED", "Слишком много диагностических архивов")
		return
	}
	bundle, err := server.dependencies.Diagnostics.Build(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "DIAGNOSTIC_UNAVAILABLE", "Диагностический архив временно недоступен")
		return
	}
	if len(bundle.Content) == 0 || len(bundle.Content) > diagnostics.MaximumBundleBytes || bundle.Filename == "" || len(bundle.SHA256) != 64 {
		writeInternalError(writer, errors.New("diagnostic builder returned an invalid bundle"))
		return
	}
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{
		Severity: "INFO", Type: "DIAGNOSTIC_BUNDLE_CREATED",
		Details: map[string]any{
			"user_id": principal.UserID, "sha256": bundle.SHA256, "bytes": len(bundle.Content),
			"uncompressed_bytes": bundle.UncompressedSize, "complete": bundle.Manifest.Complete,
			"section_errors": bundle.Manifest.SectionErrors, "section_warnings": bundle.Manifest.SectionWarnings,
		},
	}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/zip")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+bundle.Filename+`"`)
	writer.Header().Set("Content-Length", strconv.Itoa(len(bundle.Content)))
	writer.Header().Set("X-Content-SHA256", bundle.SHA256)
	writer.Header().Set("X-Diagnostic-Complete", strconv.FormatBool(bundle.Manifest.Complete))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(bundle.Content)
}

func (server *Server) backupInventory(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Backups == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Резервные снимки не подключены")
		return
	}
	items, err := server.dependencies.Backups.Inventory(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BACKUP_INVENTORY_UNAVAILABLE", "Список резервных снимков временно недоступен")
		return
	}
	verified, invalid := 0, 0
	for _, item := range items {
		if item.Verified {
			verified++
		} else {
			invalid++
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": items, "verified_count": verified, "invalid_count": invalid,
		"daily_retention": 7, "manual_retention": 10,
		"portable_encrypted_backup_available": server.dependencies.PortableBackups != nil,
		"restore_staging_available":           server.dependencies.Restores != nil,
		"restore_available":                   server.dependencies.Restores != nil && server.dependencies.RestoreApply != nil,
	})
}

func (server *Server) createDatabaseSnapshot(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Backups == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Резервные снимки не подключены")
		return
	}
	content, err := io.ReadAll(io.LimitReader(request.Body, 1))
	request.Body.Close()
	if err != nil || len(content) != 0 {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Создание локального снимка не принимает параметры")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok || principal.SessionHash == "" || principal.UserID == "" {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if allowed, retry := server.snapshotLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "BACKUP_RATE_LIMITED", "Слишком много операций резервного копирования")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "BACKUP_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	snapshot, err := server.dependencies.Backups.Create(request.Context(), backup.KindManual)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BACKUP_CREATE_FAILED", "Не удалось создать и проверить локальный снимок")
		return
	}
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "INFO", Type: "DATABASE_MANUAL_SNAPSHOT_CREATED", Details: map[string]any{"user_id": principal.UserID, "snapshot_id": snapshot.Manifest.SnapshotID, "bytes": snapshot.Manifest.Database.Bytes, "sha256": snapshot.Manifest.Database.SHA256, "schema_version": snapshot.Manifest.SchemaVersion}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, backup.InventoryItem{
		SnapshotID: snapshot.Manifest.SnapshotID, Kind: snapshot.Manifest.Kind,
		CreatedAt: snapshot.Manifest.CreatedAt, VerifiedAt: snapshot.Manifest.VerifiedAt,
		SchemaVersion: snapshot.Manifest.SchemaVersion, Bytes: snapshot.Manifest.Database.Bytes,
		SHA256: snapshot.Manifest.Database.SHA256, Verified: true,
	})
}

func (server *Server) downloadEncryptedBackup(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.PortableBackups == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Зашифрованная резервная копия не подключена")
		return
	}
	var input struct {
		Password               string `json:"password"`
		Passphrase             string `json:"passphrase"`
		PassphraseConfirmation string `json:"passphrase_confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректные параметры резервной копии")
		return
	}
	if input.Passphrase != input.PassphraseConfirmation || backup.ValidatePassphrase(input.Passphrase) != nil {
		input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
		writeError(writer, http.StatusBadRequest, "BACKUP_PASSPHRASE_INVALID", "Passphrase должна совпадать и содержать 12–256 UTF-8 байт")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok || principal.SessionHash == "" || principal.UserID == "" {
		input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
		writeError(writer, http.StatusUnauthorized, "REAUTHENTICATION_FAILED", "Текущий пароль не подтверждён")
		return
	}
	passphrase := input.Passphrase
	input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
	if allowed, retry := server.portableBackupLimiter.allow(principal.SessionHash, server.now()); !allowed {
		passphrase = ""
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "BACKUP_RATE_LIMITED", "Слишком много операций резервного копирования")
		return
	}
	if !server.beginMaintenanceMutation() {
		passphrase = ""
		writeError(writer, http.StatusConflict, "BACKUP_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	artifact, err := server.dependencies.PortableBackups.Build(request.Context(), passphrase)
	passphrase = ""
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BACKUP_CREATE_FAILED", "Не удалось создать и проверить зашифрованную резервную копию")
		return
	}
	defer server.dependencies.PortableBackups.Remove(artifact)
	if artifact.Bytes <= 0 || artifact.Bytes > backup.MaximumPortableBackupBytes || len(artifact.SHA256) != 64 || artifact.Filename == "" || artifact.SnapshotID == "" {
		writeInternalError(writer, errors.New("portable backup builder returned invalid metadata"))
		return
	}
	reader, err := server.dependencies.PortableBackups.Open(artifact)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BACKUP_VERIFY_FAILED", "Зашифрованная резервная копия не прошла финальную проверку")
		return
	}
	defer reader.Close()
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "INFO", Type: "PORTABLE_ENCRYPTED_BACKUP_CREATED", Details: map[string]any{"user_id": principal.UserID, "snapshot_id": artifact.SnapshotID, "sha256": artifact.SHA256, "bytes": artifact.Bytes, "format_version": backup.PortableFormatVersion, "secrets_included_encrypted": true}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/vnd.gateway-vpn.backup")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+artifact.Filename+`"`)
	writer.Header().Set("Content-Length", strconv.FormatInt(artifact.Bytes, 10))
	writer.Header().Set("X-Content-SHA256", artifact.SHA256)
	writer.Header().Set("X-Backup-Snapshot", artifact.SnapshotID)
	writer.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(writer, reader, artifact.Bytes)
}

func (server *Server) restoreStatus(writer http.ResponseWriter, _ *http.Request) {
	if server.dependencies.Restores == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Восстановление не подключено")
		return
	}
	operation, pending, err := server.dependencies.Restores.Status()
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESTORE_STATUS_UNAVAILABLE", "Состояние восстановления временно недоступно")
		return
	}
	// The authorization nonce binds the root-owned journal to one explicit
	// destructive confirmation and is never part of the public API DTO.
	operation.ApplyAuthorization = ""
	writeJSON(writer, http.StatusOK, map[string]any{"pending": pending, "operation": operation, "apply_available": server.dependencies.RestoreApply != nil})
}

func (server *Server) stageRestore(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Restores == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Восстановление не подключено")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "RESTORE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Ожидается multipart backup upload")
		return
	}
	maximumUploadBytes := backup.MaximumPortableBackupBytes + (1 << 20)
	if request.ContentLength > maximumUploadBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "RESTORE_UPLOAD_TOO_LARGE", "Зашифрованная резервная копия превышает допустимый размер")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumUploadBytes)
	multipartReader, err := request.MultipartReader()
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Не удалось прочитать multipart backup upload")
		return
	}
	passphrasePart, err := multipartReader.NextPart()
	if err != nil || passphrasePart.FormName() != "passphrase" || passphrasePart.FileName() != "" {
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Первой multipart-частью должна быть passphrase")
		return
	}
	passphraseContent, err := io.ReadAll(io.LimitReader(passphrasePart, 257))
	passphrasePart.Close()
	passphrase := string(passphraseContent)
	if err != nil || backup.ValidatePassphrase(passphrase) != nil {
		writeError(writer, http.StatusBadRequest, "RESTORE_PASSPHRASE_INVALID", "Passphrase должна содержать 12–256 UTF-8 байт")
		return
	}
	backupPart, err := multipartReader.NextPart()
	if err != nil || backupPart.FormName() != "backup" || backupPart.FileName() == "" || len(backupPart.FileName()) > 180 || filepath.Base(backupPart.FileName()) != backupPart.FileName() || !strings.HasSuffix(strings.ToLower(backupPart.FileName()), ".gvpn") {
		passphrase = ""
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Второй multipart-частью должен быть .gvpn backup")
		return
	}
	operation, stageErr := server.dependencies.Restores.Stage(request.Context(), backupPart, passphrase)
	passphrase = ""
	backupPart.Close()
	if stageErr == nil {
		if extra, extraErr := multipartReader.NextPart(); extraErr == nil || extra != nil {
			if extra != nil {
				extra.Close()
			}
			if discardErr := server.dependencies.Restores.Discard(request.Context(), operation.RestoreID); discardErr != nil {
				writeInternalError(writer, errors.New("compensate invalid restore multipart failed"))
				return
			}
			writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Лишние multipart-части запрещены")
			return
		} else if !errors.Is(extraErr, io.EOF) {
			if discardErr := server.dependencies.Restores.Discard(request.Context(), operation.RestoreID); discardErr != nil {
				writeInternalError(writer, errors.New("compensate malformed restore multipart failed"))
				return
			}
			writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Multipart upload завершён некорректно")
			return
		}
	}
	if errors.Is(stageErr, backup.ErrRestorePending) {
		writeError(writer, http.StatusConflict, "RESTORE_ALREADY_PENDING", "Сначала примените или отмените существующее восстановление")
		return
	}
	if errors.Is(stageErr, backup.ErrRestoreUploadTooLarge) {
		writeError(writer, http.StatusRequestEntityTooLarge, "RESTORE_UPLOAD_TOO_LARGE", "Зашифрованная резервная копия превышает допустимый размер")
		return
	}
	if stageErr != nil {
		writeError(writer, http.StatusBadRequest, "RESTORE_VERIFICATION_FAILED", "Backup, passphrase или содержимое не прошли проверку")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "RESTORE_STAGED", Details: map[string]any{"user_id": principal.UserID, "restore_id": operation.RestoreID, "snapshot_id": operation.SnapshotID, "portable_sha256": operation.PortableSHA256, "portable_bytes": operation.PortableBytes, "schema_version": operation.SchemaVersion}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, operation)
}

func (server *Server) applyRestore(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Restores == nil || server.dependencies.RestoreApply == nil || server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Применение восстановления не подключено")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "RESTORE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	if request.Header.Get("X-Confirm-Destructive") != "apply-verified-restore" {
		writeError(writer, http.StatusConflict, "RESTORE_CONFIRMATION_REQUIRED", "Требуется явное подтверждение применения verified restore")
		return
	}
	var input struct {
		RestoreID string `json:"restore_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный restore id")
		return
	}
	operation, pending, err := server.dependencies.Restores.Status()
	if err != nil || !pending || input.RestoreID != operation.RestoreID {
		writeError(writer, http.StatusConflict, "RESTORE_NOT_PENDING", "Проверенная операция восстановления не найдена или изменилась")
		return
	}
	if err := server.dependencies.ModemRuntime.BlockPath(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось закрыть data path перед восстановлением")
		return
	}
	if _, _, err := server.dependencies.State.Block(request.Context(), state.GatewayBlocked, "VERIFIED_RESTORE_APPLY_REQUESTED"); err != nil {
		writeInternalError(writer, err)
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "RESTORE_APPLY_REQUESTED", Details: map[string]any{"user_id": principal.UserID, "restore_id": operation.RestoreID, "snapshot_id": operation.SnapshotID}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	operation, err = server.dependencies.Restores.AuthorizeApply(operation.RestoreID)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESTORE_APPLY_AUTHORIZATION_FAILED", "Data path закрыт, но подтверждение restore не удалось сохранить")
		return
	}
	if err := server.dependencies.RestoreApply.ApplyPendingRestore(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "RESTORE_APPLY_START_FAILED", "Data path закрыт, но systemd restore helper не запустился")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"restore_id": operation.RestoreID, "state": "APPLY_SCHEDULED", "management_reconnect_required": true})
}

func (server *Server) discardRestore(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Restores == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Восстановление не подключено")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "RESTORE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	if request.Header.Get("X-Confirm-Destructive") != "discard-staged-restore" {
		writeError(writer, http.StatusConflict, "RESTORE_DISCARD_CONFIRMATION_REQUIRED", "Требуется явное подтверждение удаления staged restore")
		return
	}
	var input struct {
		RestoreID string `json:"restore_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный restore id")
		return
	}
	operation, pending, err := server.dependencies.Restores.Status()
	if err != nil || !pending || operation.State != backup.RestoreStateStaged || input.RestoreID != operation.RestoreID {
		writeError(writer, http.StatusConflict, "RESTORE_NOT_PENDING", "Проверенная staged операция восстановления не найдена или изменилась")
		return
	}
	if err := server.dependencies.Restores.Discard(request.Context(), operation.RestoreID); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESTORE_DISCARD_FAILED", "Не удалось безопасно удалить staged restore")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "RESTORE_DISCARDED", Details: map[string]any{"user_id": principal.UserID, "restore_id": operation.RestoreID, "snapshot_id": operation.SnapshotID}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) updateStatus(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Updates == nil && server.dependencies.UpdateApply == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Подписанные обновления не подключены")
		return
	}
	response := map[string]any{
		"pending":                 false,
		"operation":               nil,
		"staging_query_state":     "NOT_CONFIGURED",
		"apply_available":         false,
		"transaction":             nil,
		"transaction_query_state": "NOT_CONFIGURED",
	}
	if server.dependencies.Updates != nil {
		operation, pending, err := server.dependencies.Updates.Status()
		if err != nil {
			response["staging_query_state"] = "UNAVAILABLE"
		} else {
			response["staging_query_state"] = "AVAILABLE"
			response["pending"] = pending
			if pending {
				response["operation"] = operation
			}
		}
	}
	if server.dependencies.UpdateApply != nil {
		transaction, err := server.dependencies.UpdateApply.UpdateStatus(request.Context())
		if err != nil {
			response["transaction_query_state"] = "UNAVAILABLE"
		} else {
			response["transaction_query_state"] = "AVAILABLE"
			response["transaction"] = transaction
		}
	}
	response["apply_available"] = server.dependencies.Updates != nil && server.dependencies.UpdateApply != nil && response["staging_query_state"] == "AVAILABLE"
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) softwareUpdatePolicy(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.UpdatePolicy == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Политика обновлений не подключена")
		return
	}
	policy, err := server.dependencies.UpdatePolicy.Get(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "UPDATE_POLICY_UNAVAILABLE", "Не удалось прочитать политику обновлений")
		return
	}
	writeJSON(writer, http.StatusOK, policy)
}

func (server *Server) updateAutomationStatus(writer http.ResponseWriter, request *http.Request) {
	response := map[string]any{"runtime_state": "UNAVAILABLE", "status": nil}
	if server.dependencies.UpdateAutomation == nil {
		writeJSON(writer, http.StatusOK, response)
		return
	}
	status, err := server.dependencies.UpdateAutomation.Status(request.Context())
	if err != nil {
		writeJSON(writer, http.StatusOK, response)
		return
	}
	response["runtime_state"] = "AVAILABLE"
	response["status"] = status
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) updateSoftwareUpdatePolicy(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.UpdatePolicy == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Политика обновлений не подключена")
		return
	}
	var input struct {
		Channel                    string `json:"channel"`
		AutomaticCheckEnabled      bool   `json:"automatic_check_enabled"`
		AutomaticDownloadEnabled   bool   `json:"automatic_download_enabled"`
		AutomaticApplyEnabled      bool   `json:"automatic_apply_enabled"`
		CheckIntervalHours         int    `json:"check_interval_hours"`
		JitterMinutes              int    `json:"jitter_minutes"`
		MaintenanceWindowEnabled   bool   `json:"maintenance_window_enabled"`
		MaintenanceStartMinuteUTC  int    `json:"maintenance_start_minute_utc"`
		MaintenanceDurationMinutes int    `json:"maintenance_duration_minutes"`
		MaximumApplyDelayHours     int    `json:"maximum_apply_delay_hours"`
		RetentionMaximumPoints     int    `json:"retention_maximum_points"`
		RetentionMaximumBytes      int64  `json:"retention_maximum_bytes"`
		RetentionMaximumAgeDays    int    `json:"retention_maximum_age_days"`
		RetentionMinimumOldPoints  int    `json:"retention_minimum_old_points"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректная политика обновлений")
		return
	}
	policy, err := server.dependencies.UpdatePolicy.Update(request.Context(), updatepkg.AutomationPolicyInput{
		Channel: input.Channel, AutomaticCheckEnabled: input.AutomaticCheckEnabled,
		AutomaticDownloadEnabled: input.AutomaticDownloadEnabled, AutomaticApplyEnabled: input.AutomaticApplyEnabled,
		CheckIntervalHours: input.CheckIntervalHours, JitterMinutes: input.JitterMinutes,
		MaintenanceWindowEnabled:  input.MaintenanceWindowEnabled,
		MaintenanceStartMinuteUTC: input.MaintenanceStartMinuteUTC, MaintenanceDurationMinutes: input.MaintenanceDurationMinutes,
		MaximumApplyDelayHours: input.MaximumApplyDelayHours,
		RetentionMaximumPoints: input.RetentionMaximumPoints, RetentionMaximumBytes: input.RetentionMaximumBytes,
		RetentionMaximumAgeDays: input.RetentionMaximumAgeDays, RetentionMinimumOldPoints: input.RetentionMinimumOldPoints,
	})
	if err != nil {
		writeError(writer, http.StatusBadRequest, "UPDATE_POLICY_INVALID", "Политика обновлений содержит небезопасное или неподдерживаемое сочетание")
		return
	}
	writeJSON(writer, http.StatusOK, policy)
}

func (server *Server) updateRestorePoints(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.UpdateRestorePoints == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "История версий не подключена")
		return
	}
	items, err := server.dependencies.UpdateRestorePoints.RestorePointInventory(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "UPDATE_RESTORE_POINTS_UNAVAILABLE", "Не удалось проверить историю версий")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) rollbackToUpdateRestorePoint(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.UpdateRestorePoints == nil || server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Откат к сохранённой версии не подключён")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "UPDATE_ROLLBACK_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	if request.Header.Get("X-Confirm-Destructive") != "rollback-update-restore-point" {
		writeError(writer, http.StatusConflict, "UPDATE_ROLLBACK_CONFIRMATION_REQUIRED", "Требуется явное подтверждение отката с заменой более новых настроек и данных")
		return
	}
	var input struct {
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil || len(input.Password) > 1024 || input.Confirmation != "ROLLBACK_TO_RESTORE_POINT" {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusConflict, "UPDATE_ROLLBACK_TYPED_CONFIRMATION_REQUIRED", "Введите точную контрольную фразу ROLLBACK_TO_RESTORE_POINT")
		return
	}
	pointID := request.PathValue("id")
	if updatepkg.ValidateRestorePointID(pointID) != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный идентификатор точки восстановления")
		return
	}
	items, err := server.dependencies.UpdateRestorePoints.RestorePointInventory(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "UPDATE_RESTORE_POINTS_UNAVAILABLE", "Не удалось повторно проверить историю версий")
		return
	}
	var target *updatepkg.RestorePoint
	for index := range items {
		if items[index].Manifest.PointID == pointID {
			target = &items[index]
			break
		}
	}
	if target == nil {
		writeError(writer, http.StatusConflict, "UPDATE_RESTORE_POINT_CHANGED", "Точка восстановления не найдена или изменилась")
		return
	}
	if !target.Compatible {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusConflict, "UPDATE_RESTORE_POINT_INCOMPATIBLE", "Точка восстановления несовместима с текущим host contract")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		input.Password, input.Confirmation = "", ""
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			writer.Header().Set("Retry-After", "2")
			writeError(writer, http.StatusTooManyRequests, "REAUTH_RATE_LIMITED", "Слишком много неверных попыток; повторите позже")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "REAUTH_FAILED", "Текущий пароль указан неверно")
		case errors.Is(err, auth.ErrInvalidSession):
			writeError(writer, http.StatusUnauthorized, "SESSION_INVALID", "Сессия истекла или отозвана")
		default:
			writeInternalError(writer, err)
		}
		return
	}
	input.Password, input.Confirmation = "", ""
	if err := server.dependencies.ModemRuntime.BlockPath(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось закрыть data path перед откатом")
		return
	}
	if _, _, err := server.dependencies.State.Block(request.Context(), state.GatewayBlocked, "UPDATE_RESTORE_POINT_ROLLBACK_REQUESTED"); err != nil {
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "UPDATE_RESTORE_POINT_ROLLBACK_REQUESTED", Details: map[string]any{
		"user_id": principal.UserID, "point_id": pointID,
		"target_gateway_version": target.Manifest.GatewayVersion, "target_schema_version": target.Manifest.SchemaVersion,
		"target_release_manifest_sha256": target.Manifest.ReleaseManifestSHA256,
	}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.UpdateRestorePoints.RollbackToRestorePoint(request.Context(), pointID); err != nil {
		writeError(writer, http.StatusBadGateway, "UPDATE_ROLLBACK_START_FAILED", "Data path закрыт, но fixed systemd rollback helper не запустился")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"operation_kind": "RESTORE_POINT_ROLLBACK", "target_restore_point_id": pointID,
		"target_gateway_version": target.Manifest.GatewayVersion, "state": "ROLLBACK_SCHEDULED", "management_reconnect_required": true,
	})
}

func (server *Server) deleteUpdateRestorePoint(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.UpdateRestorePoints == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "История версий не подключена")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "delete-update-restore-point" {
		writeError(writer, http.StatusConflict, "UPDATE_RESTORE_POINT_CONFIRMATION_REQUIRED", "Требуется явное подтверждение удаления точки восстановления")
		return
	}
	pointID := request.PathValue("id")
	if updatepkg.ValidateRestorePointID(pointID) != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный идентификатор точки восстановления")
		return
	}
	if err := server.dependencies.UpdateRestorePoints.DeleteRestorePoint(request.Context(), pointID); err != nil {
		writeError(writer, http.StatusConflict, "UPDATE_RESTORE_POINT_PROTECTED", "Точка текущей, recovery или активной версии защищена либо изменилась")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "UPDATE_RESTORE_POINT_DELETED", Details: map[string]any{"user_id": principal.UserID, "point_id": pointID}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) pruneUpdateRestorePoints(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.UpdateRestorePoints == nil || server.dependencies.UpdatePolicy == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Очистка истории версий не подключена")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "prune-update-restore-points" {
		writeError(writer, http.StatusConflict, "UPDATE_RESTORE_POINT_CONFIRMATION_REQUIRED", "Требуется явное подтверждение очистки истории версий")
		return
	}
	var input struct{}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Запрос очистки не должен содержать параметры")
		return
	}
	policy, err := server.dependencies.UpdatePolicy.Get(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "UPDATE_POLICY_UNAVAILABLE", "Не удалось прочитать retention-политику")
		return
	}
	removed, err := server.dependencies.UpdateRestorePoints.PruneRestorePoints(request.Context(), policy.RetentionPolicy())
	if err != nil {
		writeError(writer, http.StatusConflict, "UPDATE_RESTORE_POINT_PRUNE_FAILED", "История изменилась или защищённые версии не прошли проверку")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "UPDATE_RESTORE_POINTS_PRUNED", Details: map[string]any{"user_id": principal.UserID, "removed": removed, "removed_count": len(removed)}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"removed": removed})
}

func (server *Server) availableUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.RemoteUpdates == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Проверка официальных каналов обновления не подключена")
		return
	}
	channel := request.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	if channel != "stable" && channel != "testing" {
		writeError(writer, http.StatusBadRequest, "UPDATE_CHANNEL_INVALID", "Канал должен быть stable или testing")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 45*time.Second)
	defer cancel()
	available, err := server.dependencies.RemoteUpdates.Check(ctx, channel)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "UPDATE_CHECK_FAILED", "Не удалось получить и проверить подписанный manifest выбранного канала")
		return
	}
	writeJSON(writer, http.StatusOK, available)
}

func (server *Server) availableMihomoUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.RemoteUpdates == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Проверка одобренных обновлений Mihomo не подключена")
		return
	}
	channel := request.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	if channel != "stable" && channel != "testing" {
		writeError(writer, http.StatusBadRequest, "UPDATE_CHANNEL_INVALID", "Канал Mihomo должен быть stable или testing")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 45*time.Second)
	defer cancel()
	available, err := server.dependencies.RemoteUpdates.CheckMihomo(ctx, channel)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "MIHOMO_UPDATE_CHECK_FAILED", "Не удалось получить и проверить подписанный manifest совместимости Mihomo")
		return
	}
	writeJSON(writer, http.StatusOK, available)
}

func (server *Server) stageRemoteUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.RemoteUpdates == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Удалённая загрузка подписанных обновлений не подключена")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "UPDATE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	principal := request.Context().Value(principalKey).(auth.Principal)
	if allowed, retry := server.updateLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "RATE_LIMITED", "Повторите загрузку release позже")
		return
	}
	var input struct {
		Source   string `json:"source"`
		Channel  string `json:"channel"`
		ExactURL string `json:"exact_url"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный источник обновления")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Minute)
	defer cancel()
	var (
		operation updatepkg.Operation
		err       error
	)
	switch input.Source {
	case "GITHUB_CHANNEL":
		if (input.Channel != "stable" && input.Channel != "testing") || input.ExactURL != "" {
			writeError(writer, http.StatusBadRequest, "UPDATE_SOURCE_INVALID", "Для официального источника выберите stable или testing без URL")
			return
		}
		operation, err = server.dependencies.RemoteUpdates.StageChannel(ctx, input.Channel)
	case "MIHOMO_GITHUB_CHANNEL":
		if (input.Channel != "stable" && input.Channel != "testing") || input.ExactURL != "" {
			writeError(writer, http.StatusBadRequest, "UPDATE_SOURCE_INVALID", "Для обновления Mihomo выберите stable или testing без URL")
			return
		}
		operation, err = server.dependencies.RemoteUpdates.StageMihomoChannel(ctx, input.Channel)
	case "EXACT_HTTPS":
		if input.Channel != "" || input.ExactURL == "" {
			writeError(writer, http.StatusBadRequest, "UPDATE_SOURCE_INVALID", "Для advanced-источника укажите один exact HTTPS URL")
			return
		}
		operation, err = server.dependencies.RemoteUpdates.StageExact(ctx, input.ExactURL)
	default:
		writeError(writer, http.StatusBadRequest, "UPDATE_SOURCE_INVALID", "Поддерживаются официальный Gateway-канал, одобренный Mihomo-канал и exact HTTPS")
		return
	}
	if errors.Is(err, updatepkg.ErrUpdatePending) {
		writeError(writer, http.StatusConflict, "UPDATE_ALREADY_PENDING", "Сначала примените или удалите существующий staged release")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadGateway, "REMOTE_UPDATE_STAGE_FAILED", "Release не загружен либо не прошёл подписанную проверку и compatibility gate")
		return
	}
	if err := server.appendUpdateStagedEvent(request.Context(), principal, operation); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, operation)
}

func (server *Server) stageUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Updates == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Подписанные обновления не подключены")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "UPDATE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	principal := request.Context().Value(principalKey).(auth.Principal)
	if allowed, retry := server.updateLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "RATE_LIMITED", "Повторите загрузку release позже")
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		writeError(writer, http.StatusBadRequest, "INVALID_UPDATE_UPLOAD", "Ожидается один multipart release archive")
		return
	}
	maximumUploadBytes := updatepkg.MaximumArchiveBytes + (1 << 20)
	if request.ContentLength > maximumUploadBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "UPDATE_UPLOAD_TOO_LARGE", "Release archive превышает допустимый размер")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumUploadBytes)
	multipartReader, err := request.MultipartReader()
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_UPDATE_UPLOAD", "Не удалось прочитать multipart release archive")
		return
	}
	releasePart, err := multipartReader.NextPart()
	if err != nil || releasePart.FormName() != "release" || releasePart.FileName() == "" || len(releasePart.FileName()) > 200 || filepath.Base(releasePart.FileName()) != releasePart.FileName() || !strings.HasSuffix(strings.ToLower(releasePart.FileName()), ".tar.gz") {
		writeError(writer, http.StatusBadRequest, "INVALID_UPDATE_UPLOAD", "Multipart должен содержать один файл .tar.gz в поле release")
		return
	}
	operation, stageErr := server.dependencies.Updates.Stage(request.Context(), releasePart)
	releasePart.Close()
	if stageErr == nil {
		if extra, extraErr := multipartReader.NextPart(); extraErr == nil || extra != nil {
			if extra != nil {
				extra.Close()
			}
			if discardErr := server.dependencies.Updates.Discard(request.Context(), operation.UpdateID); discardErr != nil {
				writeInternalError(writer, errors.New("compensate invalid update multipart failed"))
				return
			}
			writeError(writer, http.StatusBadRequest, "INVALID_UPDATE_UPLOAD", "Лишние multipart-части запрещены")
			return
		} else if !errors.Is(extraErr, io.EOF) {
			if discardErr := server.dependencies.Updates.Discard(request.Context(), operation.UpdateID); discardErr != nil {
				writeInternalError(writer, errors.New("compensate malformed update multipart failed"))
				return
			}
			writeError(writer, http.StatusBadRequest, "INVALID_UPDATE_UPLOAD", "Multipart upload завершён некорректно")
			return
		}
	}
	if errors.Is(stageErr, updatepkg.ErrUpdatePending) {
		writeError(writer, http.StatusConflict, "UPDATE_ALREADY_PENDING", "Сначала примените или удалите существующий staged release")
		return
	}
	if stageErr != nil {
		writeError(writer, http.StatusBadRequest, "UPDATE_VERIFICATION_FAILED", "Подпись, signer, файлы или compatibility release не прошли проверку")
		return
	}
	if err := server.appendUpdateStagedEvent(request.Context(), principal, operation); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, operation)
}

func (server *Server) appendUpdateStagedEvent(ctx context.Context, principal auth.Principal, operation updatepkg.Operation) error {
	return server.dependencies.State.AppendEvent(ctx, state.EventInput{Severity: "WARNING", Type: "SIGNED_UPDATE_STAGED", Details: map[string]any{
		"user_id": principal.UserID, "update_id": operation.UpdateID,
		"gateway_version": operation.GatewayVersion, "mihomo_version": operation.MihomoVersion,
		"signer_key_sha256": operation.SignerKeySHA256, "manifest_sha256": operation.ManifestSHA256,
		"bytes": operation.UncompressedBytes, "file_count": operation.FileCount,
		"source_kind": operation.SourceKind, "source_channel": operation.SourceChannel,
		"source_reference": operation.SourceReference,
	}})
}

func (server *Server) applyUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Updates == nil || server.dependencies.UpdateApply == nil || server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Применение подписанных обновлений не подключено")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "UPDATE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	if request.Header.Get("X-Confirm-Destructive") != "apply-verified-update" {
		writeError(writer, http.StatusConflict, "UPDATE_CONFIRMATION_REQUIRED", "Требуется явное подтверждение применения verified signed release")
		return
	}
	var input struct {
		UpdateID string `json:"update_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный update id")
		return
	}
	operation, pending, err := server.dependencies.Updates.Status()
	if err != nil || !pending || operation.State != "STAGED" || input.UpdateID != operation.UpdateID {
		writeError(writer, http.StatusConflict, "UPDATE_NOT_PENDING", "Проверенный staged release не найден или изменился")
		return
	}
	if err := server.dependencies.ModemRuntime.BlockPath(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "PATH_BLOCK_FAILED", "Не удалось закрыть data path перед обновлением")
		return
	}
	if _, _, err := server.dependencies.State.Block(request.Context(), state.GatewayBlocked, "SIGNED_UPDATE_APPLY_REQUESTED"); err != nil {
		writeInternalError(writer, err)
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "SIGNED_UPDATE_APPLY_REQUESTED", Details: map[string]any{"user_id": principal.UserID, "update_id": operation.UpdateID, "gateway_version": operation.GatewayVersion, "signer_key_sha256": operation.SignerKeySHA256, "manifest_sha256": operation.ManifestSHA256}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	if err := server.dependencies.UpdateApply.ApplyPendingUpdate(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "UPDATE_APPLY_START_FAILED", "Data path закрыт, но fixed systemd update helper не запустился")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"update_id": operation.UpdateID, "state": "APPLY_SCHEDULED", "management_reconnect_required": true})
}

func (server *Server) discardUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Updates == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Подписанные обновления не подключены")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "UPDATE_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	if request.Header.Get("X-Confirm-Destructive") != "discard-staged-update" {
		writeError(writer, http.StatusConflict, "UPDATE_DISCARD_CONFIRMATION_REQUIRED", "Требуется явное подтверждение удаления staged release")
		return
	}
	var input struct {
		UpdateID string `json:"update_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный update id")
		return
	}
	operation, pending, err := server.dependencies.Updates.Status()
	if err != nil || !pending || operation.State != "STAGED" || input.UpdateID != operation.UpdateID {
		writeError(writer, http.StatusConflict, "UPDATE_NOT_PENDING", "Проверенный staged release не найден или изменился")
		return
	}
	if err := server.dependencies.Updates.Discard(request.Context(), operation.UpdateID); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "UPDATE_DISCARD_FAILED", "Не удалось безопасно удалить staged release")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "SIGNED_UPDATE_DISCARDED", Details: map[string]any{"user_id": principal.UserID, "update_id": operation.UpdateID, "gateway_version": operation.GatewayVersion, "manifest_sha256": operation.ManifestSHA256}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) logs(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Journal == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Просмотр journald не подключён")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok || principal.SessionHash == "" {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if allowed, retry := server.journalLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "LOG_QUERY_RATE_LIMITED", "Слишком много запросов журнала")
		return
	}
	allowedKeys := map[string]bool{
		"limit": true, "cursor": true, "since": true, "until": true, "level": true,
		"component": true, "category": true, "modem_id": true, "subscription_id": true,
		"path_id": true, "correlation_id": true, "search": true,
	}
	for key := range request.URL.Query() {
		if !allowedKeys[key] {
			writeError(writer, http.StatusBadRequest, "INVALID_LOG_FILTER", "Неизвестный фильтр журнала")
			return
		}
	}
	limit := loggingpkg.MaximumJournalPageSize
	var err error
	if raw := request.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "INVALID_LOG_FILTER", "Некорректный размер страницы журнала")
			return
		}
	}
	query := loggingpkg.JournalQuery{
		Limit: limit, Cursor: request.URL.Query().Get("cursor"),
		Since: request.URL.Query().Get("since"), Until: request.URL.Query().Get("until"),
		Levels:    append([]string(nil), request.URL.Query()["level"]...),
		Component: request.URL.Query().Get("component"), Category: request.URL.Query().Get("category"), ModemID: request.URL.Query().Get("modem_id"),
		SubscriptionID: request.URL.Query().Get("subscription_id"), PathID: request.URL.Query().Get("path_id"),
		CorrelationID: request.URL.Query().Get("correlation_id"), Search: request.URL.Query().Get("search"),
	}
	query, err = loggingpkg.NormalizeJournalQuery(query, server.now())
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_LOG_FILTER", err.Error())
		return
	}
	page, err := server.dependencies.Journal.QueryLogs(request.Context(), query)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "LOGS_UNAVAILABLE", "Технический журнал временно недоступен")
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (server *Server) updateLoggingSettings(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Logging == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Настройки логирования не подключены")
		return
	}
	var input struct {
		GlobalLevel                   string            `json:"global_level"`
		ComponentLevels               map[string]string `json:"component_levels"`
		DebugComponents               []string          `json:"debug_components"`
		DebugTTLSeconds               int64             `json:"debug_ttl_seconds"`
		RetentionDays                 int               `json:"retention_days"`
		MaxDiskUsageBytes             int64             `json:"max_disk_usage_bytes"`
		DiagnosticExcerptBytes        int64             `json:"diagnostic_excerpt_bytes"`
		HealthErrorAggregationSeconds int               `json:"health_error_aggregation_seconds"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if input.DebugTTLSeconds < 0 || input.DebugTTLSeconds > int64((24*time.Hour)/time.Second) {
		writeError(writer, http.StatusBadRequest, "VALIDATION_FAILED", "Некорректный срок debug")
		return
	}
	settings, err := server.dependencies.Logging.Update(request.Context(), loggingpkg.UpdateInput{
		GlobalLevel: input.GlobalLevel, ComponentLevels: input.ComponentLevels,
		DebugComponents: input.DebugComponents, DebugTTL: time.Duration(input.DebugTTLSeconds) * time.Second,
		RetentionDays: input.RetentionDays, MaxDiskUsageBytes: input.MaxDiskUsageBytes,
		DiagnosticExcerptBytes:        input.DiagnosticExcerptBytes,
		HealthErrorAggregationSeconds: input.HealthErrorAggregationSeconds,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	syncState := "NOT_CONNECTED"
	if server.dependencies.LoggingSync != nil {
		syncState = "SYNCED"
		if err := server.dependencies.LoggingSync.SyncLogging(request.Context()); err != nil {
			syncState = "RETRY_PENDING"
		}
	}
	server.writeLoggingSettings(writer, request.Context(), settings, syncState)
}

func (server *Server) updateWatchdogSettings(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Watchdog == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Настройки самоконтроля не подключены")
		return
	}
	var input struct {
		Enabled                        bool              `json:"enabled"`
		CheckIntervalSeconds           int               `json:"check_interval_seconds"`
		FailureThreshold               int               `json:"failure_threshold"`
		SuccessThreshold               int               `json:"success_threshold"`
		ReconcileEnabled               bool              `json:"reconcile_enabled"`
		ComponentRestartEnabled        bool              `json:"component_restart_enabled"`
		RestartCooldownSeconds         int               `json:"restart_cooldown_seconds"`
		MaxRestartsPerComponent        int               `json:"max_restarts_per_component"`
		RestartWindowSeconds           int               `json:"restart_window_seconds"`
		HostRebootEnabled              bool              `json:"host_reboot_enabled"`
		RebootAfterCriticalSeconds     int               `json:"reboot_after_critical_seconds"`
		MaxRebootsPer24h               int               `json:"max_reboots_per_24h"`
		RebootGraceSeconds             int               `json:"reboot_grace_seconds"`
		WorkerStaleSeconds             int               `json:"worker_stale_seconds"`
		WireGuardHandshakeStaleSeconds int               `json:"wireguard_handshake_stale_seconds"`
		BackupMaxAgeHours              int               `json:"backup_max_age_hours"`
		DatabaseWALMaxBytes            int64             `json:"database_wal_max_bytes"`
		MinimumDiskFreeBytes           int64             `json:"minimum_disk_free_bytes"`
		MinimumDiskFreePercent         int               `json:"minimum_disk_free_percent"`
		MinimumMemoryAvailableBytes    int64             `json:"minimum_memory_available_bytes"`
		MinimumMemoryAvailablePercent  int               `json:"minimum_memory_available_percent"`
		ComponentRecoveryModes         map[string]string `json:"component_recovery_modes"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	policy, err := server.dependencies.Watchdog.Update(request.Context(), watchdog.UpdateInput{
		Enabled: input.Enabled, CheckIntervalSeconds: input.CheckIntervalSeconds,
		FailureThreshold: input.FailureThreshold, SuccessThreshold: input.SuccessThreshold,
		ReconcileEnabled: input.ReconcileEnabled, ComponentRestartEnabled: input.ComponentRestartEnabled,
		RestartCooldownSeconds:  input.RestartCooldownSeconds,
		MaxRestartsPerComponent: input.MaxRestartsPerComponent, RestartWindowSeconds: input.RestartWindowSeconds,
		HostRebootEnabled: input.HostRebootEnabled, RebootAfterCriticalSeconds: input.RebootAfterCriticalSeconds,
		MaxRebootsPer24h: input.MaxRebootsPer24h, RebootGraceSeconds: input.RebootGraceSeconds,
		WorkerStaleSeconds:             input.WorkerStaleSeconds,
		WireGuardHandshakeStaleSeconds: input.WireGuardHandshakeStaleSeconds,
		BackupMaxAgeHours:              input.BackupMaxAgeHours, DatabaseWALMaxBytes: input.DatabaseWALMaxBytes,
		MinimumDiskFreeBytes: input.MinimumDiskFreeBytes, MinimumDiskFreePercent: input.MinimumDiskFreePercent,
		MinimumMemoryAvailableBytes:   input.MinimumMemoryAvailableBytes,
		MinimumMemoryAvailablePercent: input.MinimumMemoryAvailablePercent,
		ComponentRecoveryModes:        input.ComponentRecoveryModes,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"policy": policy, "durable_budgets_reset": false})
}

func (server *Server) writeLoggingSettings(writer http.ResponseWriter, ctx context.Context, settings loggingpkg.Settings, syncRequestState string) {
	effective := make(map[string]string)
	for _, component := range loggingpkg.Components() {
		effective[component] = settings.EffectiveLevel(component, server.now())
	}
	remaining := server.dependencies.Logging.DebugRemaining()
	remainingSeconds := int64(0)
	if remaining > 0 {
		remainingSeconds = int64((remaining + time.Second - 1) / time.Second)
	}
	retention, err := (loggingpkg.RuntimeRepository{Database: server.dependencies.Database}).Get(ctx)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	exportPolicy, err := (loggingpkg.ExportRepository{Database: server.dependencies.Database}).Get(ctx)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"global_level": settings.GlobalLevel, "component_levels": settings.ComponentLevels,
		"effective_levels": effective, "available_components": loggingpkg.Components(),
		"available_categories":  loggingpkg.Categories(),
		"available_base_levels": []string{loggingpkg.LevelError, loggingpkg.LevelWarning, loggingpkg.LevelInfo},
		"debug_components":      settings.DebugComponents, "debug_until": settings.DebugUntil,
		"debug_remaining_seconds":   remainingSeconds,
		"minimum_debug_ttl_seconds": int64(loggingpkg.MinimumDebugTTL / time.Second),
		"maximum_debug_ttl_seconds": int64(loggingpkg.MaximumDebugTTL / time.Second),
		"retention_days":            settings.RetentionDays, "max_disk_usage_bytes": settings.MaxDiskUsageBytes,
		"diagnostic_excerpt_bytes":         settings.DiagnosticExcerptBytes,
		"health_error_aggregation_seconds": settings.HealthErrorAggregationSeconds,
		"audit_minimum_level":              loggingpkg.LevelInfo, "updated_at": settings.UpdatedAt,
		"retention_apply_state": retention.State, "retention_sync_request": syncRequestState,
		"retention_last_error_code": retention.LastErrorCode,
		"retention_desired_sha256":  retention.DesiredSHA256, "retention_applied_sha256": retention.AppliedSHA256,
		"retention_applied_at": retention.AppliedAt,
		"log_export_enabled":   exportPolicy.Enabled, "log_export_state": exportPolicy.State,
		"log_export_desired_generation": exportPolicy.DesiredGeneration,
		"log_export_applied_generation": exportPolicy.AppliedGeneration,
		"log_export_max_file_bytes":     exportPolicy.MaxFileBytes,
		"log_export_max_total_bytes":    exportPolicy.MaxTotalBytes,
		"log_export_max_archive_files":  exportPolicy.MaxArchiveFiles,
		"log_export_retention_days":     exportPolicy.RetentionDays,
		"log_export_categories":         exportPolicy.Categories,
		"log_export_sftp_path":          "/var/log/gateway-vpn/current",
	})
}

func (server *Server) trafficCurrent(writer http.ResponseWriter, request *http.Request) {
	current, err := (traffic.Collector{Database: server.dependencies.Database}).Current(request.Context(), server.now())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"date": current.Date, "upload_bytes": current.UploadBytes, "download_bytes": current.DownloadBytes,
		"service_upload_bytes": current.ServiceUploadBytes, "service_download_bytes": current.ServiceDownloadBytes,
		"mihomo_upload_bytes": current.MihomoUploadBytes, "mihomo_download_bytes": current.MihomoDownloadBytes,
		"current_upload_bps": current.CurrentUploadBPS, "current_download_bps": current.CurrentDownloadBPS,
		"session_upload_bytes": current.SessionUploadBytes, "session_download_bytes": current.SessionDownloadBytes,
		"session_service_upload_bytes": current.SessionServiceUploadBytes, "session_service_download_bytes": current.SessionServiceDownloadBytes,
		"session_started_at": current.SessionStartedAt, "mihomo_available": current.MihomoAvailable,
		"checkpointed_at": current.CheckpointedAt, "per_subscription": nil,
	})
}

func (server *Server) trafficDaily(writer http.ResponseWriter, request *http.Request) {
	from, to := trafficRange(request, server.now())
	items, err := (traffic.Collector{Database: server.dependencies.Database}).Daily(request.Context(), from, to)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "attribution": "TOTAL_ONLY"})
}

func (server *Server) trafficMonthly(writer http.ResponseWriter, request *http.Request) {
	from, to := trafficRange(request, server.now())
	items, err := (traffic.Collector{Database: server.dependencies.Database}).Daily(request.Context(), from, to)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	type total struct{ Upload, Download, ServiceUpload, ServiceDownload uint64 }
	months := make(map[string]total)
	for _, item := range items {
		month := item.Date[:7]
		value := months[month]
		value.Upload += item.UploadBytes
		value.Download += item.DownloadBytes
		value.ServiceUpload += item.ServiceUploadBytes
		value.ServiceDownload += item.ServiceDownloadBytes
		months[month] = value
	}
	keys := make([]string, 0, len(months))
	for month := range months {
		keys = append(keys, month)
	}
	sort.Strings(keys)
	result := make([]map[string]any, 0, len(keys))
	for _, month := range keys {
		value := months[month]
		result = append(result, map[string]any{
			"month": month, "upload_bytes": value.Upload, "download_bytes": value.Download,
			"service_upload_bytes": value.ServiceUpload, "service_download_bytes": value.ServiceDownload,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result, "attribution": "TOTAL_ONLY"})
}

func (server *Server) trafficCSV(writer http.ResponseWriter, request *http.Request) {
	from, to := trafficRange(request, server.now())
	items, err := (traffic.Collector{Database: server.dependencies.Database}).Daily(request.Context(), from, to)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer.Header().Set("Content-Disposition", "attachment; filename=gateway-vpn-traffic.csv")
	writer.WriteHeader(http.StatusOK)
	csvWriter := csv.NewWriter(writer)
	_ = csvWriter.Write([]string{"date", "upload_bytes", "download_bytes", "service_upload_bytes", "service_download_bytes", "mihomo_upload_bytes", "mihomo_download_bytes", "checkpointed_at"})
	for _, item := range items {
		_ = csvWriter.Write([]string{
			item.Date, strconv.FormatUint(item.UploadBytes, 10), strconv.FormatUint(item.DownloadBytes, 10),
			strconv.FormatUint(item.ServiceUploadBytes, 10), strconv.FormatUint(item.ServiceDownloadBytes, 10),
			strconv.FormatUint(item.MihomoUploadBytes, 10), strconv.FormatUint(item.MihomoDownloadBytes, 10), item.CheckpointedAt,
		})
	}
	csvWriter.Flush()
}

func (server *Server) stageNetworkApply(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.NetworkBroker == nil || server.dependencies.NetworkCandidate == nil || server.dependencies.Backups == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Привилегированный сетевой broker не подключён")
		return
	}
	var input struct {
		LANAddress string `json:"lan_address"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	candidate, err := server.dependencies.NetworkCandidate(request.Context(), input.LANAddress)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.stagePreparedNetworkCandidate(writer, request, candidate, "LAN_ADDRESS", "")
}

type ethernetNetworkInput struct {
	AddressMode string   `json:"address_mode"`
	IPv4CIDR    string   `json:"ipv4_cidr"`
	Gateway     string   `json:"gateway"`
	DNS         []string `json:"dns"`
	MTU         int64    `json:"mtu"`
}

func (server *Server) createEthernetUplink(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление Ethernet-выходами не подключено")
		return
	}
	var input struct {
		Name               string `json:"name"`
		NetworkInterfaceID string `json:"network_interface_id"`
		ethernetNetworkInput
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	uplinkID, err := newEthernetUplinkID()
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	candidate, err := server.ethernetCandidate(request, networkapply.EthernetMutation{
		Operation: networkapply.EthernetCreate, UplinkID: uplinkID,
		TargetInterfaceID: input.NetworkInterfaceID, Name: input.Name,
		AddressMode: input.AddressMode, IPv4CIDR: input.IPv4CIDR,
		Gateway: input.Gateway, DNS: input.DNS, MTU: input.MTU,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.stagePreparedNetworkCandidate(writer, request, candidate, networkapply.EthernetCreate, uplinkID)
}

func (server *Server) replaceEthernetInterface(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление Ethernet-выходами не подключено")
		return
	}
	var input struct {
		NetworkInterfaceID        string `json:"network_interface_id"`
		ExpectedDesiredGeneration int64  `json:"expected_desired_generation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	current, err := server.dependencies.Uplinks.Get(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if current.Type != uplink.TypeEthernet {
		writeError(writer, http.StatusConflict, "UPLINK_TYPE_INVALID", "Переназначить сетевую карту можно только для Ethernet-выхода")
		return
	}
	var dns []string
	if err := json.Unmarshal([]byte(current.ConfiguredDNSJSON), &dns); err != nil {
		writeInternalError(writer, err)
		return
	}
	candidate, err := server.ethernetCandidate(request, networkapply.EthernetMutation{
		Operation: networkapply.EthernetReplaceInterface, UplinkID: current.ID,
		ExpectedDesiredGeneration: input.ExpectedDesiredGeneration,
		TargetInterfaceID:         input.NetworkInterfaceID, AddressMode: current.AddressMode,
		IPv4CIDR: current.ConfiguredIPv4CIDR, Gateway: current.ConfiguredGateway, DNS: dns, MTU: current.MTU,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.stagePreparedNetworkCandidate(writer, request, candidate, networkapply.EthernetReplaceInterface, current.ID)
}

func (server *Server) updateEthernetNetwork(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Управление Ethernet-выходами не подключено")
		return
	}
	var input struct {
		ExpectedDesiredGeneration int64 `json:"expected_desired_generation"`
		ethernetNetworkInput
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	current, err := server.dependencies.Uplinks.Get(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if current.Type != uplink.TypeEthernet {
		writeError(writer, http.StatusConflict, "UPLINK_TYPE_INVALID", "IP-настройки применимы только к Ethernet-выходу")
		return
	}
	candidate, err := server.ethernetCandidate(request, networkapply.EthernetMutation{
		Operation: networkapply.EthernetUpdateAddress, UplinkID: current.ID,
		ExpectedDesiredGeneration: input.ExpectedDesiredGeneration,
		TargetInterfaceID:         current.NetworkInterfaceID, AddressMode: input.AddressMode,
		IPv4CIDR: input.IPv4CIDR, Gateway: input.Gateway, DNS: input.DNS, MTU: input.MTU,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.stagePreparedNetworkCandidate(writer, request, candidate, networkapply.EthernetUpdateAddress, current.ID)
}

func (server *Server) deleteEthernetUplink(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Uplinks == nil || server.dependencies.State == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Удаление Ethernet-выходов не подключено")
		return
	}
	if request.Header.Get("X-Confirm-Destructive") != "delete-disabled-ethernet-uplink" {
		writeError(writer, http.StatusConflict, "CONFIRM_DELETE_ETHERNET_UPLINK", "Удаление отключённого Ethernet-выхода требует явного подтверждения")
		return
	}
	var input struct {
		ExpectedDesiredGeneration int64 `json:"expected_desired_generation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	current, err := server.dependencies.Uplinks.Get(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if current.Type != uplink.TypeEthernet {
		writeError(writer, http.StatusConflict, "UPLINK_TYPE_INVALID", "Удалить здесь можно только Ethernet-выход")
		return
	}
	if current.DesiredGeneration != input.ExpectedDesiredGeneration {
		writeDomainError(writer, store.ErrStaleGeneration)
		return
	}
	if current.Enabled {
		writeError(writer, http.StatusConflict, "DISABLE_UPLINK_FIRST", "Перед удалением Ethernet-выход необходимо отключить")
		return
	}
	snapshot, err := server.dependencies.State.Get(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	if snapshot.ActiveUplinkID == current.ID {
		writeError(writer, http.StatusConflict, "ACTIVE_UPLINK_PROTECTED", "Активный Ethernet-выход нельзя удалить")
		return
	}
	candidate, err := server.ethernetCandidate(request, networkapply.EthernetMutation{
		Operation: networkapply.EthernetDelete, UplinkID: current.ID,
		ExpectedDesiredGeneration: current.DesiredGeneration,
		TargetInterfaceID:         current.NetworkInterfaceID,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.stagePreparedNetworkCandidate(writer, request, candidate, networkapply.EthernetDelete, current.ID)
}

func (server *Server) ethernetCandidate(request *http.Request, mutation networkapply.EthernetMutation) (networkapply.Candidate, error) {
	localIP, _, err := confirmationDestination(request.Context(), server.dependencies.Database)
	if err != nil {
		return networkapply.Candidate{}, errors.New("не удалось определить текущий защищённый адрес управления")
	}
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return networkapply.Candidate{}, errors.New("локальный адрес API недоступен")
	}
	_, port, err := net.SplitHostPort(local.String())
	if err != nil || port == "" {
		return networkapply.Candidate{}, errors.New("порт текущего API недоступен")
	}
	return networkapply.Candidate{
		Ethernet: &mutation, ManagementDestinationIP: localIP,
		ManagementURL: "https://" + net.JoinHostPort(localIP, port),
	}, nil
}

func newEthernetUplinkID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("allocate Ethernet uplink id failed")
	}
	return "ethernet-" + hex.EncodeToString(value), nil
}

func (server *Server) stagePreparedNetworkCandidate(writer http.ResponseWriter, request *http.Request, candidate networkapply.Candidate, operation, uplinkID string) {
	if server.dependencies.NetworkBroker == nil || server.dependencies.Backups == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Привилегированный сетевой broker не подключён")
		return
	}
	if !server.beginMaintenanceMutation() {
		writeError(writer, http.StatusConflict, "NETWORK_APPLY_BLOCKED_BY_POWER", "Операция питания уже подтверждена")
		return
	}
	defer server.endMaintenanceMutation()
	snapshot, err := server.dependencies.Backups.Create(request.Context(), backup.KindPreNetworkApply)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "PRE_APPLY_BACKUP_FAILED", "Сетевая операция не начата: проверенный снимок состояния создать не удалось")
		return
	}
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "INFO", Type: "DATABASE_PRE_NETWORK_APPLY_SNAPSHOT_CREATED", Details: map[string]any{"snapshot_id": snapshot.Manifest.SnapshotID, "sha256": snapshot.Manifest.Database.SHA256, "schema_version": snapshot.Manifest.SchemaVersion, "operation": operation, "uplink_id": uplinkID}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	prepared, err := server.dependencies.NetworkBroker.Stage(request.Context(), candidate)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "NETWORK_BROKER_REJECTED", "Сетевая транзакция отклонена")
		return
	}
	writeJSON(writer, http.StatusAccepted, prepared)
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
	broker := server.dependencies.NetworkBroker
	go func(applyID string) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		_ = broker.Apply(ctx, applyID)
	}(prepared.ApplyID)
}

type networkTopologyInput struct {
	ExpectedDesiredGeneration int64                                  `json:"expected_desired_generation"`
	Profile                   string                                 `json:"profile"`
	LANInterfaceIDs           []string                               `json:"lan_interface_ids"`
	ManagementInterfaceIDs    []string                               `json:"management_interface_ids"`
	WGEndpointInterfaceIDs    []string                               `json:"wg_endpoint_interface_ids"`
	SharedOneArmInterfaceID   string                                 `json:"shared_one_arm_interface_id"`
	LANInterfaceName          string                                 `json:"lan_interface_name"`
	LANAddress                string                                 `json:"lan_address"`
	DHCPDNSEnabled            bool                                   `json:"dhcp_dns_enabled"`
	IngressEnabled            bool                                   `json:"ingress_enabled"`
	IngressTopologyMode       string                                 `json:"ingress_topology_mode"`
	IngressListenInterfaces   []networkapply.TopologyListenInterface `json:"ingress_listen_interfaces"`
	AcknowledgedPrerequisites []string                               `json:"acknowledged_prerequisites"`
	RequireWireGuardConfirm   bool                                   `json:"require_wireguard_confirmation"`
}

func (input networkTopologyInput) mutation() networkapply.TopologyMutation {
	return networkapply.TopologyMutation{
		ExpectedDesiredGeneration: input.ExpectedDesiredGeneration,
		Profile:                   input.Profile,
		LANInterfaceIDs:           append([]string(nil), input.LANInterfaceIDs...),
		ManagementInterfaceIDs:    append([]string(nil), input.ManagementInterfaceIDs...),
		WGEndpointInterfaceIDs:    append([]string(nil), input.WGEndpointInterfaceIDs...),
		SharedOneArmInterfaceID:   input.SharedOneArmInterfaceID,
		LANInterfaceName:          input.LANInterfaceName,
		LANAddress:                input.LANAddress,
		DHCPDNSEnabled:            input.DHCPDNSEnabled,
		IngressEnabled:            input.IngressEnabled,
		IngressTopologyMode:       input.IngressTopologyMode,
		IngressListenInterfaces:   append([]networkapply.TopologyListenInterface(nil), input.IngressListenInterfaces...),
		AcknowledgedPrerequisites: append([]string(nil), input.AcknowledgedPrerequisites...),
	}
}

func (server *Server) networkTopology(writer http.ResponseWriter, request *http.Request) {
	var profile, state, lastError, updatedAt string
	var desired, applied int64
	if err := server.dependencies.Database.QueryRowContext(request.Context(), `
SELECT active_profile,desired_generation,applied_generation,state,last_error_code,updated_at
FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state, &lastError, &updatedAt); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"active_profile": profile, "desired_generation": desired, "applied_generation": applied,
		"state": state, "last_error_code": lastError, "updated_at": updatedAt,
		"lan_interface_name": server.dependencies.NetworkInterface,
		"lan_address":        server.dependencies.NetworkLANAddress,
		"profiles": []string{
			networkapply.TopologyEthernetHiLink, networkapply.TopologyEthernetEthernet,
			networkapply.TopologyOneArmWireGuard, networkapply.TopologyMixed,
		},
	})
}

func (server *Server) previewNetworkTopology(writer http.ResponseWriter, request *http.Request) {
	previewer, ok := server.dependencies.NetworkBroker.(TopologyNetworkBroker)
	if !ok {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Проверка topology profile не подключена")
		return
	}
	var input networkTopologyInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	candidate, err := server.topologyCandidate(request, input)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "TOPOLOGY_CANDIDATE_INVALID", err.Error())
		return
	}
	preview, err := previewer.PreviewTopology(request.Context(), candidate)
	if err != nil {
		writeError(writer, http.StatusConflict, "TOPOLOGY_PREVIEW_REJECTED", "Профиль нельзя безопасно применить в текущем состоянии")
		return
	}
	writeJSON(writer, http.StatusOK, preview)
}

func (server *Server) applyNetworkTopology(writer http.ResponseWriter, request *http.Request) {
	var input networkTopologyInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	candidate, err := server.topologyCandidate(request, input)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "TOPOLOGY_CANDIDATE_INVALID", err.Error())
		return
	}
	server.stagePreparedNetworkCandidate(writer, request, candidate, networkapply.OperationTopologyProfile, "")
}

func (server *Server) topologyCandidate(request *http.Request, input networkTopologyInput) (networkapply.Candidate, error) {
	oldPrefix, err := netip.ParsePrefix(server.dependencies.NetworkLANAddress)
	if err != nil || !oldPrefix.Addr().Is4() {
		return networkapply.Candidate{}, errors.New("текущий LAN-адрес Gateway недоступен")
	}
	newPrefix, err := netip.ParsePrefix(input.LANAddress)
	if err != nil || !newPrefix.Addr().Is4() {
		return networkapply.Candidate{}, errors.New("новый LAN-адрес должен быть IPv4 CIDR")
	}
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return networkapply.Candidate{}, errors.New("локальный адрес API недоступен")
	}
	_, port, err := net.SplitHostPort(local.String())
	if err != nil || port == "" {
		return networkapply.Candidate{}, errors.New("порт API недоступен")
	}
	mutation := input.mutation()
	return networkapply.Candidate{
		Topology:                     &mutation,
		OldURL:                       "https://" + net.JoinHostPort(oldPrefix.Addr().String(), port),
		NewURL:                       "https://" + net.JoinHostPort(newPrefix.Addr().String(), port),
		ManagementDestinationIP:      newPrefix.Addr().String(),
		RequireWireGuardConfirmation: input.RequireWireGuardConfirm,
	}, nil
}

func (server *Server) networkSettings(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.NetworkInterface == "" || server.dependencies.NetworkLANAddress == "" {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Сетевые настройки runtime не подключены")
		return
	}
	var activeID, activeState, operationKind, oldURL, newURL, deadline string
	err := server.dependencies.Database.QueryRowContext(request.Context(), `
SELECT id, state, operation_kind, old_url, new_url, rollback_deadline
FROM network_apply_transactions
WHERE state IN (?, ?, ?, ?)
	ORDER BY created_at DESC LIMIT 1`, networkapply.StatePreparing, networkapply.StateArmed, networkapply.StateApplied, networkapply.StateConfirming).Scan(&activeID, &activeState, &operationKind, &oldURL, &newURL, &deadline)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"interface_name": server.dependencies.NetworkInterface,
		"lan_address":    server.dependencies.NetworkLANAddress,
		"active_apply":   map[string]any{"apply_id": activeID, "state": activeState, "operation_kind": operationKind, "old_url": oldURL, "new_url": newURL, "rollback_deadline": deadline},
	})
}

func (server *Server) networkApplyStatus(writer http.ResponseWriter, request *http.Request) {
	var item struct {
		ID, State, OperationKind, CandidateJSON, OldURL, NewURL, RollbackDeadline, ErrorCode, CreatedAt, UpdatedAt, ConfirmedAt, RolledBackAt string
	}
	var errorCode, confirmedAt, rolledBackAt sql.NullString
	err := server.dependencies.Database.QueryRowContext(request.Context(), `
SELECT id, state, operation_kind, candidate_json, old_url, new_url, rollback_deadline, error_code,
       created_at, updated_at, confirmed_at, rolled_back_at
FROM network_apply_transactions WHERE id=?`, request.PathValue("id")).Scan(
		&item.ID, &item.State, &item.OperationKind, &item.CandidateJSON, &item.OldURL, &item.NewURL, &item.RollbackDeadline,
		&errorCode, &item.CreatedAt, &item.UpdatedAt, &confirmedAt, &rolledBackAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", "Операция не найдена")
		return
	}
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	item.ErrorCode, item.ConfirmedAt, item.RolledBackAt = errorCode.String, confirmedAt.String, rolledBackAt.String
	var ethernetOperation, uplinkID, topologyProfile string
	var topologyGeneration int64
	if item.OperationKind == networkapply.OperationEthernetUplink {
		var candidate networkapply.EthernetMutation
		if err := json.Unmarshal([]byte(item.CandidateJSON), &candidate); err == nil {
			ethernetOperation, uplinkID = candidate.Operation, candidate.UplinkID
		}
	} else if item.OperationKind == networkapply.OperationTopologyProfile {
		var candidate networkapply.TopologyMutation
		if err := json.Unmarshal([]byte(item.CandidateJSON), &candidate); err == nil {
			topologyProfile, topologyGeneration = candidate.Profile, candidate.ExpectedDesiredGeneration
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"apply_id": item.ID, "state": item.State, "operation_kind": item.OperationKind,
		"ethernet_operation": ethernetOperation, "uplink_id": uplinkID,
		"topology_profile": topologyProfile, "topology_expected_generation": topologyGeneration,
		"old_url": item.OldURL, "new_url": item.NewURL,
		"rollback_deadline": item.RollbackDeadline, "error_code": item.ErrorCode,
		"created_at": item.CreatedAt, "updated_at": item.UpdatedAt,
		"confirmed_at": item.ConfirmedAt, "rolled_back_at": item.RolledBackAt,
	})
}

func (server *Server) confirmNetworkApply(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.NetworkBroker == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Привилегированный сетевой broker не подключён")
		return
	}
	var input struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	localIP, viaWireGuard, err := confirmationDestination(request.Context(), server.dependencies.Database)
	if err != nil {
		writeError(writer, http.StatusForbidden, "CONFIRM_SOURCE_INVALID", "Подтверждение должно прийти через новый адрес или WireGuard")
		return
	}
	err = server.dependencies.NetworkBroker.Confirm(request.Context(), request.PathValue("id"), networkapply.ConfirmEvidence{Token: input.ConfirmToken, LocalDestinationIP: localIP, ViaWireGuard: viaWireGuard})
	if err != nil {
		writeError(writer, http.StatusForbidden, "CONFIRMATION_REJECTED", "Подтверждение сетевой транзакции отклонено")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func confirmationDestination(ctx context.Context, database *sql.DB) (string, bool, error) {
	local, ok := ctx.Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return "", false, errors.New("HTTP local destination is unavailable")
	}
	host, _, err := net.SplitHostPort(local.String())
	if err != nil {
		return "", false, errors.New("HTTP local destination is invalid")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return "", false, errors.New("HTTP local destination is not private IPv4")
	}
	wireGuard := netip.MustParsePrefix("10.80.0.0/24").Contains(address)
	if !wireGuard && database != nil {
		var ingressCIDR string
		err := database.QueryRowContext(ctx, `
SELECT subnet_cidr FROM wireguard_ingress_servers
WHERE enabled=1 ORDER BY created_at, id LIMIT 1`).Scan(&ingressCIDR)
		if err == nil {
			wireGuard = wireGuardConfirmationAddress(address, ingressCIDR)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", false, errors.New("configured WireGuard confirmation subnet is unavailable")
		}
	}
	return address.String(), wireGuard, nil
}

func wireGuardConfirmationAddress(address netip.Addr, subnetCIDR string) bool {
	prefix, err := netip.ParsePrefix(subnetCIDR)
	return err == nil && prefix == prefix.Masked() && prefix.Addr().Is4() && prefix.Addr().IsPrivate() && prefix.Contains(address)
}

func trafficRange(request *http.Request, now time.Time) (string, string) {
	to := request.URL.Query().Get("to")
	if to == "" {
		to = now.UTC().Format("2006-01-02")
	}
	from := request.URL.Query().Get("from")
	if from == "" {
		from = now.UTC().AddDate(0, -1, 0).Format("2006-01-02")
	}
	return from, to
}

func (server *Server) now() time.Time {
	if server.dependencies.Now != nil {
		return server.dependencies.Now().UTC()
	}
	return time.Now().UTC()
}

func (server *Server) beginMaintenanceMutation() bool {
	server.maintenanceMutex.Lock()
	defer server.maintenanceMutex.Unlock()
	if server.powerPending {
		return false
	}
	server.maintenanceMutations++
	return true
}

func (server *Server) endMaintenanceMutation() {
	server.maintenanceMutex.Lock()
	defer server.maintenanceMutex.Unlock()
	if server.maintenanceMutations > 0 {
		server.maintenanceMutations--
	}
}

func (server *Server) reservePowerAction() bool {
	server.maintenanceMutex.Lock()
	defer server.maintenanceMutex.Unlock()
	if server.powerPending || server.maintenanceMutations != 0 {
		return false
	}
	server.powerPending = true
	return true
}

func (server *Server) releasePowerAction() {
	server.maintenanceMutex.Lock()
	server.powerPending = false
	server.maintenanceMutex.Unlock()
}

func effectivePathState(cell pathmatrix.Cell, now time.Time) (string, string) {
	if cell.State == pathmatrix.StateQualified || cell.State == pathmatrix.StateDegraded {
		expires, err := time.Parse(time.RFC3339Nano, cell.ExpiresAt)
		if err != nil || !expires.After(now) {
			return pathmatrix.StateStale, "RESULT_EXPIRED"
		}
		if cell.State == pathmatrix.StateQualified {
			return cell.State, "FRESH_FULL"
		}
		return cell.State, "FRESH_LIMITED"
	}
	return cell.State, cell.State
}

func decodeJSON(request *http.Request, destination any) error {
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeDomainError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, http.StatusNotFound, "NOT_FOUND", "Объект не найден")
	case errors.Is(err, store.ErrPrioritySetMismatch):
		writeError(writer, http.StatusConflict, "PRIORITY_SET_MISMATCH", "Список приоритетов не совпадает с активными объектами")
	case errors.Is(err, store.ErrStaleGeneration):
		writeError(writer, http.StatusConflict, "STALE_GENERATION", "Состояние изменилось; обновите страницу")
	case errors.Is(err, bypass.ErrLastRequiredConfirmation):
		writeError(writer, http.StatusConflict, "CONFIRM_LAST_REQUIRED_TARGET", "Отключение, изменение или удаление последнего обязательного ресурса требует явного подтверждения")
	default:
		writeError(writer, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	}
}

func writeAuthManagementError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		writer.Header().Set("Retry-After", "2")
		writeError(writer, http.StatusTooManyRequests, "REAUTH_RATE_LIMITED", "Слишком много неверных попыток; повторите позже")
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(writer, http.StatusUnauthorized, "REAUTH_FAILED", "Текущий пароль указан неверно")
	case errors.Is(err, auth.ErrInvalidSession):
		writeError(writer, http.StatusUnauthorized, "SESSION_INVALID", "Сессия истекла или отозвана")
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, http.StatusNotFound, "NOT_FOUND", "Пользователь или сессия не найдены")
	case errors.Is(err, auth.ErrInvalidUsername):
		writeError(writer, http.StatusBadRequest, "INVALID_USERNAME", "Имя должно содержать 3–64 ASCII-символа: буквы, цифры, точку, дефис или подчёркивание; первый символ — буква или цифра")
	case errors.Is(err, auth.ErrInvalidPassword):
		writeError(writer, http.StatusBadRequest, "INVALID_PASSWORD", "Пароль должен содержать от 12 до 1024 байт")
	case errors.Is(err, auth.ErrUsernameExists):
		writeError(writer, http.StatusConflict, "USERNAME_EXISTS", "Пользователь с таким именем уже существует")
	case errors.Is(err, auth.ErrNoUserChanges):
		writeError(writer, http.StatusBadRequest, "NO_CHANGES", "Не указаны изменения пользователя")
	case errors.Is(err, auth.ErrSelfUserMutation):
		writeError(writer, http.StatusConflict, "CURRENT_USER_PROTECTED", "Текущего пользователя нельзя отключить или удалить")
	case errors.Is(err, auth.ErrLastEnabledUser):
		writeError(writer, http.StatusConflict, "LAST_ENABLED_USER", "Нельзя отключить последнего активного администратора")
	case errors.Is(err, auth.ErrUserMustBeDisabled):
		writeError(writer, http.StatusConflict, "USER_MUST_BE_DISABLED", "Перед удалением пользователя необходимо отключить")
	case errors.Is(err, auth.ErrSelfPasswordReset):
		writeError(writer, http.StatusConflict, "USE_OWN_PASSWORD_CHANGE", "Собственный пароль изменяется только с вводом текущего пароля")
	case errors.Is(err, auth.ErrPasswordUnchanged):
		writeError(writer, http.StatusBadRequest, "PASSWORD_UNCHANGED", "Новый пароль должен отличаться от текущего")
	case errors.Is(err, auth.ErrCredentialsChanged):
		writeError(writer, http.StatusConflict, "CREDENTIALS_CHANGED", "Учётные данные уже изменились; обновите страницу")
	case errors.Is(err, auth.ErrInvalidSessionID):
		writeError(writer, http.StatusBadRequest, "INVALID_SESSION_ID", "Некорректный идентификатор сессии")
	default:
		writeInternalError(writer, err)
	}
}

func writeInternalError(writer http.ResponseWriter, _ error) {
	writeError(writer, http.StatusInternalServerError, "INTERNAL_ERROR", "Внутренняя ошибка Gateway VPN")
}

func newID(prefix string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic("crypto/rand unavailable")
	}
	return prefix + "-" + hex.EncodeToString(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(writer, request)
	})
}
