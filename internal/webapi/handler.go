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
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/hilink"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/traffic"
	updatepkg "gateway-vpn/internal/update"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

const sessionCookieName = "gateway_vpn_session"

//go:embed static/*
var staticFiles embed.FS

type Dependencies struct {
	Database                *sql.DB
	Auth                    auth.Service
	State                   *state.Repository
	Modems                  *modem.Repository
	Discoveries             *hilink.DiscoveryRegistry
	WireGuardRuntime        *wireguardpkg.RuntimeStore
	WireGuardConfigPath     string
	WireGuardSync           WireGuardSynchronizer
	ModemRuntime            ModemRuntime
	ModemReconcile          func(context.Context) (hilink.CycleResult, error)
	ModemPathProbe          ModemPathProber
	PathOperations          PathOperator
	PathActivator           ManualPathActivator
	Subscriptions           *subscription.Repository
	Nodes                   *subscription.NodeRepository
	Paths                   *pathmatrix.Repository
	Targets                 *bypass.Repository
	Matchers                *subscription.MatcherRepository
	SubscriptionRefresh     SubscriptionRefresher
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
	UpdateApply             UpdateApplyTrigger
	Now                     func() time.Time
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

type NetworkBroker interface {
	Stage(context.Context, networkapply.Candidate) (networkapply.Prepared, error)
	Apply(context.Context, string) error
	Confirm(context.Context, string, networkapply.ConfirmEvidence) error
}

type SubscriptionRefresher interface {
	RefreshOne(context.Context, string, bool) (subscription.RefreshResult, error)
	ReclassifyOne(context.Context, string) (subscription.RefreshResult, error)
}

type WireGuardSynchronizer interface {
	SyncWireGuard(context.Context) error
}

type ModemRuntime interface {
	BlockPath(context.Context) error
	SyncRouting(context.Context) error
	SyncWireGuard(context.Context) error
}

type ModemPathProber interface {
	RequalifyModem(context.Context, string) (candidateruntime.RequalificationResult, error)
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
	matcherPreviewSecret  []byte
	journalLimiter        *journalRateLimiter
	diagnosticLimiter     *diagnosticRateLimiter
	snapshotLimiter       *diagnosticRateLimiter
	portableBackupLimiter *diagnosticRateLimiter
	updateLimiter         *diagnosticRateLimiter
}

type contextKey string

const principalKey contextKey = "principal"

func New(dependencies Dependencies) (*Server, error) {
	if dependencies.Database == nil || dependencies.Auth.Database == nil || dependencies.State == nil || dependencies.Modems == nil || dependencies.Subscriptions == nil || dependencies.Nodes == nil || dependencies.Paths == nil || dependencies.Targets == nil || dependencies.Matchers == nil {
		return nil, errors.New("complete Web API dependencies are required")
	}
	previewSecret := make([]byte, 32)
	if _, err := rand.Read(previewSecret); err != nil {
		return nil, errors.New("initialize matcher preview protection failed")
	}
	server := &Server{dependencies: dependencies, matcherPreviewSecret: previewSecret, journalLimiter: newJournalRateLimiter(), diagnosticLimiter: newDiagnosticRateLimiter(), snapshotLimiter: newDiagnosticRateLimiter(), portableBackupLimiter: newDiagnosticRateLimiter(), updateLimiter: newDiagnosticRateLimiter()}
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
	mux.Handle("GET /api/v1/wireguard/status", server.protected(http.HandlerFunc(server.wireGuardStatus)))
	mux.Handle("GET /api/v1/settings/wireguard", server.protected(http.HandlerFunc(server.wireGuardSettings)))
	mux.Handle("PUT /api/v1/settings/wireguard", server.protected(http.HandlerFunc(server.updateWireGuardSettings)))
	mux.Handle("POST /api/v1/gateway/reconcile", server.protected(http.HandlerFunc(server.reconcile)))
	mux.Handle("GET /api/v1/modems", server.protected(http.HandlerFunc(server.modems)))
	mux.Handle("PUT /api/v1/modems/priorities", server.protected(http.HandlerFunc(server.reorderModems)))
	mux.Handle("PATCH /api/v1/modems/{id}", server.protected(http.HandlerFunc(server.updateModem)))
	mux.Handle("POST /api/v1/modems/{id}/enable", server.protected(http.HandlerFunc(server.enableModem)))
	mux.Handle("POST /api/v1/modems/{id}/disable", server.protected(http.HandlerFunc(server.disableModem)))
	mux.Handle("POST /api/v1/modems/{id}/probe", server.protected(http.HandlerFunc(server.probeModem)))
	mux.Handle("POST /api/v1/modems/{id}/recover", server.protected(http.HandlerFunc(server.recoverModem)))
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
	mux.Handle("GET /api/v1/nodes", server.protected(http.HandlerFunc(server.nodes)))
	mux.Handle("PATCH /api/v1/nodes/{id}", server.protected(http.HandlerFunc(server.updateNode)))
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
	mux.Handle("GET /api/v1/health/periodic", server.protected(http.HandlerFunc(server.periodicHealth)))
	mux.Handle("GET /api/v1/settings/logging", server.protected(http.HandlerFunc(server.loggingSettings)))
	mux.Handle("PUT /api/v1/settings/logging", server.protected(http.HandlerFunc(server.updateLoggingSettings)))
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
		"active_modem_id": snapshot.ActiveModemID, "active_path_id": snapshot.ActivePathID,
		"management_modem_id":    snapshot.ManagementModemID,
		"active_subscription_id": snapshot.ActiveSubscriptionID, "active_node_id": snapshot.ActiveNodeID,
		"config_generation":            snapshot.ConfigGeneration,
		"policy_transition_generation": snapshot.PolicyTransitionGeneration,
		"policy_transition_started_at": snapshot.PolicyTransitionStartedAt,
		"policy_transition_deadline":   snapshot.PolicyTransitionDeadline,
		"updated_at":                   snapshot.UpdatedAt,
	})
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

func (server *Server) modems(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Modems.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]any{
			"id": item.ID, "number": item.DisplayNumber, "name": item.Name,
			"operator_label": item.OperatorLabel, "observed_operator": item.ObservedOperator,
			"enabled": item.Enabled, "priority": item.Priority, "interface_name": item.InterfaceName,
			"management_cidr": item.ManagementCIDR, "gateway": item.Gateway, "mtu": item.MTU,
			"routing_table_id": item.RoutingTableID, "fwmark": item.Fwmark,
			"state": item.State, "telemetry_state": item.TelemetryState,
			"management_reachability_state": item.ManagementReachabilityState,
			"last_seen_at":                  item.LastSeenAt, "stable_since": item.StableSince,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
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
	if err := server.dependencies.Modems.ReorderEnabled(request.Context(), input.IDs); err != nil {
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
		if snapshot.ActiveModemID == id {
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
	if err := server.dependencies.Modems.SetRecovering(request.Context(), id); err != nil {
		writeDomainError(writer, err)
		return
	}
	result, err := server.reconcileModemInventory(request.Context())
	if err != nil {
		writeJSON(writer, http.StatusAccepted, map[string]any{"recovery": "RETRY_PENDING", "convergence": server.convergeModemRuntime(request.Context())})
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"recovery": "RECONCILED", "ready": containsString(result.ReadyModems, id), "convergence": server.convergeModemRuntime(request.Context())})
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
		activeModemID = snapshot.ActiveModemID
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
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
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
			"external_name": item.ExternalName, "proxy_type": item.ProxyType, "candidate": item.Enabled,
			"selection_override": item.SelectionOverride, "candidate_source": item.CandidateSource,
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

func (server *Server) refreshSubscription(writer http.ResponseWriter, request *http.Request) {
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

func (server *Server) matrix(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Paths.List(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	now := server.now()
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		effectiveState, reason := effectivePathState(item, now)
		result = append(result, map[string]any{
			"id": item.ID, "modem_id": item.ModemID, "modem_number": item.ModemDisplayNumber,
			"modem_name": item.ModemName, "modem_priority": item.ModemPriority,
			"subscription_id": item.SubscriptionID, "subscription_name": item.SubscriptionName,
			"subscription_priority": item.SubscriptionPriority, "state": effectiveState,
			"stored_state": item.State, "reason_code": reason, "transport_state": item.TransportState,
			"selected_node_id": item.SelectedNodeID, "candidate_nodes": item.CandidateNodes,
			"qualified_nodes": item.QualifiedNodes, "required_targets_passed": item.RequiredTargetsPassed,
			"required_targets_total": item.RequiredTargetsTotal, "latency_ms": item.LatencyMS,
			"policy_generation": item.PolicyGeneration, "route_generation": item.RouteGeneration,
			"last_checked_at": item.LastCheckedAt, "expires_at": item.ExpiresAt,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": result})
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
		"node_id": result.Candidate.NodeID, "modem_id": result.Candidate.ModemID,
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
	created, err := server.dependencies.Targets.Create(request.Context(), bypass.CreateInput{ID: newID("target"), Name: input.Name, Kind: input.Kind, Value: input.Value, Required: input.Required, Timeout: time.Duration(input.TimeoutSeconds) * time.Second, SuccessMode: input.SuccessMode, ExpectedStatus: input.ExpectedStatus, ExpectedBodySubstring: input.ExpectedBodySubstring})
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
	err := server.dependencies.Targets.Update(request.Context(), request.PathValue("id"), bypass.UpdateInput{Name: input.Name, Kind: input.Kind, Value: input.Value, Enabled: input.Enabled, Required: input.Required, Timeout: time.Duration(input.TimeoutSeconds) * time.Second, SuccessMode: input.SuccessMode, ExpectedStatus: input.ExpectedStatus, ExpectedBodySubstring: input.ExpectedBodySubstring, AllowNoRequired: confirmsNoRequiredTargets(request)})
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
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"target_id": target.ID, "scope": "ALL_ELIGIBLE_PATHS",
		"qualification": server.requalifyReadyModems(request.Context()),
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
		Passphrase             string `json:"passphrase"`
		PassphraseConfirmation string `json:"passphrase_confirmation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректные параметры резервной копии")
		return
	}
	if input.Passphrase != input.PassphraseConfirmation || backup.ValidatePassphrase(input.Passphrase) != nil {
		writeError(writer, http.StatusBadRequest, "BACKUP_PASSPHRASE_INVALID", "Passphrase должна совпадать и содержать 12–256 UTF-8 байт")
		return
	}
	principal, ok := request.Context().Value(principalKey).(auth.Principal)
	if !ok || principal.SessionHash == "" || principal.UserID == "" {
		writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход")
		return
	}
	if allowed, retry := server.portableBackupLimiter.allow(principal.SessionHash, server.now()); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(writer, http.StatusTooManyRequests, "BACKUP_RATE_LIMITED", "Слишком много операций резервного копирования")
		return
	}
	passphrase := input.Passphrase
	input.Passphrase, input.PassphraseConfirmation = "", ""
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
	writeJSON(writer, http.StatusOK, map[string]any{"pending": pending, "operation": operation, "apply_available": server.dependencies.RestoreApply != nil})
}

func (server *Server) stageRestore(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Restores == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Восстановление не подключено")
		return
	}
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
	if err != nil || !pending || operation.State != "STAGED" || input.RestoreID != operation.RestoreID {
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

func (server *Server) stageUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Updates == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Подписанные обновления не подключены")
		return
	}
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
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "WARNING", Type: "SIGNED_UPDATE_STAGED", Details: map[string]any{"user_id": principal.UserID, "update_id": operation.UpdateID, "gateway_version": operation.GatewayVersion, "mihomo_version": operation.MihomoVersion, "signer_key_sha256": operation.SignerKeySHA256, "manifest_sha256": operation.ManifestSHA256, "bytes": operation.UncompressedBytes, "file_count": operation.FileCount}}); err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, operation)
}

func (server *Server) applyUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.Updates == nil || server.dependencies.UpdateApply == nil || server.dependencies.ModemRuntime == nil {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Применение подписанных обновлений не подключено")
		return
	}
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
		"component": true, "modem_id": true, "subscription_id": true,
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
		Component: request.URL.Query().Get("component"), ModemID: request.URL.Query().Get("modem_id"),
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
	writeJSON(writer, http.StatusOK, map[string]any{
		"global_level": settings.GlobalLevel, "component_levels": settings.ComponentLevels,
		"effective_levels": effective, "available_components": loggingpkg.Components(),
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
	})
}

func (server *Server) trafficCurrent(writer http.ResponseWriter, request *http.Request) {
	date := server.now().Format("2006-01-02")
	items, err := (traffic.Collector{Database: server.dependencies.Database}).Daily(request.Context(), date, date)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	if len(items) == 0 {
		writeJSON(writer, http.StatusOK, map[string]any{"date": date, "upload_bytes": 0, "download_bytes": 0, "per_subscription": nil})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"date": date, "upload_bytes": items[0].UploadBytes, "download_bytes": items[0].DownloadBytes, "checkpointed_at": items[0].CheckpointedAt, "per_subscription": nil})
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
	type total struct{ Upload, Download uint64 }
	months := make(map[string]total)
	for _, item := range items {
		month := item.Date[:7]
		value := months[month]
		value.Upload += item.UploadBytes
		value.Download += item.DownloadBytes
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
		result = append(result, map[string]any{"month": month, "upload_bytes": value.Upload, "download_bytes": value.Download})
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
	_ = csvWriter.Write([]string{"date", "upload_bytes", "download_bytes", "mihomo_upload_bytes", "mihomo_download_bytes", "checkpointed_at"})
	for _, item := range items {
		_ = csvWriter.Write([]string{item.Date, strconv.FormatUint(item.UploadBytes, 10), strconv.FormatUint(item.DownloadBytes, 10), strconv.FormatUint(item.MihomoUploadBytes, 10), strconv.FormatUint(item.MihomoDownloadBytes, 10), item.CheckpointedAt})
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
	snapshot, err := server.dependencies.Backups.Create(request.Context(), backup.KindPreNetworkApply)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "PRE_APPLY_BACKUP_FAILED", "Сетевая операция не начата: проверенный снимок состояния создать не удалось")
		return
	}
	if err := server.dependencies.State.AppendEvent(request.Context(), state.EventInput{Severity: "INFO", Type: "DATABASE_PRE_NETWORK_APPLY_SNAPSHOT_CREATED", Details: map[string]any{"snapshot_id": snapshot.Manifest.SnapshotID, "sha256": snapshot.Manifest.Database.SHA256, "schema_version": snapshot.Manifest.SchemaVersion}}); err != nil {
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

func (server *Server) networkSettings(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.NetworkInterface == "" || server.dependencies.NetworkLANAddress == "" {
		writeError(writer, http.StatusNotImplemented, "NOT_AVAILABLE", "Сетевые настройки runtime не подключены")
		return
	}
	var activeID, activeState, oldURL, newURL, deadline string
	err := server.dependencies.Database.QueryRowContext(request.Context(), `
SELECT id, state, old_url, new_url, rollback_deadline
FROM network_apply_transactions
WHERE state IN (?, ?, ?, ?)
ORDER BY created_at DESC LIMIT 1`, networkapply.StatePreparing, networkapply.StateArmed, networkapply.StateApplied, networkapply.StateConfirming).Scan(&activeID, &activeState, &oldURL, &newURL, &deadline)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"interface_name": server.dependencies.NetworkInterface,
		"lan_address":    server.dependencies.NetworkLANAddress,
		"active_apply":   map[string]any{"apply_id": activeID, "state": activeState, "old_url": oldURL, "new_url": newURL, "rollback_deadline": deadline},
	})
}

func (server *Server) networkApplyStatus(writer http.ResponseWriter, request *http.Request) {
	var item struct {
		ID, State, OldURL, NewURL, RollbackDeadline, ErrorCode, CreatedAt, UpdatedAt, ConfirmedAt, RolledBackAt string
	}
	var errorCode, confirmedAt, rolledBackAt sql.NullString
	err := server.dependencies.Database.QueryRowContext(request.Context(), `
SELECT id, state, old_url, new_url, rollback_deadline, error_code,
       created_at, updated_at, confirmed_at, rolled_back_at
FROM network_apply_transactions WHERE id=?`, request.PathValue("id")).Scan(
		&item.ID, &item.State, &item.OldURL, &item.NewURL, &item.RollbackDeadline,
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
	writeJSON(writer, http.StatusOK, map[string]any{
		"apply_id": item.ID, "state": item.State, "old_url": item.OldURL, "new_url": item.NewURL,
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
	localIP, viaWireGuard, err := confirmationDestination(request.Context())
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

func confirmationDestination(ctx context.Context) (string, bool, error) {
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
	return address.String(), wireGuard, nil
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

func effectivePathState(cell pathmatrix.Cell, now time.Time) (string, string) {
	if cell.State == pathmatrix.StateQualified && cell.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, cell.ExpiresAt)
		if err != nil || !expires.After(now) {
			return pathmatrix.StateStale, "RESULT_EXPIRED"
		}
		return cell.State, "FRESH_QUALIFIED"
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
