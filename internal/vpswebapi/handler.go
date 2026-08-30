// Package vpswebapi exposes the restricted VPS Hub API and embedded WebUI.
// It deliberately has its own cookie, database and backup role and must be
// bound only to localhost or an administrator WireGuard address.
package vpswebapi

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsbackup"
	"gateway-vpn/internal/vpsfabric"
)

const sessionCookieName = "gateway_vpn_vps_session"

type contextKey string

const principalKey contextKey = "vps-principal"

//go:embed static/*
var staticFiles embed.FS

type RestoreApplyTrigger interface {
	ApplyPendingVPSRestore(context.Context) error
}

type FabricApplyTrigger interface {
	ApplyVPSFabric(context.Context) error
}

type Dependencies struct {
	Database     *sql.DB
	Auth         auth.Service
	Backups      *vpsbackup.Manager
	Restores     *vpsbackup.RestoreManager
	Hub          vpsagent.HubRepository
	AdminKeys    *vpsagent.AdminKeyManager
	RestoreApply RestoreApplyTrigger
	FabricApply  FabricApplyTrigger
	// FabricStatusPath contains display-only telemetry written by the root
	// watchdog. It is never used to authorize a privileged host mutation.
	FabricStatusPath string
	Now              func() time.Time
}

type Server struct {
	dependencies Dependencies
	handler      http.Handler
}

func New(dependencies Dependencies) (*Server, error) {
	if dependencies.Database == nil || dependencies.Auth.Database == nil || dependencies.Backups == nil || dependencies.Restores == nil {
		return nil, errors.New("complete VPS Hub Web API dependencies are required")
	}
	if dependencies.Hub.Database == nil {
		dependencies.Hub.Database = dependencies.Database
	}
	if dependencies.Hub.Now == nil && dependencies.Now != nil {
		dependencies.Hub.Now = dependencies.Now
	}
	dependencies.Hub.HostApplyAvailable = dependencies.FabricApply != nil
	server := &Server{dependencies: dependencies}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", server.login)
	mux.Handle("POST /api/v1/auth/logout", server.protected(http.HandlerFunc(server.logout)))
	mux.Handle("GET /api/v1/auth/session", server.protected(http.HandlerFunc(server.session)))
	mux.Handle("PUT /api/v1/auth/password", server.protected(http.HandlerFunc(server.changePassword)))
	mux.HandleFunc("POST /api/v1/pairing/complete", server.completePairing)
	mux.Handle("GET /api/v1/hub/overview", server.protected(http.HandlerFunc(server.hubOverview)))
	mux.Handle("GET /api/v1/hub/pairing-invitations", server.protected(http.HandlerFunc(server.listPairingInvitations)))
	mux.Handle("POST /api/v1/hub/pairing-invitations", server.protected(http.HandlerFunc(server.createPairingInvitation)))
	mux.Handle("DELETE /api/v1/hub/pairing-invitations/{id}", server.protected(http.HandlerFunc(server.rejectPairingInvitation)))
	mux.Handle("GET /api/v1/hub/gateways", server.protected(http.HandlerFunc(server.listGateways)))
	mux.Handle("POST /api/v1/hub/gateways/{id}/revoke", server.protected(http.HandlerFunc(server.revokeGateway)))
	mux.Handle("GET /api/v1/hub/admins", server.protected(http.HandlerFunc(server.listAdmins)))
	mux.Handle("POST /api/v1/hub/admins", server.protected(http.HandlerFunc(server.createAdmin)))
	mux.Handle("POST /api/v1/hub/admins/{id}/config", server.protected(http.HandlerFunc(server.downloadAdminConfig)))
	mux.Handle("POST /api/v1/hub/admins/{id}/rotate", server.protected(http.HandlerFunc(server.rotateAdmin)))
	mux.Handle("POST /api/v1/hub/admins/{id}/revoke", server.protected(http.HandlerFunc(server.revokeAdmin)))
	mux.Handle("PUT /api/v1/hub/admins/{id}/trust-mode", server.protected(http.HandlerFunc(server.updateAdminTrustMode)))
	mux.Handle("GET /api/v1/hub/admin-relays", server.protected(http.HandlerFunc(server.listAdminRelays)))
	mux.Handle("POST /api/v1/hub/admin-relays", server.protected(http.HandlerFunc(server.createAdminRelay)))
	mux.Handle("PUT /api/v1/hub/admin-relays/{id}/enabled", server.protected(http.HandlerFunc(server.setAdminRelayEnabled)))
	mux.Handle("DELETE /api/v1/hub/admin-relays/{id}", server.protected(http.HandlerFunc(server.deleteAdminRelay)))
	mux.Handle("GET /api/v1/hub/resources", server.protected(http.HandlerFunc(server.listResources)))
	mux.Handle("POST /api/v1/hub/resources", server.protected(http.HandlerFunc(server.createResource)))
	mux.Handle("PUT /api/v1/hub/resources/{id}", server.protected(http.HandlerFunc(server.updateResource)))
	mux.Handle("DELETE /api/v1/hub/resources/{id}", server.protected(http.HandlerFunc(server.deleteResource)))
	mux.Handle("GET /api/v1/hub/access-matrix", server.protected(http.HandlerFunc(server.accessMatrix)))
	mux.Handle("POST /api/v1/hub/acl", server.protected(http.HandlerFunc(server.createACL)))
	mux.Handle("DELETE /api/v1/hub/acl/{id}", server.protected(http.HandlerFunc(server.deleteACL)))
	mux.Handle("GET /api/v1/hub/watchdog", server.protected(http.HandlerFunc(server.hubWatchdog)))
	mux.Handle("POST /api/v1/hub/fabric/apply", server.protected(http.HandlerFunc(server.applyFabric)))
	mux.Handle("GET /api/v1/vps/backup/status", server.protected(http.HandlerFunc(server.backupStatus)))
	mux.Handle("POST /api/v1/vps/backup/download", server.protected(http.HandlerFunc(server.downloadBackup)))
	mux.Handle("POST /api/v1/vps/restore/stage", server.protected(http.HandlerFunc(server.stageRestore)))
	mux.Handle("POST /api/v1/vps/restore/apply", server.protected(http.HandlerFunc(server.applyRestore)))
	mux.Handle("DELETE /api/v1/vps/restore", server.protected(http.HandlerFunc(server.discardRestore)))
	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /", http.FileServer(http.FS(staticRoot)))
	server.handler = securityHeaders(mux)
	return server, nil
}

func (server *Server) Handler() http.Handler { return server.handler }

func (server *Server) login(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(request, &input, 4096); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректный запрос входа")
		return
	}
	session, err := server.dependencies.Auth.Login(request.Context(), input.Username, input.Password, request.RemoteAddr+"\x00"+request.UserAgent())
	input.Password = ""
	if errors.Is(err, auth.ErrRateLimited) {
		writer.Header().Set("Retry-After", "2")
		writeError(writer, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "Слишком много попыток входа")
		return
	}
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Неверное имя пользователя или пароль")
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: session.Token, Path: "/", Expires: session.ExpiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(writer, http.StatusOK, sessionResponse(session.UserID, session.Username, session.ID, session.CSRFToken, session.MustChangePassword, session.ExpiresAt))
}

func (server *Server) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "Требуется вход в VPS Hub")
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
			writeError(writer, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Перед продолжением замените временный пароль VPS Hub")
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
		writeError(writer, http.StatusServiceUnavailable, "SESSION_UPDATE_FAILED", "Не удалось обновить сессию")
		return
	}
	writeJSON(writer, http.StatusOK, sessionResponse(principal.UserID, principal.Username, principal.SessionHash, csrf, principal.MustChangePassword, principal.ExpiresAt))
}

func (server *Server) changePassword(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		CurrentPassword      string `json:"current_password"`
		NewPassword          string `json:"new_password"`
		PasswordConfirmation string `json:"password_confirmation"`
	}
	if err := decodeJSON(request, &input, 4096); err != nil || input.NewPassword != input.PasswordConfirmation {
		writeError(writer, http.StatusBadRequest, "PASSWORD_CONFIRMATION_MISMATCH", "Новый пароль и подтверждение не совпадают")
		return
	}
	err := server.dependencies.Auth.ChangePassword(request.Context(), principal, input.CurrentPassword, input.NewPassword)
	input.CurrentPassword, input.NewPassword, input.PasswordConfirmation = "", "", ""
	if err != nil {
		writeError(writer, http.StatusBadRequest, "PASSWORD_CHANGE_FAILED", "Пароль не изменён; проверьте текущий и новый пароль")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) completePairing(writer http.ResponseWriter, request *http.Request) {
	var input vpsagent.PairingCompletion
	if err := decodeJSON(request, &input, 8192); err != nil {
		writeError(writer, http.StatusBadRequest, "PAIRING_REQUEST_INVALID", "Некорректное завершение pairing")
		return
	}
	peer, err := server.dependencies.Hub.CompletePairing(request.Context(), input)
	input.Token = ""
	if err != nil {
		writeHubError(writer, err, "Pairing не завершён")
		return
	}
	_ = server.audit(request.Context(), "WARNING", "VPS_GATEWAY_PAIRING_COMPLETED", map[string]any{"gateway_peer_id": peer.ID, "site_id": peer.SiteID})
	server.scheduleFabric(request.Context(), "GATEWAY_PAIRING_COMPLETED")
	writeJSON(writer, http.StatusCreated, map[string]any{"gateway": peer, "state": "AWAITING_HOST_APPLY"})
}

func (server *Server) hubOverview(writer http.ResponseWriter, request *http.Request) {
	overview, err := server.dependencies.Hub.Overview(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "HUB_OVERVIEW_UNAVAILABLE", "Состояние VPS Hub недоступно")
		return
	}
	writeJSON(writer, http.StatusOK, overview)
}

func (server *Server) listPairingInvitations(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Hub.ListPairings(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "PAIRING_LIST_UNAVAILABLE", "Список приглашений недоступен")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) createPairingInvitation(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		GatewayName   string `json:"gateway_name"`
		Endpoint      string `json:"endpoint"`
		Subnet        string `json:"assigned_subnet"`
		ExpirySeconds int64  `json:"expiry_seconds"`
	}
	if err := decodeJSON(request, &input, 8192); err != nil || input.ExpirySeconds != 0 && (input.ExpirySeconds < 300 || input.ExpirySeconds > 86400) {
		writeError(writer, http.StatusBadRequest, "PAIRING_INVITATION_INVALID", "Проверьте имя, endpoint, /30 подсеть и срок 5 минут–24 часа")
		return
	}
	bundle, err := server.dependencies.Hub.CreatePairing(request.Context(), vpsagent.PairingCreateInput{
		GatewayName: input.GatewayName, Endpoint: input.Endpoint, Subnet: input.Subnet, ExpiresIn: time.Duration(input.ExpirySeconds) * time.Second,
	})
	if err != nil {
		writeHubError(writer, err, "Не удалось создать pairing-приглашение")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_PAIRING_INVITATION_CREATED", map[string]any{"user_id": principal.UserID, "invitation_id": bundle.InvitationID, "assigned_subnet": bundle.AssignedSubnet, "expires_at": bundle.ExpiresAt})
	writeJSON(writer, http.StatusCreated, map[string]any{"invitation": bundle, "token_shown_once": true})
}

func (server *Server) rejectPairingInvitation(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || request.Header.Get("X-Confirm-Destructive") != "reject-pairing-invitation" {
		writeError(writer, http.StatusConflict, "PAIRING_REJECT_CONFIRMATION_REQUIRED", "Требуется подтверждение отзыва приглашения")
		return
	}
	if err := server.dependencies.Hub.RejectPairing(request.Context(), id); err != nil {
		writeHubError(writer, err, "Приглашение не отозвано")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_PAIRING_INVITATION_REJECTED", map[string]any{"user_id": principal.UserID, "invitation_id": id})
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) listGateways(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Hub.ListGateways(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "GATEWAY_LIST_UNAVAILABLE", "Список Gateway недоступен")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) revokeGateway(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || !server.requireReauthenticatedPhrase(writer, request, "ОТОЗВАТЬ GATEWAY "+id) {
		return
	}
	if err := server.dependencies.Hub.RevokeGateway(request.Context(), id); err != nil {
		writeHubError(writer, err, "Gateway не отозван")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "CRITICAL", "VPS_GATEWAY_REVOKED", map[string]any{"user_id": principal.UserID, "gateway_peer_id": id})
	server.scheduleFabric(request.Context(), "GATEWAY_REVOKED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) listAdmins(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Hub.ListAdmins(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "ADMIN_LIST_UNAVAILABLE", "Список администраторов недоступен")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "managed_key_creation_available": server.dependencies.AdminKeys != nil && server.dependencies.AdminKeys.Available()})
}

func (server *Server) createAdmin(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Name            string `json:"name"`
		PublicKey       string `json:"public_key"`
		AssignedAddress string `json:"assigned_address"`
		KeyMode         string `json:"key_mode"`
		Password        string `json:"password"`
		Confirmation    string `json:"confirmation"`
		TrustMode       string `json:"trust_mode"`
	}
	if err := decodeJSON(request, &input, 8192); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_REQUEST_INVALID", "Некорректные параметры администратора")
		return
	}
	if input.KeyMode == "" {
		input.KeyMode = "EXTERNAL"
	}
	mode := strings.ToUpper(strings.TrimSpace(input.KeyMode))
	var item vpsagent.AdminPeer
	var err error
	if mode == "MANAGED" {
		trustMode := strings.ToUpper(strings.TrimSpace(input.TrustMode))
		if trustMode != "" && trustMode != vpsagent.TrustRoutedHub {
			writeError(writer, http.StatusBadRequest, "MANAGED_ADMIN_TRUST_MODE_INVALID", "Управляемый VPS-ключ поддерживает только ROUTED_HUB; для END_TO_END_RELAY приватный ключ должен оставаться на устройстве администратора")
			return
		}
		if server.dependencies.AdminKeys == nil || !server.dependencies.AdminKeys.Available() {
			writeError(writer, http.StatusServiceUnavailable, "MANAGED_ADMIN_KEYS_UNAVAILABLE", "Управляемая выдача конфигурации на этом VPS недоступна")
			return
		}
		if input.Confirmation != "СОЗДАТЬ УПРАВЛЯЕМЫЙ КЛЮЧ" {
			writeError(writer, http.StatusConflict, "MANAGED_ADMIN_CONFIRMATION_INVALID", "Контрольная фраза для создания ключа не совпадает")
			return
		}
		if !server.reauthenticate(writer, request, input.Password) {
			return
		}
		item, err = server.dependencies.AdminKeys.Create(request.Context(), input.Name, input.AssignedAddress)
	} else if mode == "EXTERNAL" {
		item, err = server.dependencies.Hub.CreateAdmin(request.Context(), vpsagent.AdminCreateInput{Name: input.Name, PublicKey: input.PublicKey, AssignedAddress: input.AssignedAddress, KeyMode: "EXTERNAL", TrustMode: input.TrustMode})
	} else {
		writeError(writer, http.StatusBadRequest, "ADMIN_KEY_MODE_INVALID", "Выберите внешний или управляемый режим ключа")
		return
	}
	input.Password, input.Confirmation = "", ""
	if err != nil {
		writeHubError(writer, err, "Администратор не добавлен")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ADMIN_PEER_CREATED", map[string]any{"user_id": principal.UserID, "admin_peer_id": item.ID, "assigned_address": item.AssignedAddress, "key_mode": item.KeyMode})
	server.scheduleFabric(request.Context(), "ADMIN_CREATED")
	writeJSON(writer, http.StatusCreated, item)
}

func (server *Server) updateAdminTrustMode(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok {
		writeError(writer, http.StatusBadRequest, "ADMIN_ID_INVALID", "Некорректный идентификатор администратора")
		return
	}
	var input struct {
		TrustMode string `json:"trust_mode"`
	}
	if err := decodeJSON(request, &input, 2048); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_TRUST_MODE_INVALID", "Выберите ROUTED_HUB или END_TO_END_RELAY")
		return
	}
	if err := server.dependencies.Hub.SetAdminTrustMode(request.Context(), id, input.TrustMode); err != nil {
		writeHubError(writer, err, "Trust mode администратора не изменён")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ADMIN_TRUST_MODE_UPDATED", map[string]any{"user_id": principal.UserID, "admin_peer_id": id, "trust_mode": strings.ToUpper(strings.TrimSpace(input.TrustMode))})
	server.scheduleFabric(request.Context(), "ADMIN_TRUST_MODE_UPDATED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) listAdminRelays(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Hub.ListAdminRelays(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "ADMIN_RELAY_LIST_UNAVAILABLE", "Список end-to-end relay недоступен")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "destination_port": vpsagent.AdminRelayDestinationPort, "private_keys_on_vps": false})
}

func (server *Server) createAdminRelay(writer http.ResponseWriter, request *http.Request) {
	var input vpsagent.AdminRelayInput
	if err := decodeJSON(request, &input, 8192); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_RELAY_REQUEST_INVALID", "Некорректные параметры end-to-end relay")
		return
	}
	item, err := server.dependencies.Hub.CreateAdminRelay(request.Context(), input)
	if err != nil {
		writeHubError(writer, err, "End-to-end relay не создан")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ADMIN_RELAY_CREATED", map[string]any{"user_id": principal.UserID, "relay_id": item.ID, "gateway_peer_id": item.GatewayPeerID, "public_udp_port": item.PublicUDPPort})
	server.scheduleFabric(request.Context(), "ADMIN_RELAY_CREATED")
	writeJSON(writer, http.StatusCreated, item)
}

func (server *Server) setAdminRelayEnabled(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok {
		writeError(writer, http.StatusBadRequest, "ADMIN_RELAY_ID_INVALID", "Некорректный идентификатор relay")
		return
	}
	var input struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(request, &input, 2048); err != nil {
		writeError(writer, http.StatusBadRequest, "ADMIN_RELAY_REQUEST_INVALID", "Некорректное состояние relay")
		return
	}
	if err := server.dependencies.Hub.SetAdminRelayEnabled(request.Context(), id, input.Enabled); err != nil {
		writeHubError(writer, err, "Состояние relay не изменено")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ADMIN_RELAY_STATE_UPDATED", map[string]any{"user_id": principal.UserID, "relay_id": id, "enabled": input.Enabled})
	server.scheduleFabric(request.Context(), "ADMIN_RELAY_STATE_UPDATED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) deleteAdminRelay(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || request.Header.Get("X-Confirm-Destructive") != "delete-disabled-admin-relay" {
		writeError(writer, http.StatusConflict, "ADMIN_RELAY_DELETE_CONFIRMATION_REQUIRED", "Удалить можно только заранее отключённый relay после подтверждения")
		return
	}
	if err := server.dependencies.Hub.DeleteAdminRelay(request.Context(), id); err != nil {
		writeHubError(writer, err, "Relay не удалён")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ADMIN_RELAY_DELETED", map[string]any{"user_id": principal.UserID, "relay_id": id})
	server.scheduleFabric(request.Context(), "ADMIN_RELAY_DELETED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) downloadAdminConfig(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || server.dependencies.AdminKeys == nil || !server.dependencies.AdminKeys.Available() {
		writeError(writer, http.StatusServiceUnavailable, "MANAGED_ADMIN_KEYS_UNAVAILABLE", "Управляемая конфигурация администратора недоступна")
		return
	}
	var input struct {
		Endpoint     string `json:"endpoint"`
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input, 4096); err != nil || input.Confirmation != "СКАЧАТЬ КОНФИГУРАЦИЮ "+id {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusConflict, "ADMIN_CONFIG_CONFIRMATION_INVALID", "Контрольная фраза для одноразовой выдачи не совпадает")
		return
	}
	if !server.reauthenticate(writer, request, input.Password) {
		input.Password, input.Confirmation = "", ""
		return
	}
	input.Password, input.Confirmation = "", ""
	artifact, err := server.dependencies.AdminKeys.Export(request.Context(), id, input.Endpoint)
	input.Endpoint = ""
	if err != nil {
		writeHubError(writer, err, "Готовая конфигурация не выдана; она могла быть уже скачана")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "CRITICAL", "VPS_ADMIN_PRIVATE_CONFIG_CONSUMED", map[string]any{"user_id": principal.UserID, "admin_peer_id": id})
	writer.Header().Set("Content-Type", "application/x-wireguard-profile")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+artifact.Filename+`"`)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(artifact.Content)
}

func (server *Server) rotateAdmin(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || server.dependencies.AdminKeys == nil || !server.dependencies.AdminKeys.Available() {
		writeError(writer, http.StatusServiceUnavailable, "MANAGED_ADMIN_KEYS_UNAVAILABLE", "Смена управляемого ключа недоступна")
		return
	}
	var input struct {
		Name            string `json:"name"`
		AssignedAddress string `json:"assigned_address"`
		Password        string `json:"password"`
		Confirmation    string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input, 8192); err != nil || input.Confirmation != "НАЧАТЬ СМЕНУ КЛЮЧА "+id {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusConflict, "ADMIN_ROTATION_CONFIRMATION_INVALID", "Контрольная фраза для смены ключа не совпадает")
		return
	}
	if !server.reauthenticate(writer, request, input.Password) {
		input.Password, input.Confirmation = "", ""
		return
	}
	input.Password, input.Confirmation = "", ""
	replacement, err := server.dependencies.AdminKeys.Rotate(request.Context(), id, input.Name, input.AssignedAddress)
	if err != nil {
		writeHubError(writer, err, "Сменный ключ администратора не создан")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ADMIN_KEY_ROTATION_STARTED", map[string]any{"user_id": principal.UserID, "source_admin_peer_id": id, "replacement_admin_peer_id": replacement.ID})
	server.scheduleFabric(request.Context(), "ADMIN_ROTATION_STARTED")
	writeJSON(writer, http.StatusCreated, replacement)
}

func (server *Server) revokeAdmin(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || !server.requireReauthenticatedPhrase(writer, request, "ОТОЗВАТЬ АДМИНИСТРАТОРА "+id) {
		return
	}
	var err error
	if server.dependencies.AdminKeys != nil && server.dependencies.AdminKeys.Available() {
		err = server.dependencies.AdminKeys.Revoke(request.Context(), id)
	} else {
		err = server.dependencies.Hub.RevokeAdmin(request.Context(), id)
	}
	if err != nil {
		writeHubError(writer, err, "Администратор не отозван")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "CRITICAL", "VPS_ADMIN_PEER_REVOKED", map[string]any{"user_id": principal.UserID, "admin_peer_id": id})
	server.scheduleFabric(request.Context(), "ADMIN_REVOKED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) listResources(writer http.ResponseWriter, request *http.Request) {
	items, err := server.dependencies.Hub.ListResources(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESOURCE_LIST_UNAVAILABLE", "Список ресурсов недоступен")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) createResource(writer http.ResponseWriter, request *http.Request) {
	var input vpsagent.ResourceInput
	if err := decodeJSON(request, &input, 16384); err != nil {
		writeError(writer, http.StatusBadRequest, "RESOURCE_REQUEST_INVALID", "Некорректные параметры ресурса")
		return
	}
	item, err := server.dependencies.Hub.CreateResource(request.Context(), input)
	if err != nil {
		writeHubError(writer, err, "Ресурс не создан")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_RESOURCE_CREATED", map[string]any{"user_id": principal.UserID, "publication_id": item.ID, "gateway_peer_id": item.GatewayPeerID, "resource_kind": item.ResourceKind})
	server.scheduleFabric(request.Context(), "RESOURCE_CREATED")
	writeJSON(writer, http.StatusCreated, item)
}

func (server *Server) updateResource(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok {
		writeError(writer, http.StatusBadRequest, "RESOURCE_ID_INVALID", "Некорректный идентификатор ресурса")
		return
	}
	var input vpsagent.ResourceInput
	if err := decodeJSON(request, &input, 16384); err != nil {
		writeError(writer, http.StatusBadRequest, "RESOURCE_REQUEST_INVALID", "Некорректные параметры ресурса")
		return
	}
	item, err := server.dependencies.Hub.UpdateResource(request.Context(), id, input)
	if err != nil {
		writeHubError(writer, err, "Ресурс не изменён")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_RESOURCE_UPDATED", map[string]any{"user_id": principal.UserID, "publication_id": item.ID, "desired_generation": item.DesiredGeneration})
	server.scheduleFabric(request.Context(), "RESOURCE_UPDATED")
	writeJSON(writer, http.StatusOK, item)
}

func (server *Server) deleteResource(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || request.Header.Get("X-Confirm-Destructive") != "delete-resource-publication" {
		writeError(writer, http.StatusConflict, "RESOURCE_DELETE_CONFIRMATION_REQUIRED", "Требуется подтверждение удаления публикации")
		return
	}
	if err := server.dependencies.Hub.DeleteResource(request.Context(), id); err != nil {
		writeHubError(writer, err, "Ресурс не удалён")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_RESOURCE_DELETED", map[string]any{"user_id": principal.UserID, "publication_id": id})
	server.scheduleFabric(request.Context(), "RESOURCE_DELETED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) accessMatrix(writer http.ResponseWriter, request *http.Request) {
	gateways, gatewayErr := server.dependencies.Hub.ListGateways(request.Context())
	admins, adminErr := server.dependencies.Hub.ListAdmins(request.Context())
	resources, resourceErr := server.dependencies.Hub.ListResources(request.Context())
	grants, grantErr := server.dependencies.Hub.ListACL(request.Context())
	overview, overviewErr := server.dependencies.Hub.Overview(request.Context())
	if errors.Join(gatewayErr, adminErr, resourceErr, grantErr, overviewErr) != nil {
		writeError(writer, http.StatusServiceUnavailable, "ACCESS_MATRIX_UNAVAILABLE", "Матрица доступа недоступна")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"gateways": gateways, "administrators": admins, "resources": resources, "grants": grants,
		"desired_generation": overview.DesiredGeneration, "applied_generation": overview.AppliedGeneration,
		"state": overview.FabricState, "host_apply_available": overview.HostApplyAvailable,
	})
}

func (server *Server) createACL(writer http.ResponseWriter, request *http.Request) {
	var input vpsagent.ACLInput
	if err := decodeJSON(request, &input, 8192); err != nil {
		writeError(writer, http.StatusBadRequest, "ACL_REQUEST_INVALID", "Некорректное правило доступа")
		return
	}
	item, err := server.dependencies.Hub.CreateACL(request.Context(), input)
	if err != nil {
		writeHubError(writer, err, "Правило доступа не создано")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ACL_GRANT_CREATED", map[string]any{"user_id": principal.UserID, "acl_id": item.ID, "generation": item.Generation})
	server.scheduleFabric(request.Context(), "ACL_CREATED")
	writeJSON(writer, http.StatusCreated, item)
}

func (server *Server) deleteACL(writer http.ResponseWriter, request *http.Request) {
	id, ok := boundedPathID(request.PathValue("id"))
	if !ok || request.Header.Get("X-Confirm-Destructive") != "delete-acl-grant" {
		writeError(writer, http.StatusConflict, "ACL_DELETE_CONFIRMATION_REQUIRED", "Требуется подтверждение удаления правила")
		return
	}
	if err := server.dependencies.Hub.DeleteACL(request.Context(), id); err != nil {
		writeHubError(writer, err, "Правило доступа не удалено")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_ACL_GRANT_DELETED", map[string]any{"user_id": principal.UserID, "acl_id": id})
	server.scheduleFabric(request.Context(), "ACL_DELETED")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) applyFabric(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.FabricApply == nil {
		writeError(writer, http.StatusNotImplemented, "FABRIC_APPLY_UNAVAILABLE", "Привилегированный reconciler Management Fabric не подключён")
		return
	}
	overview, err := server.dependencies.Hub.Overview(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "FABRIC_STATE_UNAVAILABLE", "Состояние Management Fabric недоступно")
		return
	}
	if overview.AppliedGeneration == overview.DesiredGeneration {
		writeJSON(writer, http.StatusOK, map[string]any{"state": "ALREADY_APPLIED", "generation": overview.AppliedGeneration})
		return
	}
	if err := server.dependencies.FabricApply.ApplyVPSFabric(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "FABRIC_APPLY_START_FAILED", "Не удалось поставить безопасное применение Management Fabric в очередь")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_FABRIC_APPLY_REQUESTED", map[string]any{"user_id": principal.UserID, "desired_generation": overview.DesiredGeneration})
	writeJSON(writer, http.StatusAccepted, map[string]any{"state": "APPLY_SCHEDULED", "generation": overview.DesiredGeneration})
}

func (server *Server) scheduleFabric(ctx context.Context, reason string) {
	if server.dependencies.FabricApply == nil {
		return
	}
	if err := server.dependencies.FabricApply.ApplyVPSFabric(ctx); err != nil {
		_ = server.audit(ctx, "ERROR", "VPS_FABRIC_APPLY_SCHEDULE_FAILED", map[string]any{"reason": reason})
	}
}

func (server *Server) hubWatchdog(writer http.ResponseWriter, request *http.Request) {
	report := server.dependencies.Hub.ControllerHealth(request.Context())
	host := map[string]any{
		"available": false, "state": "UNKNOWN", "healthy": false,
		"reconcile_scheduled": false, "reason": "STATUS_UNAVAILABLE", "checked_at": "",
	}
	if server.dependencies.FabricStatusPath != "" {
		status, err := vpsfabric.ReadWatchdogStatus(server.dependencies.FabricStatusPath, server.now(), 3*time.Minute)
		if err == nil {
			host = map[string]any{
				"available": true, "state": status.State, "healthy": status.Healthy,
				"reconcile_scheduled": status.ReconcileScheduled, "reason": status.Reason, "checked_at": status.CheckedAt,
				"desired_generation": status.DesiredGeneration, "applied_generation": status.AppliedGeneration,
				"relay_count": status.RelayCount, "relay_rule_count": status.RelayRuleCount,
				"relay_packets": status.RelayPackets, "relay_bytes": status.RelayBytes,
			}
			if status.State == "FAILED" {
				report.State = "FAILED"
			} else if status.State == "PENDING" && report.State == "HEALTHY" {
				report.State = "PENDING"
			}
		} else if server.dependencies.FabricApply != nil && report.State == "HEALTHY" {
			report.State = "PENDING"
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"state": report.State, "checked_at": report.CheckedAt, "components": report.Components,
		"host_fabric": host,
	})
}

func (server *Server) requireReauthenticatedPhrase(writer http.ResponseWriter, request *http.Request, expected string) bool {
	var input struct {
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input, 4096); err != nil || input.Confirmation != expected {
		input.Password, input.Confirmation = "", ""
		writeError(writer, http.StatusConflict, "DESTRUCTIVE_CONFIRMATION_INVALID", "Контрольная фраза не совпадает")
		return false
	}
	if !server.reauthenticate(writer, request, input.Password) {
		input.Password, input.Confirmation = "", ""
		return false
	}
	input.Password, input.Confirmation = "", ""
	return true
}

func (server *Server) reauthenticate(writer http.ResponseWriter, request *http.Request, password string) bool {
	principal := request.Context().Value(principalKey).(auth.Principal)
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, password); err != nil {
		writeError(writer, http.StatusUnauthorized, "REAUTHENTICATION_FAILED", "Текущий пароль VPS Hub указан неверно")
		return false
	}
	return true
}

func (server *Server) backupStatus(writer http.ResponseWriter, _ *http.Request) {
	operation, pending, err := server.dependencies.Restores.Status()
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESTORE_STATUS_UNAVAILABLE", "Состояние восстановления недоступно")
		return
	}
	operation.ApplyAuthorization = ""
	writeJSON(writer, http.StatusOK, map[string]any{
		"backup_available": true, "format": ".gvpn-vps", "role": "vps", "pending": pending,
		"operation": operation, "apply_available": server.dependencies.RestoreApply != nil,
		"confirmation_phrases": confirmationPhrases(operation),
	})
}

func (server *Server) downloadBackup(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		Password               string `json:"password"`
		Passphrase             string `json:"passphrase"`
		PassphraseConfirmation string `json:"passphrase_confirmation"`
	}
	if err := decodeJSON(request, &input, 4096); err != nil || input.Passphrase != input.PassphraseConfirmation || backup.ValidatePassphrase(input.Passphrase) != nil {
		writeError(writer, http.StatusBadRequest, "BACKUP_PASSPHRASE_INVALID", "Passphrase должна совпадать и содержать 12–256 UTF-8 байт")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
		writeError(writer, http.StatusUnauthorized, "REAUTHENTICATION_FAILED", "Текущий пароль VPS Hub указан неверно")
		return
	}
	passphrase := input.Passphrase
	input.Password, input.Passphrase, input.PassphraseConfirmation = "", "", ""
	artifact, err := server.dependencies.Backups.Build(request.Context(), passphrase)
	passphrase = ""
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BACKUP_CREATE_FAILED", "Не удалось создать и проверить VPS backup")
		return
	}
	defer server.dependencies.Backups.Remove(artifact)
	reader, err := server.dependencies.Backups.Open(artifact)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "BACKUP_VERIFY_FAILED", "Финальная проверка VPS backup не пройдена")
		return
	}
	defer reader.Close()
	_ = server.audit(request.Context(), "WARNING", "VPS_PORTABLE_BACKUP_CREATED", map[string]any{"user_id": principal.UserID, "backup_id": artifact.Manifest.BackupID, "sha256": artifact.SHA256, "bytes": artifact.Bytes})
	writer.Header().Set("Content-Type", "application/vnd.gateway-vpn.vps-backup")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+artifact.Filename+`"`)
	writer.Header().Set("Content-Length", strconv.FormatInt(artifact.Bytes, 10))
	writer.Header().Set("X-Content-SHA256", artifact.SHA256)
	writer.Header().Set("X-Backup-Role", "vps")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(writer, reader, artifact.Bytes)
}

func (server *Server) stageRestore(writer http.ResponseWriter, request *http.Request) {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Ожидается multipart .gvpn-vps upload")
		return
	}
	maximum := backup.MaximumPortableBackupBytes + (1 << 20)
	if request.ContentLength > maximum {
		writeError(writer, http.StatusRequestEntityTooLarge, "RESTORE_UPLOAD_TOO_LARGE", "VPS backup превышает допустимый размер")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximum)
	reader, err := request.MultipartReader()
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Не удалось прочитать upload")
		return
	}
	passphrasePart, err := reader.NextPart()
	if err != nil || passphrasePart.FormName() != "passphrase" || passphrasePart.FileName() != "" {
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Первой частью должна быть passphrase")
		return
	}
	passphraseContent, err := io.ReadAll(io.LimitReader(passphrasePart, 257))
	passphrasePart.Close()
	passphrase := string(passphraseContent)
	if err != nil || backup.ValidatePassphrase(passphrase) != nil {
		writeError(writer, http.StatusBadRequest, "RESTORE_PASSPHRASE_INVALID", "Некорректная passphrase")
		return
	}
	backupPart, err := reader.NextPart()
	if err != nil || backupPart.FormName() != "backup" || backupPart.FileName() == "" || len(backupPart.FileName()) > 180 || filepath.Base(backupPart.FileName()) != backupPart.FileName() || !strings.HasSuffix(strings.ToLower(backupPart.FileName()), ".gvpn-vps") {
		passphrase = ""
		writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Второй частью должен быть файл .gvpn-vps")
		return
	}
	operation, stageErr := server.dependencies.Restores.Stage(request.Context(), backupPart, passphrase)
	passphrase = ""
	backupPart.Close()
	if stageErr == nil {
		if extra, extraErr := reader.NextPart(); extraErr == nil || extra != nil {
			if extra != nil {
				extra.Close()
			}
			_ = server.dependencies.Restores.Discard(operation.RestoreID)
			writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Лишние multipart-части запрещены")
			return
		} else if !errors.Is(extraErr, io.EOF) {
			_ = server.dependencies.Restores.Discard(operation.RestoreID)
			writeError(writer, http.StatusBadRequest, "INVALID_RESTORE_UPLOAD", "Multipart upload завершён некорректно")
			return
		}
	}
	if errors.Is(stageErr, vpsbackup.ErrRestorePending) {
		writeError(writer, http.StatusConflict, "RESTORE_ALREADY_PENDING", "Сначала примените или отмените текущее восстановление")
		return
	}
	if errors.Is(stageErr, vpsbackup.ErrRestoreUploadTooLarge) {
		writeError(writer, http.StatusRequestEntityTooLarge, "RESTORE_UPLOAD_TOO_LARGE", "VPS backup превышает допустимый размер")
		return
	}
	if stageErr != nil {
		writeError(writer, http.StatusBadRequest, "RESTORE_VERIFICATION_FAILED", "Файл, роль, passphrase или содержимое не прошли проверку")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_RESTORE_STAGED", map[string]any{"user_id": principal.UserID, "restore_id": operation.RestoreID, "backup_id": operation.BackupID, "source_vps_id": operation.SourceVPSID})
	operation.ApplyAuthorization = ""
	writeJSON(writer, http.StatusCreated, map[string]any{"operation": operation, "confirmation_phrases": confirmationPhrases(operation)})
}

func (server *Server) applyRestore(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.RestoreApply == nil {
		writeError(writer, http.StatusNotImplemented, "RESTORE_APPLY_UNAVAILABLE", "Привилегированный restore helper не подключён")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	var input struct {
		RestoreID    string `json:"restore_id"`
		Mode         string `json:"mode"`
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(request, &input, 4096); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST", "Некорректное подтверждение восстановления")
		return
	}
	operation, pending, err := server.dependencies.Restores.Status()
	phrase := confirmationPhrase(operation, input.Mode)
	if err != nil || !pending || operation.RestoreID != input.RestoreID || operation.State != vpsbackup.RestoreStateStaged || phrase == "" || input.Confirmation != phrase {
		writeError(writer, http.StatusConflict, "RESTORE_CONFIRMATION_INVALID", "Restore изменился либо контрольная фраза не совпадает")
		return
	}
	if err := server.dependencies.Auth.Reauthenticate(request.Context(), principal, input.Password); err != nil {
		input.Password = ""
		writeError(writer, http.StatusUnauthorized, "REAUTHENTICATION_FAILED", "Текущий пароль VPS Hub указан неверно")
		return
	}
	input.Password, input.Confirmation = "", ""
	operation, err = server.dependencies.Restores.AuthorizeApply(operation.RestoreID, input.Mode)
	if err != nil {
		writeError(writer, http.StatusConflict, "RESTORE_AUTHORIZATION_FAILED", "Не удалось сохранить разрешение восстановления")
		return
	}
	_ = server.audit(request.Context(), "WARNING", "VPS_RESTORE_APPLY_REQUESTED", map[string]any{"user_id": principal.UserID, "restore_id": operation.RestoreID, "mode": operation.SelectedMode})
	if err := server.dependencies.RestoreApply.ApplyPendingVPSRestore(request.Context()); err != nil {
		writeError(writer, http.StatusBadGateway, "RESTORE_APPLY_START_FAILED", "Restore разрешён, но привилегированный helper не запустился; операцию можно повторить")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"restore_id": operation.RestoreID, "state": "APPLY_SCHEDULED", "management_reconnect_required": true})
}

func (server *Server) discardRestore(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("X-Confirm-Destructive") != "discard-staged-vps-restore" {
		writeError(writer, http.StatusConflict, "RESTORE_DISCARD_CONFIRMATION_REQUIRED", "Требуется подтверждение отмены")
		return
	}
	operation, pending, err := server.dependencies.Restores.Status()
	if err != nil || !pending || operation.State != vpsbackup.RestoreStateStaged {
		writeError(writer, http.StatusConflict, "RESTORE_NOT_PENDING", "Staged restore не найден")
		return
	}
	if err := server.dependencies.Restores.Discard(operation.RestoreID); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESTORE_DISCARD_FAILED", "Не удалось удалить staged restore")
		return
	}
	principal := request.Context().Value(principalKey).(auth.Principal)
	_ = server.audit(request.Context(), "WARNING", "VPS_RESTORE_DISCARDED", map[string]any{"user_id": principal.UserID, "restore_id": operation.RestoreID})
	writer.WriteHeader(http.StatusNoContent)
}

func confirmationPhrases(operation vpsbackup.RestoreOperation) map[string]string {
	result := map[string]string{}
	for _, mode := range operation.AllowedModes {
		if phrase := confirmationPhrase(operation, mode); phrase != "" {
			result[mode] = phrase
		}
	}
	return result
}

func confirmationPhrase(operation vpsbackup.RestoreOperation, mode string) string {
	switch mode {
	case vpsbackup.RestoreModeSameVPS:
		if operation.IdentityMatches {
			return "ВОССТАНОВИТЬ VPS " + operation.LiveVPSID
		}
	case vpsbackup.RestoreModeNewVPS:
		return "ИМПОРТИРОВАТЬ КАК НОВЫЙ VPS"
	}
	return ""
}

func (server *Server) audit(ctx context.Context, severity, eventType string, details map[string]any) error {
	content, err := json.Marshal(details)
	if err != nil || len(content) > 8192 {
		return errors.New("encode VPS audit event failed")
	}
	_, err = server.dependencies.Database.ExecContext(ctx, "INSERT INTO audit_events(occurred_at,severity,event_type,details_json) VALUES(?,?,?,?)", server.now().Format(time.RFC3339Nano), severity, eventType, string(content))
	return err
}

func (server *Server) now() time.Time {
	if server.dependencies.Now != nil {
		return server.dependencies.Now().UTC()
	}
	return time.Now().UTC()
}

func sessionResponse(userID, username, sessionID, csrf string, mustChange bool, expires time.Time) map[string]any {
	return map[string]any{"user_id": userID, "user": username, "session_id": sessionID, "csrf_token": csrf, "must_change_password": mustChange, "expires_at": expires.UTC().Format(time.RFC3339Nano)}
}

func decodeJSON(request *http.Request, destination any, maximum int64) error {
	content, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return errors.New("JSON body exceeds its bound")
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
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

func writeHubError(writer http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, vpsagent.ErrHubNotFound):
		writeError(writer, http.StatusNotFound, "HUB_OBJECT_NOT_FOUND", "Объект VPS Hub не найден")
	case errors.Is(err, vpsagent.ErrHubConflict):
		writeError(writer, http.StatusConflict, "HUB_STATE_CONFLICT", "Адрес, подсеть, ключ или идентификатор конфликтует с существующей конфигурацией")
	case errors.Is(err, vpsagent.ErrPairingRejected):
		writeError(writer, http.StatusForbidden, "PAIRING_REJECTED", "Приглашение истекло, отозвано, уже использовано или токен неверен")
	default:
		writeError(writer, http.StatusBadRequest, "HUB_OPERATION_REJECTED", fallback+"; проверьте значения и текущие состояния")
	}
}

func boundedPathID(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\\x00\r\n\t") {
		return "", false
	}
	return value, true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request)
	})
}
