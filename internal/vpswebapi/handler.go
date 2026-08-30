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
	"gateway-vpn/internal/vpsbackup"
)

const sessionCookieName = "gateway_vpn_vps_session"

type contextKey string

const principalKey contextKey = "vps-principal"

//go:embed static/*
var staticFiles embed.FS

type RestoreApplyTrigger interface {
	ApplyPendingVPSRestore(context.Context) error
}

type Dependencies struct {
	Database     *sql.DB
	Auth         auth.Service
	Backups      *vpsbackup.Manager
	Restores     *vpsbackup.RestoreManager
	RestoreApply RestoreApplyTrigger
	Now          func() time.Time
}

type Server struct {
	dependencies Dependencies
	handler      http.Handler
}

func New(dependencies Dependencies) (*Server, error) {
	if dependencies.Database == nil || dependencies.Auth.Database == nil || dependencies.Backups == nil || dependencies.Restores == nil {
		return nil, errors.New("complete VPS Hub Web API dependencies are required")
	}
	server := &Server{dependencies: dependencies}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", server.login)
	mux.Handle("POST /api/v1/auth/logout", server.protected(http.HandlerFunc(server.logout)))
	mux.Handle("GET /api/v1/auth/session", server.protected(http.HandlerFunc(server.session)))
	mux.Handle("PUT /api/v1/auth/password", server.protected(http.HandlerFunc(server.changePassword)))
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request)
	})
}
