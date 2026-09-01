package webapi

import (
	"context"
	"io"
	"net/http"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/state"
)

func (server *Server) createManagementResource(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.ResourceInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "RESOURCE_REQUEST_INVALID", "Некорректные параметры локального ресурса")
		return
	}
	if input.ID == "" {
		input.ID = newID("resource")
	}
	item, err := server.dependencies.ManagementFabric.CreateResource(request.Context(), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_CREATED", map[string]any{"resource_id": item.ID, "kind": item.Kind, "access_profile": item.AccessProfile})
	writeJSON(writer, http.StatusCreated, map[string]any{"resource": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) updateManagementResource(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.ResourceInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "RESOURCE_REQUEST_INVALID", "Некорректные параметры локального ресурса")
		return
	}
	item, err := server.dependencies.ManagementFabric.UpdateResource(request.Context(), request.PathValue("id"), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_UPDATED", map[string]any{"resource_id": item.ID, "enabled": item.Enabled, "access_profile": item.AccessProfile})
	writeJSON(writer, http.StatusOK, map[string]any{"resource": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) deleteManagementResource(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil || request.Header.Get("X-Confirm-Destructive") != "delete-disabled-resource" {
		writeError(writer, http.StatusConflict, "RESOURCE_DELETE_CONFIRMATION_REQUIRED", "Сначала отключите ресурс и подтвердите удаление вместе с его публикациями и ACL")
		return
	}
	if err := server.dependencies.ManagementFabric.DeleteResource(request.Context(), request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_DELETED", map[string]any{"resource_id": request.PathValue("id")})
	_ = server.requestManagementFabricSync(request.Context())
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) probeManagementResource(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabricAdmin == nil {
		writeError(writer, http.StatusNotImplemented, "RESOURCE_PROBE_NOT_AVAILABLE", "Проверка локальных ресурсов доступна только через root broker")
		return
	}
	content, err := io.ReadAll(io.LimitReader(request.Body, 1))
	request.Body.Close()
	if err != nil || len(content) != 0 {
		writeError(writer, http.StatusBadRequest, "RESOURCE_PROBE_REQUEST_INVALID", "Проверка принимает только ID ресурса из адреса и не принимает параметры маршрута")
		return
	}
	result, err := server.dependencies.ManagementFabricAdmin.ProbeManagementResource(request.Context(), request.PathValue("id"))
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "RESOURCE_PROBE_FAILED", "Проверка не завершена; состояние ресурса не считается рабочим")
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_PROBED", map[string]any{"resource_id": result.ResourceID, "state": result.State, "reason_code": result.ReasonCode, "interface": result.Interface})
	writeJSON(writer, http.StatusOK, map[string]any{"probe": result, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) createManagementResourcePublication(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.ResourcePublicationInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "PUBLICATION_REQUEST_INVALID", "Некорректные параметры публикации ресурса")
		return
	}
	if input.ID == "" {
		input.ID = newID("publication")
	}
	item, err := server.dependencies.ManagementFabric.CreateResourcePublication(request.Context(), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_PUBLICATION_CREATED", map[string]any{"publication_id": item.ID, "resource_id": item.ResourceID, "link_id": item.LinkID})
	writeJSON(writer, http.StatusCreated, map[string]any{"publication": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) updateManagementResourcePublication(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.ResourcePublicationInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "PUBLICATION_REQUEST_INVALID", "Некорректные параметры публикации ресурса")
		return
	}
	item, err := server.dependencies.ManagementFabric.UpdateResourcePublication(request.Context(), request.PathValue("id"), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_PUBLICATION_UPDATED", map[string]any{"publication_id": item.ID, "enabled": item.Enabled})
	writeJSON(writer, http.StatusOK, map[string]any{"publication": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) deleteManagementResourcePublication(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil || request.Header.Get("X-Confirm-Destructive") != "delete-disabled-publication" {
		writeError(writer, http.StatusConflict, "PUBLICATION_DELETE_CONFIRMATION_REQUIRED", "Сначала отключите публикацию и подтвердите удаление")
		return
	}
	if err := server.dependencies.ManagementFabric.DeleteResourcePublication(request.Context(), request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_PUBLICATION_DELETED", map[string]any{"publication_id": request.PathValue("id")})
	_ = server.requestManagementFabricSync(request.Context())
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) createManagementResourceACL(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.ResourceACLInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "RESOURCE_ACL_REQUEST_INVALID", "Некорректные параметры ACL ресурса")
		return
	}
	if input.ID == "" {
		input.ID = newID("resource-acl")
	}
	item, err := server.dependencies.ManagementFabric.CreateResourceACL(request.Context(), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_ACL_CREATED", map[string]any{"acl_id": item.ID, "admin_id": item.AdminID, "resource_id": item.ResourceID})
	writeJSON(writer, http.StatusCreated, map[string]any{"acl": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) updateManagementResourceACL(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil {
		writeError(writer, http.StatusNotImplemented, "MANAGEMENT_FABRIC_NOT_AVAILABLE", "Management Fabric не подключён")
		return
	}
	var input managementfabric.ResourceACLInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "RESOURCE_ACL_REQUEST_INVALID", "Некорректные параметры ACL ресурса")
		return
	}
	item, err := server.dependencies.ManagementFabric.UpdateResourceACL(request.Context(), request.PathValue("id"), input)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_ACL_UPDATED", map[string]any{"acl_id": item.ID, "enabled": item.Enabled})
	writeJSON(writer, http.StatusOK, map[string]any{"acl": item, "sync_state": server.requestManagementFabricSync(request.Context())})
}

func (server *Server) deleteManagementResourceACL(writer http.ResponseWriter, request *http.Request) {
	if server.dependencies.ManagementFabric == nil || request.Header.Get("X-Confirm-Destructive") != "delete-disabled-resource-acl" {
		writeError(writer, http.StatusConflict, "RESOURCE_ACL_DELETE_CONFIRMATION_REQUIRED", "Сначала отключите ACL и подтвердите удаление")
		return
	}
	if err := server.dependencies.ManagementFabric.DeleteResourceACL(request.Context(), request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	server.appendManagementResourceEvent(request.Context(), "MANAGEMENT_RESOURCE_ACL_DELETED", map[string]any{"acl_id": request.PathValue("id")})
	_ = server.requestManagementFabricSync(request.Context())
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) appendManagementResourceEvent(ctx context.Context, eventType string, details map[string]any) {
	if server.dependencies.State == nil {
		return
	}
	if principal, ok := ctx.Value(principalKey).(auth.Principal); ok {
		details["user_id"] = principal.UserID
	}
	_ = server.dependencies.State.AppendEvent(ctx, state.EventInput{Severity: "INFO", Type: eventType, Details: details})
}
