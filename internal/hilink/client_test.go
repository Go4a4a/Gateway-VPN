package hilink

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHiLinkClientUsesSessionTokenAndToleratesOptionalOperatorFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/webserver/SesTokInfo":
			fmt.Fprint(writer, `<response><SesInfo>SessionID=test</SesInfo><TokInfo>token</TokInfo></response>`)
		case "/api/device/information":
			if request.Header.Get("Cookie") != "SessionID=test" || request.Header.Get("__RequestVerificationToken") != "token" {
				t.Errorf("missing session headers: %+v", request.Header)
			}
			fmt.Fprint(writer, `<response><DeviceName>E3372</DeviceName><SerialNumber>ABC12345</SerialNumber><SoftwareVersion>1.0</SoftwareVersion><WebUIVersion>2.0</WebUIVersion></response>`)
		case "/api/monitoring/status":
			fmt.Fprint(writer, `<response><ConnectionStatus>901</ConnectionStatus><SignalIcon>4</SignalIcon><CurrentNetworkType>19</CurrentNetworkType></response>`)
		case "/api/net/current-plmn":
			http.Error(writer, "unsupported", http.StatusNotFound)
		default:
			http.NotFound(writer, request)
		}
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	client, err := newClient(server.URL, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.DeviceInformation(context.Background())
	if err != nil || info.DeviceName != "E3372" || info.RawSerial != "ABC12345" {
		t.Fatalf("DeviceInformation() = %+v, %v", info, err)
	}
	telemetry, err := client.Telemetry(context.Background())
	if err != nil || telemetry.SignalLevel != "4" || telemetry.Operator != "" {
		t.Fatalf("Telemetry() = %+v, %v", telemetry, err)
	}
}

func TestHiLinkClientRejectsPublicOrRedirectingManagementURL(t *testing.T) {
	if _, err := NewClient("http://8.8.8.8", nil); err == nil {
		t.Fatal("NewClient(public) error = nil")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://example.com", http.StatusFound)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	client, err := newClient(server.URL, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeviceInformation(context.Background()); err == nil {
		t.Fatal("DeviceInformation(redirect) error = nil")
	}
}
