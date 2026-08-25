package app

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/tlsbootstrap"
)

func TestServeHTTPSUsesTLS13AndShutsDown(t *testing.T) {
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if _, err := tlsbootstrap.Ensure(certPath, keyPath, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeHTTPS(ctx, []string{address}, certPath, keyPath, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { io.WriteString(writer, "ok") }), nil)
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}}
	var response *http.Response
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		response, err = client.Get("https://" + address)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("HTTPS request error = %v", err)
	}
	response.Body.Close()
	if response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = %x", response.TLS.Version)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeHTTPS() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeHTTPS did not stop")
	}
}
