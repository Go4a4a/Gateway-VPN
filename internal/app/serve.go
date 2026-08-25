package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

type listenerExit struct {
	address  string
	required bool
	err      error
}

func ServeHTTPS(ctx context.Context, addresses []string, certPath, keyPath string, handler http.Handler, logger *slog.Logger) error {
	if len(addresses) == 0 || handler == nil {
		return errors.New("HTTPS addresses and handler are required")
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load management TLS key pair: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	httpServer := &http.Server{
		Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 1 << 20,
	}
	exits := make(chan listenerExit, len(addresses)*2)
	active := make(map[string]bool, len(addresses))
	var mutex sync.Mutex
	start := func(address string, required bool) error {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			return err
		}
		mutex.Lock()
		active[address] = true
		mutex.Unlock()
		logger.Info("management HTTPS listener ready", "address", address, "required", required)
		go func() {
			err := httpServer.Serve(tls.NewListener(listener, tlsConfig.Clone()))
			mutex.Lock()
			active[address] = false
			mutex.Unlock()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			exits <- listenerExit{address: address, required: required, err: err}
		}()
		return nil
	}
	if err := start(addresses[0], true); err != nil {
		return fmt.Errorf("bind required LAN management address %s: %w", addresses[0], err)
	}
	for _, address := range addresses[1:] {
		if err := start(address, false); err != nil {
			logger.Warn("optional management address is not available yet", "address", address, "error", err)
		}
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err := httpServer.Shutdown(shutdownContext)
			cancel()
			if err != nil {
				return fmt.Errorf("shutdown management HTTPS: %w", err)
			}
			return nil
		case exit := <-exits:
			if exit.err != nil {
				logger.Error("management HTTPS listener stopped", "address", exit.address, "error", exit.err)
			}
			if exit.required && exit.err != nil {
				_ = httpServer.Close()
				return fmt.Errorf("required management HTTPS listener stopped: %w", exit.err)
			}
		case <-ticker.C:
			for _, address := range addresses[1:] {
				mutex.Lock()
				isActive := active[address]
				mutex.Unlock()
				if !isActive {
					if err := start(address, false); err != nil {
						logger.Debug("optional management address retry deferred", "address", address, "error", err)
					}
				}
			}
		}
	}
}
