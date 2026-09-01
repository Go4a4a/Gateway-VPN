package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	httpResponse = "gateway-vpn-http-ok"
	udpPayload   = "gateway-vpn-udp-ok"
	maximumDNS   = 4096
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "probe":
		err = probe(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mihomo-peer serve --http ADDRESS --udp ADDRESS --dns ADDRESS --answer IPv4 | probe --kind http|udp|dns --address ADDRESS [--name NAME --answer IPv4]")
	os.Exit(2)
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	httpAddress := flags.String("http", "", "HTTP listen address")
	udpAddress := flags.String("udp", "", "UDP echo listen address")
	dnsAddress := flags.String("dns", "", "DNS UDP/TCP listen address")
	answerText := flags.String("answer", "", "DNS IPv4 answer")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *httpAddress == "" || *udpAddress == "" || *dnsAddress == "" {
		return errors.New("invalid serve arguments")
	}
	answer := net.ParseIP(*answerText).To4()
	if answer == nil {
		return errors.New("serve answer must be IPv4")
	}

	httpListener, err := net.Listen("tcp4", *httpAddress)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	defer httpListener.Close()
	udpEndpoint, err := net.ResolveUDPAddr("udp4", *udpAddress)
	if err != nil {
		return fmt.Errorf("resolve UDP: %w", err)
	}
	udpListener, err := net.ListenUDP("udp4", udpEndpoint)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer udpListener.Close()
	dnsUDPEndpoint, err := net.ResolveUDPAddr("udp4", *dnsAddress)
	if err != nil {
		return fmt.Errorf("resolve DNS UDP: %w", err)
	}
	dnsUDP, err := net.ListenUDP("udp4", dnsUDPEndpoint)
	if err != nil {
		return fmt.Errorf("listen DNS UDP: %w", err)
	}
	defer dnsUDP.Close()
	dnsTCP, err := net.Listen("tcp4", *dnsAddress)
	if err != nil {
		return fmt.Errorf("listen DNS TCP: %w", err)
	}
	defer dnsTCP.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 4)
	httpServer := &http.Server{
		Handler:           http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(response, httpResponse) }),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       2 * time.Second,
	}
	go func() { errorsChannel <- normalizeServeError(httpServer.Serve(httpListener)) }()
	go func() { errorsChannel <- serveUDPEcho(ctx, udpListener) }()
	go func() { errorsChannel <- serveDNSUDP(ctx, dnsUDP, answer) }()
	go func() { errorsChannel <- serveDNSTCP(ctx, dnsTCP, answer) }()
	fmt.Println("MIHOMO_PEER_READY")
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
		return nil
	case err := <-errorsChannel:
		return err
	}
}

func normalizeServeError(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func serveUDPEcho(ctx context.Context, listener *net.UDPConn) error {
	buffer := make([]byte, 2048)
	for {
		_ = listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		read, remote, err := listener.ReadFromUDP(buffer)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		if err != nil {
			return normalizeServeError(err)
		}
		if _, err := listener.WriteToUDP(buffer[:read], remote); err != nil {
			return normalizeServeError(err)
		}
	}
}

func serveDNSUDP(ctx context.Context, listener *net.UDPConn, answer net.IP) error {
	buffer := make([]byte, maximumDNS)
	for {
		_ = listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		read, remote, err := listener.ReadFromUDP(buffer)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		if err != nil {
			return normalizeServeError(err)
		}
		response, err := dnsResponse(buffer[:read], answer)
		if err != nil {
			continue
		}
		if _, err := listener.WriteToUDP(response, remote); err != nil {
			return normalizeServeError(err)
		}
	}
}

func serveDNSTCP(ctx context.Context, listener net.Listener, answer net.IP) error {
	for {
		if tcp, ok := listener.(*net.TCPListener); ok {
			_ = tcp.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}
		connection, err := listener.Accept()
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		if err != nil {
			return normalizeServeError(err)
		}
		go handleDNSTCP(connection, answer)
	}
}

func handleDNSTCP(connection net.Conn, answer net.IP) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	length := make([]byte, 2)
	if _, err := io.ReadFull(connection, length); err != nil {
		return
	}
	size := int(binary.BigEndian.Uint16(length))
	if size < 12 || size > maximumDNS {
		return
	}
	query := make([]byte, size)
	if _, err := io.ReadFull(connection, query); err != nil {
		return
	}
	response, err := dnsResponse(query, answer)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(length, uint16(len(response)))
	_, _ = connection.Write(append(length, response...))
}

func dnsResponse(query []byte, answer net.IP) ([]byte, error) {
	questionEnd, err := dnsQuestionEnd(query)
	if err != nil || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("invalid DNS query")
	}
	response := make([]byte, 0, questionEnd+16)
	response = append(response, query[:2]...)
	response = append(response, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	response = append(response, query[12:questionEnd]...)
	response = append(response, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04)
	response = append(response, answer.To4()...)
	return response, nil
}

func dnsQuestionEnd(packet []byte) (int, error) {
	if len(packet) < 17 {
		return 0, errors.New("DNS packet is too short")
	}
	position := 12
	for {
		if position >= len(packet) {
			return 0, errors.New("DNS question is truncated")
		}
		length := int(packet[position])
		position++
		if length == 0 {
			break
		}
		if length > 63 || position+length > len(packet) {
			return 0, errors.New("DNS label is invalid")
		}
		position += length
	}
	if position+4 > len(packet) {
		return 0, errors.New("DNS question type is truncated")
	}
	return position + 4, nil
}

func probe(arguments []string) error {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kind := flags.String("kind", "", "http, udp, or dns")
	address := flags.String("address", "", "remote address")
	name := flags.String("name", "gateway-vpn.test.", "DNS name")
	answerText := flags.String("answer", "", "expected DNS IPv4 answer")
	timeout := flags.Duration("timeout", 2*time.Second, "probe timeout")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *address == "" || *timeout < 100*time.Millisecond || *timeout > 10*time.Second {
		return errors.New("invalid probe arguments")
	}
	switch *kind {
	case "http":
		return probeHTTP(*address, *timeout)
	case "udp":
		return probeUDP(*address, *timeout)
	case "dns":
		answer := net.ParseIP(*answerText).To4()
		if answer == nil {
			return errors.New("DNS probe answer must be IPv4")
		}
		return probeDNS(*address, *name, answer, *timeout)
	default:
		return errors.New("probe kind must be http, udp, or dns")
	}
}

func probeHTTP(address string, timeout time.Duration) error {
	connection, err := net.DialTimeout("tcp4", address, timeout)
	if err != nil {
		return fmt.Errorf("HTTP connect: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(connection, "GET /gate HTTP/1.1\r\nHost: gateway-vpn.test\r\nConnection: close\r\n\r\n"); err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	response, err := io.ReadAll(io.LimitReader(connection, 16<<10))
	if err != nil {
		return fmt.Errorf("HTTP response: %w", err)
	}
	if !bytes.Contains(response, []byte(httpResponse)) {
		return errors.New("HTTP response marker is missing")
	}
	return nil
}

func probeUDP(address string, timeout time.Duration) error {
	connection, err := net.DialTimeout("udp4", address, timeout)
	if err != nil {
		return fmt.Errorf("UDP connect: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := connection.Write([]byte(udpPayload)); err != nil {
		return fmt.Errorf("UDP request: %w", err)
	}
	response := make([]byte, 128)
	read, err := connection.Read(response)
	if err != nil {
		return fmt.Errorf("UDP response: %w", err)
	}
	if string(response[:read]) != udpPayload {
		return errors.New("UDP response marker is invalid")
	}
	return nil
}

func probeDNS(address, name string, answer net.IP, timeout time.Duration) error {
	query, identifier, err := dnsQuery(name)
	if err != nil {
		return err
	}
	connection, err := net.DialTimeout("udp4", address, timeout)
	if err != nil {
		return fmt.Errorf("DNS connect: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := connection.Write(query); err != nil {
		return fmt.Errorf("DNS request: %w", err)
	}
	response := make([]byte, maximumDNS)
	read, err := connection.Read(response)
	if err != nil {
		return fmt.Errorf("DNS response: %w", err)
	}
	if err := verifyDNSResponse(response[:read], identifier, answer); err != nil {
		return err
	}
	return nil
}

func dnsQuery(name string) ([]byte, uint16, error) {
	identifierBytes := make([]byte, 2)
	if _, err := rand.Read(identifierBytes); err != nil {
		return nil, 0, errors.New("generate DNS identifier")
	}
	identifier := binary.BigEndian.Uint16(identifierBytes)
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], identifier)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return nil, 0, errors.New("DNS name is empty")
	}
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, errors.New("DNS name label is invalid")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query, identifier, nil
}

func verifyDNSResponse(response []byte, identifier uint16, answer net.IP) error {
	if len(response) < 16 || binary.BigEndian.Uint16(response[:2]) != identifier || response[2]&0x80 == 0 {
		return errors.New("DNS response header is invalid")
	}
	if binary.BigEndian.Uint16(response[6:8]) < 1 || !bytes.Contains(response, answer.To4()) {
		return errors.New("DNS expected IPv4 answer is missing")
	}
	return nil
}
