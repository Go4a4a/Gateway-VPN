package hilink

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxHiLinkResponseBytes = 256 << 10

type Client struct {
	base       *url.URL
	httpClient *http.Client
}

type DeviceInformation struct {
	DeviceName      string
	RawSerial       string
	SoftwareVersion string
	WebUIVersion    string
}

type Telemetry struct {
	ConnectionStatus string
	SignalLevel      string
	NetworkType      string
	Operator         string
}

type sessionToken struct {
	Session string `xml:"SesInfo"`
	Token   string `xml:"TokInfo"`
}

func NewClient(gateway string, httpClient *http.Client) (*Client, error) {
	return newClient(gateway, httpClient, false)
}

func newClient(gateway string, httpClient *http.Client, allowLoopback bool) (*Client, error) {
	parsed, err := url.Parse(gateway)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("HiLink base URL must be an HTTP(S) origin without credentials")
	}
	host := net.ParseIP(parsed.Hostname())
	if host == nil {
		return nil, errors.New("HiLink base URL must use a literal management IP")
	}
	address, ok := netip.AddrFromSlice(host)
	address = address.Unmap()
	if !ok || !address.Is4() || (!address.IsPrivate() && !(allowLoopback && address.IsLoopback())) || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("HiLink management IP must be private IPv4")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	clone := *httpClient
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: parsed, httpClient: &clone}, nil
}

func (client *Client) DeviceInformation(ctx context.Context) (DeviceInformation, error) {
	var response struct {
		DeviceName      string `xml:"DeviceName"`
		SerialNumber    string `xml:"SerialNumber"`
		SoftwareVersion string `xml:"SoftwareVersion"`
		WebUIVersion    string `xml:"WebUIVersion"`
	}
	if err := client.getXML(ctx, "/api/device/information", &response); err != nil {
		return DeviceInformation{}, err
	}
	return DeviceInformation{DeviceName: cleanTelemetry(response.DeviceName, 128), RawSerial: cleanTelemetry(response.SerialNumber, 256), SoftwareVersion: cleanTelemetry(response.SoftwareVersion, 128), WebUIVersion: cleanTelemetry(response.WebUIVersion, 128)}, nil
}

func (client *Client) Telemetry(ctx context.Context) (Telemetry, error) {
	var status struct {
		ConnectionStatus   string `xml:"ConnectionStatus"`
		SignalIcon         string `xml:"SignalIcon"`
		CurrentNetworkType string `xml:"CurrentNetworkType"`
	}
	if err := client.getXML(ctx, "/api/monitoring/status", &status); err != nil {
		return Telemetry{}, err
	}
	operator := ""
	var network struct {
		FullName  string `xml:"FullName"`
		ShortName string `xml:"ShortName"`
		Numeric   string `xml:"Numeric"`
	}
	if err := client.getXML(ctx, "/api/net/current-plmn", &network); err == nil {
		operator = network.FullName
		if operator == "" {
			operator = network.ShortName
		}
		if operator == "" {
			operator = network.Numeric
		}
	}
	return Telemetry{ConnectionStatus: cleanTelemetry(status.ConnectionStatus, 64), SignalLevel: cleanTelemetry(status.SignalIcon, 32), NetworkType: cleanTelemetry(status.CurrentNetworkType, 64), Operator: cleanTelemetry(operator, 128)}, nil
}

func (client *Client) getXML(ctx context.Context, endpoint string, destination any) error {
	token, _ := client.readSessionToken(ctx)
	requestURL := *client.base
	requestURL.Path = endpoint
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create HiLink request: %w", err)
	}
	request.Header.Set("Accept", "application/xml")
	if token.Session != "" {
		request.Header.Set("Cookie", token.Session)
	}
	if token.Token != "" {
		request.Header.Set("__RequestVerificationToken", token.Token)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call HiLink API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HiLink API returned HTTP %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxHiLinkResponseBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read HiLink API response: %w", err)
	}
	if len(content) > maxHiLinkResponseBytes {
		return errors.New("HiLink API response exceeds size limit")
	}
	if err := xml.Unmarshal(content, destination); err != nil {
		return fmt.Errorf("decode HiLink XML: %w", err)
	}
	return nil
}

func (client *Client) readSessionToken(ctx context.Context) (sessionToken, error) {
	requestURL := *client.base
	requestURL.Path = "/api/webserver/SesTokInfo"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return sessionToken{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return sessionToken{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return sessionToken{}, fmt.Errorf("HiLink session endpoint returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return sessionToken{}, err
	}
	var token sessionToken
	if err := xml.Unmarshal(content, &token); err != nil {
		return sessionToken{}, err
	}
	token.Session = cleanHeader(token.Session)
	token.Token = cleanHeader(token.Token)
	return token, nil
}

func cleanTelemetry(value string, limit int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return -1
		}
		return char
	}, value)
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

func cleanHeader(value string) string {
	if strings.ContainsAny(value, "\r\n") || len(value) > 4096 {
		return ""
	}
	return strings.TrimSpace(value)
}
