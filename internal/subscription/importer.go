package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxPayloadBytes  = 8 << 20
	MaxNodes         = 5000
	MaxNodeNameBytes = 512
)

type ImportedNode struct {
	ExternalName   string
	MatchName      string
	NormalizedName string
	Fingerprint    string
	ProxyType      string
	Config         map[string]any
}

type ImportResult struct {
	Format string
	Nodes  []ImportedNode
}

func Import(payload []byte) (ImportResult, error) {
	if len(payload) == 0 {
		return ImportResult{}, errors.New("subscription payload is empty")
	}
	if len(payload) > MaxPayloadBytes {
		return ImportResult{}, fmt.Errorf("subscription payload exceeds %d bytes", MaxPayloadBytes)
	}
	return importPayload(bytes.TrimSpace(payload), true)
}

func importPayload(payload []byte, allowWholeBase64 bool) (ImportResult, error) {
	if result, recognized, err := importYAML(payload); recognized {
		return result, err
	}
	if result, recognized, err := importURIList(string(payload)); recognized {
		return result, err
	}
	if allowWholeBase64 {
		if decoded, ok := decodeBase64String(string(payload)); ok {
			result, err := importPayload(bytes.TrimSpace(decoded), false)
			if err != nil {
				return ImportResult{}, fmt.Errorf("decode base64 subscription: %w", err)
			}
			result.Format = "base64-" + result.Format
			return result, nil
		}
	}
	return ImportResult{}, errors.New("unsupported subscription format")
}

func importYAML(payload []byte) (ImportResult, bool, error) {
	if !looksLikeClashYAML(payload) {
		return ImportResult{}, false, nil
	}
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return ImportResult{}, true, fmt.Errorf("parse subscription YAML: %w", err)
	}
	if document.Proxies == nil {
		return ImportResult{}, false, nil
	}
	if len(document.Proxies) == 0 {
		return ImportResult{}, true, errors.New("subscription YAML contains no proxies")
	}
	nodes := make([]ImportedNode, 0, len(document.Proxies))
	for index, raw := range document.Proxies {
		node, err := sanitizeProxy(raw)
		if err != nil {
			return ImportResult{}, true, fmt.Errorf("proxy %d: %w", index, err)
		}
		nodes = append(nodes, node)
	}
	nodes, err := finalizeNodes(nodes)
	return ImportResult{Format: "clash-yaml", Nodes: nodes}, true, err
}

func looksLikeClashYAML(payload []byte) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxies:") && len(line)-len(strings.TrimLeft(line, " \t")) == 0 {
			return true
		}
	}
	return false
}

func importURIList(payload string) (ImportResult, bool, error) {
	lines := strings.Split(strings.ReplaceAll(payload, "\r\n", "\n"), "\n")
	var nodes []ImportedNode
	recognized := false
	for lineNumber, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !hasSupportedScheme(line) {
			if recognized {
				return ImportResult{}, true, fmt.Errorf("line %d is not a supported proxy URI", lineNumber+1)
			}
			return ImportResult{}, false, nil
		}
		recognized = true
		node, err := importURI(line)
		if err != nil {
			return ImportResult{}, true, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		nodes = append(nodes, node)
	}
	if !recognized {
		return ImportResult{}, false, nil
	}
	finalized, err := finalizeNodes(nodes)
	return ImportResult{Format: "uri-list", Nodes: finalized}, true, err
}

func importURI(value string) (ImportedNode, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return ImportedNode{}, fmt.Errorf("parse proxy URI: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "vmess" {
		return importVMessURI(strings.TrimPrefix(value, parsed.Scheme+":"))
	}
	if scheme == "ss" {
		return importShadowsocksURI(value)
	}
	if !oneOfString(scheme, "vless", "trojan", "hysteria2", "hy2", "tuic") {
		return ImportedNode{}, fmt.Errorf("unsupported proxy URI scheme %q", scheme)
	}
	port, err := parsePort(parsed.Port())
	if err != nil {
		return ImportedNode{}, err
	}
	name, err := url.PathUnescape(parsed.Fragment)
	if err != nil || strings.TrimSpace(name) == "" {
		name = scheme + "-" + parsed.Hostname()
	}
	config := map[string]any{
		"name":   name,
		"type":   mapSchemeType(scheme),
		"server": parsed.Hostname(),
		"port":   port,
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		password, hasPassword := parsed.User.Password()
		switch scheme {
		case "vless":
			config["uuid"] = username
		case "tuic":
			config["uuid"] = username
			if hasPassword {
				config["password"] = password
			}
		default:
			config["password"] = username
		}
	}
	copyURIOptions(config, parsed.Query())
	return sanitizeProxy(config)
}

func importVMessURI(encoded string) (ImportedNode, error) {
	decoded, ok := decodeBase64String(strings.TrimPrefix(encoded, "//"))
	if !ok {
		return ImportedNode{}, errors.New("vmess URI payload is not valid base64")
	}
	var raw map[string]any
	if err := json.Unmarshal(decoded, &raw); err != nil {
		return ImportedNode{}, fmt.Errorf("decode vmess JSON: %w", err)
	}
	config := map[string]any{
		"name":   stringValue(raw["ps"]),
		"type":   "vmess",
		"server": stringValue(raw["add"]),
		"port":   raw["port"],
		"uuid":   stringValue(raw["id"]),
	}
	copyIfPresent(config, raw, "cipher", "scy")
	copyIfPresent(config, raw, "alterId", "aid")
	copyIfPresent(config, raw, "network", "net")
	copyIfPresent(config, raw, "tls", "tls")
	copyIfPresent(config, raw, "servername", "sni")
	return sanitizeProxy(config)
}

func importShadowsocksURI(value string) (ImportedNode, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return ImportedNode{}, fmt.Errorf("parse shadowsocks URI: %w", err)
	}
	name, _ := url.PathUnescape(parsed.Fragment)
	var method, password, host, portText string
	if parsed.Hostname() != "" && parsed.User != nil {
		credentials := parsed.User.Username()
		if decoded, ok := decodeBase64String(credentials); ok {
			credentials = string(decoded)
		}
		parts := strings.SplitN(credentials, ":", 2)
		if len(parts) != 2 {
			return ImportedNode{}, errors.New("invalid shadowsocks credentials")
		}
		method, password = parts[0], parts[1]
		host, portText = parsed.Hostname(), parsed.Port()
	} else {
		encoded := strings.TrimPrefix(strings.SplitN(value, "#", 2)[0], "ss://")
		decoded, ok := decodeBase64String(encoded)
		if !ok {
			return ImportedNode{}, errors.New("invalid shadowsocks base64 payload")
		}
		credentialsAndEndpoint := string(decoded)
		at := strings.LastIndex(credentialsAndEndpoint, "@")
		if at < 1 {
			return ImportedNode{}, errors.New("invalid shadowsocks endpoint")
		}
		parts := strings.SplitN(credentialsAndEndpoint[:at], ":", 2)
		if len(parts) != 2 {
			return ImportedNode{}, errors.New("invalid shadowsocks credentials")
		}
		method, password = parts[0], parts[1]
		endpoint, err := url.Parse("ss://" + credentialsAndEndpoint[at+1:])
		if err != nil {
			return ImportedNode{}, errors.New("invalid shadowsocks endpoint")
		}
		host, portText = endpoint.Hostname(), endpoint.Port()
	}
	port, err := parsePort(portText)
	if err != nil {
		return ImportedNode{}, err
	}
	if strings.TrimSpace(name) == "" {
		name = "ss-" + host
	}
	return sanitizeProxy(map[string]any{"name": name, "type": "ss", "server": host, "port": port, "cipher": method, "password": password})
}

func sanitizeProxy(raw map[string]any) (ImportedNode, error) {
	for field := range raw {
		if controllerOwnedFields[field] {
			return ImportedNode{}, fmt.Errorf("field %q is controlled by Gateway VPN", field)
		}
		if !allowedProxyFields[field] {
			return ImportedNode{}, fmt.Errorf("unsupported proxy field %q", field)
		}
	}
	name := strings.TrimSpace(stringValue(raw["name"]))
	if name == "" || !utf8.ValidString(name) || len([]byte(name)) > MaxNodeNameBytes {
		return ImportedNode{}, errors.New("proxy name is empty, invalid UTF-8, or too long")
	}
	proxyType := strings.ToLower(strings.TrimSpace(stringValue(raw["type"])))
	if !supportedProxyTypes[proxyType] {
		return ImportedNode{}, fmt.Errorf("unsupported proxy type %q", proxyType)
	}
	server, err := normalizeServer(stringValue(raw["server"]))
	if err != nil {
		return ImportedNode{}, err
	}
	port, err := numericPort(raw["port"])
	if err != nil {
		return ImportedNode{}, err
	}
	if err := validateRequiredProxyFields(proxyType, raw); err != nil {
		return ImportedNode{}, err
	}

	config := make(map[string]any, len(raw))
	for key, value := range raw {
		safe, err := sanitizeValue(value, 0)
		if err != nil {
			return ImportedNode{}, fmt.Errorf("field %s: %w", key, err)
		}
		config[key] = safe
	}
	config["name"] = name
	config["type"] = proxyType
	config["server"] = server
	config["port"] = port

	fingerprintSource := make(map[string]any, len(config)-1)
	for key, value := range config {
		if key != "name" {
			fingerprintSource[key] = value
		}
	}
	canonical, err := json.Marshal(fingerprintSource)
	if err != nil {
		return ImportedNode{}, fmt.Errorf("canonicalize proxy: %w", err)
	}
	digest := sha256.Sum256(canonical)
	matchName := normalizeNodeName(name)
	return ImportedNode{
		ExternalName:   name,
		MatchName:      matchName,
		NormalizedName: matchName,
		Fingerprint:    hex.EncodeToString(digest[:]),
		ProxyType:      proxyType,
		Config:         config,
	}, nil
}

func validateRequiredProxyFields(proxyType string, raw map[string]any) error {
	require := func(field string) error {
		if strings.TrimSpace(stringValue(raw[field])) == "" {
			return fmt.Errorf("proxy type %s requires field %s", proxyType, field)
		}
		return nil
	}
	switch proxyType {
	case "vless", "vmess":
		return require("uuid")
	case "trojan", "hysteria2":
		return require("password")
	case "tuic":
		if err := require("uuid"); err != nil {
			return err
		}
		return require("password")
	case "ss":
		if err := require("cipher"); err != nil {
			return err
		}
		return require("password")
	default:
		return nil
	}
}

func finalizeNodes(nodes []ImportedNode) ([]ImportedNode, error) {
	if len(nodes) == 0 {
		return nil, errors.New("subscription contains no nodes")
	}
	if len(nodes) > MaxNodes {
		return nil, fmt.Errorf("subscription contains %d nodes; maximum is %d", len(nodes), MaxNodes)
	}
	fingerprints := make(map[string]string, len(nodes))
	names := make(map[string]int, len(nodes))
	for index := range nodes {
		if previous, exists := fingerprints[nodes[index].Fingerprint]; exists {
			return nil, fmt.Errorf("duplicate node fingerprint for %q and %q", previous, nodes[index].ExternalName)
		}
		fingerprints[nodes[index].Fingerprint] = nodes[index].ExternalName
		base := nodes[index].NormalizedName
		names[base]++
		if names[base] > 1 {
			nodes[index].NormalizedName = base + " [" + nodes[index].Fingerprint[:8] + "]"
		}
	}
	return nodes, nil
}

func sanitizeValue(value any, depth int) (any, error) {
	if depth > 8 {
		return nil, errors.New("nested value exceeds maximum depth")
	}
	switch typed := value.(type) {
	case nil, bool, int, int64, uint64, float64:
		return typed, nil
	case string:
		if len(typed) > 4096 || !utf8.ValidString(typed) {
			return nil, errors.New("string is invalid or too long")
		}
		return typed, nil
	case []any:
		if len(typed) > 64 {
			return nil, errors.New("list has too many elements")
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			safe, err := sanitizeValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = safe
		}
		return result, nil
	case map[string]any:
		if len(typed) > 64 {
			return nil, errors.New("map has too many fields")
		}
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if len(key) > 128 {
				return nil, errors.New("map key is too long")
			}
			safe, err := sanitizeValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = safe
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", value)
	}
}

func normalizeServer(value string) (string, error) {
	server := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if server == "" || len(server) > 253 {
		return "", errors.New("proxy server is empty or too long")
	}
	if address, err := netip.ParseAddr(server); err == nil {
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return "", errors.New("private, loopback, link-local, or non-unicast proxy IP is forbidden")
		}
		return address.String(), nil
	}
	if strings.HasSuffix(server, ".local") || strings.HasSuffix(server, ".localhost") || strings.HasSuffix(server, ".internal") || strings.HasSuffix(server, ".lan") || server == "localhost" {
		return "", errors.New("local proxy hostname is forbidden")
	}
	labels := strings.Split(server, ".")
	if len(labels) < 2 {
		return "", errors.New("proxy hostname must be fully qualified")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("proxy hostname contains an invalid label")
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return "", errors.New("proxy hostname must use ASCII or punycode labels")
		}
	}
	return server, nil
}

func numericPort(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return validatePort(typed)
	case int64:
		return validatePort(int(typed))
	case uint64:
		if typed > math.MaxInt {
			return 0, errors.New("proxy port is out of range")
		}
		return validatePort(int(typed))
	case float64:
		if typed != math.Trunc(typed) {
			return 0, errors.New("proxy port must be an integer")
		}
		return validatePort(int(typed))
	case string:
		return parsePort(typed)
	default:
		return 0, errors.New("proxy port is missing or invalid")
	}
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("proxy port is invalid")
	}
	return validatePort(port)
}

func validatePort(port int) (int, error) {
	if port < 1 || port > 65535 {
		return 0, errors.New("proxy port must be between 1 and 65535")
	}
	return port, nil
}

func normalizeNodeName(value string) string {
	return cases.Fold().String(strings.TrimSpace(norm.NFKC.String(value)))
}

func decodeBase64String(value string) ([]byte, bool) {
	compact := strings.Map(func(char rune) rune {
		if char == '\r' || char == '\n' || char == ' ' || char == '\t' {
			return -1
		}
		return char
	}, strings.TrimSpace(value))
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(compact); err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	return nil, false
}

func hasSupportedScheme(value string) bool {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func mapSchemeType(scheme string) string {
	if scheme == "hy2" {
		return "hysteria2"
	}
	return scheme
}

func copyURIOptions(config map[string]any, values url.Values) {
	for source, target := range map[string]string{
		"type": "network", "security": "tls", "sni": "servername", "flow": "flow", "fp": "client-fingerprint", "path": "path", "host": "host", "serviceName": "service-name",
	} {
		if value := values.Get(source); value != "" {
			config[target] = value
		}
	}
}

func copyIfPresent(destination, source map[string]any, destinationKey, sourceKey string) {
	if value, exists := source[sourceKey]; exists && stringValue(value) != "" {
		destination[destinationKey] = value
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		if typed == math.Trunc(typed) {
			return strconv.FormatInt(int64(typed), 10)
		}
	}
	return ""
}

func oneOfString(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

var supportedProxyTypes = map[string]bool{
	"ss": true, "vmess": true, "vless": true, "trojan": true, "hysteria2": true, "tuic": true,
}

var controllerOwnedFields = map[string]bool{
	"interface-name": true,
	"routing-mark":   true,
	"dialer-proxy":   true,
}

var allowedProxyFields = map[string]bool{
	"name": true, "type": true, "server": true, "port": true,
	"uuid": true, "password": true, "username": true, "cipher": true, "alterId": true,
	"udp": true, "network": true, "tls": true, "servername": true, "sni": true,
	"skip-cert-verify": true, "client-fingerprint": true, "alpn": true, "flow": true,
	"packet-encoding": true, "ws-opts": true, "grpc-opts": true, "reality-opts": true,
	"headers": true, "host": true, "path": true, "service-name": true,
	"up": true, "down": true, "obfs": true, "obfs-password": true,
	"congestion-controller": true, "udp-relay-mode": true, "disable-sni": true,
}
