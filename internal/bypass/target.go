// Package bypass owns user-configured Internet access probe targets.
package bypass

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	KindDomain = "domain"
	KindURL    = "url"

	SuccessAnyHTTPResponse = "any_http_response"
	SuccessExpectedStatus  = "expected_status"
	SuccessExpectedBody    = "expected_body"

	MaxExpectedStatusBytes = 64
	MaxExpectedBodyBytes   = 256
)

type statusRange struct {
	first int
	last  int
}

func NormalizeTarget(kind, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) {
		return "", errors.New("probe target is empty, invalid, or too long")
	}
	if kind == KindDomain {
		value = "https://" + strings.TrimSuffix(value, "/") + "/"
	} else if kind != KindURL {
		return "", fmt.Errorf("unsupported probe target kind %q", kind)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return "", errors.New("probe target must be an HTTPS URL without credentials")
	}
	if parsed.Fragment != "" {
		return "", errors.New("probe target fragment is not allowed")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if err := validatePublicHost(host); err != nil {
		return "", err
	}
	if port := parsed.Port(); port != "" && !validPort(port) {
		return "", errors.New("probe target port is invalid")
	}
	parsed.Scheme = "https"
	port := parsed.Port()
	parsed.Host = host
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

// NormalizeStatusExpression accepts the status syntax supported by the
// pinned Mihomo health-check API. Comma and slash are accepted as list
// separators, while the stored/runtime representation always uses slash.
func NormalizeStatusExpression(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxExpectedStatusBytes || !utf8.ValidString(value) {
		return "", errors.New("expected status expression is empty, invalid, or too long")
	}
	parts := strings.Split(strings.ReplaceAll(value, ",", "/"), "/")
	if len(parts) == 0 || len(parts) > 32 {
		return "", errors.New("expected status expression has an invalid number of terms")
	}
	ranges := make([]statusRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", errors.New("expected status expression contains an empty term")
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return "", errors.New("expected status range is invalid")
		}
		first, err := parseHTTPStatus(strings.TrimSpace(bounds[0]))
		if err != nil {
			return "", err
		}
		last := first
		if len(bounds) == 2 {
			last, err = parseHTTPStatus(strings.TrimSpace(bounds[1]))
			if err != nil {
				return "", err
			}
			if last < first {
				return "", errors.New("expected status range must be ascending")
			}
		}
		ranges = append(ranges, statusRange{first: first, last: last})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].first == ranges[j].first {
			return ranges[i].last < ranges[j].last
		}
		return ranges[i].first < ranges[j].first
	})
	for index := 1; index < len(ranges); index++ {
		if ranges[index].first <= ranges[index-1].last {
			return "", errors.New("expected status terms overlap or repeat")
		}
	}
	canonical := make([]string, 0, len(ranges))
	for _, current := range ranges {
		if current.first == current.last {
			canonical = append(canonical, strconv.Itoa(current.first))
		} else {
			canonical = append(canonical, strconv.Itoa(current.first)+"-"+strconv.Itoa(current.last))
		}
	}
	return strings.Join(canonical, "/"), nil
}

func StatusMatches(expression string, status int) bool {
	canonical, err := NormalizeStatusExpression(expression)
	if err != nil || status < 100 || status > 599 {
		return false
	}
	for _, part := range strings.Split(canonical, "/") {
		bounds := strings.Split(part, "-")
		first, _ := strconv.Atoi(bounds[0])
		last := first
		if len(bounds) == 2 {
			last, _ = strconv.Atoi(bounds[1])
		}
		if status >= first && status <= last {
			return true
		}
	}
	return false
}

func parseHTTPStatus(value string) (int, error) {
	if len(value) != 3 {
		return 0, errors.New("HTTP status must contain exactly three digits")
	}
	status, err := strconv.Atoi(value)
	if err != nil || status < 100 || status > 599 {
		return 0, errors.New("HTTP status must be between 100 and 599")
	}
	return status, nil
}

func validatePublicHost(host string) error {
	if host == "" || len(host) > 253 {
		return errors.New("probe target host is empty or too long")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return errors.New("probe target IP must be public global unicast")
		}
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".internal") {
		return errors.New("local probe target hostname is forbidden")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("probe target hostname must be fully qualified")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("probe target hostname contains invalid label")
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return errors.New("probe target hostname must use ASCII or punycode")
		}
	}
	return nil
}
