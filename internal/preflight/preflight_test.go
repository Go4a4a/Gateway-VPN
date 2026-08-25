package preflight

import (
	"errors"
	"strings"
	"testing"
)

func TestReadyLinuxHost(t *testing.T) {
	probe := fakeProbe{
		goos:   "linux",
		goarch: "amd64",
		commands: map[string]string{
			"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft", "wg": "/usr/bin/wg", "systemctl": "/usr/bin/systemctl", "networkctl": "/usr/bin/networkctl",
		},
		paths: map[string]bool{
			"/dev/net/tun":                             true,
			"/proc/sys/net/ipv4/ip_forward":            true,
			"/proc/sys/net/ipv6/conf/all/disable_ipv6": true,
			"/run/systemd/system":                      true,
		},
		files: map[string]string{"/proc/sys/kernel/osrelease": "6.8.0-test\n"},
	}
	report := Run(probe)
	if !report.Ready() {
		t.Fatalf("Run() Ready = false:\n%s", report.String())
	}
	if !strings.Contains(report.String(), "preflight result: READY") {
		t.Fatalf("report missing READY result:\n%s", report.String())
	}
}

func TestWrongOSAndMissingCapabilitiesFail(t *testing.T) {
	report := Run(fakeProbe{goos: "windows", goarch: "amd64"})
	if report.Ready() {
		t.Fatal("Run() Ready = true, want false")
	}
	text := report.String()
	for _, expected := range []string{"target runtime requires Linux", "tun", "command-nft", "NOT_READY"} {
		if !strings.Contains(text, expected) {
			t.Errorf("report missing %q:\n%s", expected, text)
		}
	}
}

type fakeProbe struct {
	goos     string
	goarch   string
	commands map[string]string
	paths    map[string]bool
	files    map[string]string
}

func (probe fakeProbe) OperatingSystem() string { return probe.goos }
func (probe fakeProbe) Architecture() string    { return probe.goarch }
func (probe fakeProbe) LookPath(name string) (string, error) {
	if path := probe.commands[name]; path != "" {
		return path, nil
	}
	return "", errors.New("not found")
}
func (probe fakeProbe) Stat(path string) error {
	if probe.paths[path] {
		return nil
	}
	return errors.New("not found")
}
func (probe fakeProbe) ReadFile(path string) ([]byte, error) {
	if content, exists := probe.files[path]; exists {
		return []byte(content), nil
	}
	return nil, errors.New("not found")
}
