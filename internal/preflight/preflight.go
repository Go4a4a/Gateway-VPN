// Package preflight performs read-only host capability checks. It never runs a
// network mutation command.
package preflight

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

type State string

const (
	StatePass State = "PASS"
	StateFail State = "FAIL"
	StateInfo State = "INFO"
)

type Check struct {
	ID      string
	State   State
	Message string
}

type Report struct {
	Checks []Check
}

func (report Report) Ready() bool {
	for _, check := range report.Checks {
		if check.State == StateFail {
			return false
		}
	}
	return true
}

func (report Report) String() string {
	lines := make([]string, 0, len(report.Checks)+1)
	for _, check := range report.Checks {
		lines = append(lines, fmt.Sprintf("[%s] %s: %s", check.State, check.ID, check.Message))
	}
	if report.Ready() {
		lines = append(lines, "preflight result: READY")
	} else {
		lines = append(lines, "preflight result: NOT_READY")
	}
	return strings.Join(lines, "\n")
}

type Probe interface {
	OperatingSystem() string
	Architecture() string
	LookPath(name string) (string, error)
	Stat(path string) error
	ReadFile(path string) ([]byte, error)
}

func RunHost() Report {
	return Run(hostProbe{})
}

func Run(probe Probe) Report {
	report := Report{}
	if probe.OperatingSystem() == "linux" {
		report.Checks = append(report.Checks, Check{ID: "os", State: StatePass, Message: "Linux host"})
	} else {
		report.Checks = append(report.Checks, Check{ID: "os", State: StateFail, Message: "target runtime requires Linux; found " + probe.OperatingSystem()})
	}
	if probe.Architecture() == "amd64" {
		report.Checks = append(report.Checks, Check{ID: "arch", State: StatePass, Message: "amd64 architecture"})
	} else {
		report.Checks = append(report.Checks, Check{ID: "arch", State: StateFail, Message: "MVP requires amd64; found " + probe.Architecture()})
	}

	for _, requirement := range []struct {
		id   string
		path string
	}{
		{"tun", "/dev/net/tun"},
		{"ipv4-forwarding-sysctl", "/proc/sys/net/ipv4/ip_forward"},
		{"ipv6-disable-sysctl", "/proc/sys/net/ipv6/conf/all/disable_ipv6"},
		{"systemd-runtime", "/run/systemd/system"},
	} {
		if err := probe.Stat(requirement.path); err != nil {
			report.Checks = append(report.Checks, Check{ID: requirement.id, State: StateFail, Message: requirement.path + " is unavailable"})
		} else {
			report.Checks = append(report.Checks, Check{ID: requirement.id, State: StatePass, Message: requirement.path + " is available"})
		}
	}

	for _, command := range []string{"ip", "nft", "wg", "systemctl", "networkctl"} {
		if path, err := probe.LookPath(command); err != nil {
			report.Checks = append(report.Checks, Check{ID: "command-" + command, State: StateFail, Message: command + " not found"})
		} else {
			report.Checks = append(report.Checks, Check{ID: "command-" + command, State: StatePass, Message: path})
		}
	}

	if content, err := probe.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		report.Checks = append(report.Checks, Check{ID: "kernel", State: StateInfo, Message: strings.TrimSpace(string(content))})
	} else {
		report.Checks = append(report.Checks, Check{ID: "kernel", State: StateFail, Message: "cannot read kernel release"})
	}

	sort.SliceStable(report.Checks, func(i, j int) bool { return report.Checks[i].ID < report.Checks[j].ID })
	return report
}

type hostProbe struct{}

func (hostProbe) OperatingSystem() string { return runtime.GOOS }
func (hostProbe) Architecture() string    { return runtime.GOARCH }
func (hostProbe) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}
func (hostProbe) Stat(path string) error {
	_, err := os.Stat(path)
	return err
}
func (hostProbe) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
