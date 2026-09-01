package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestNormalizeEd25519PublicKeyAcceptsExactWireKeyAndDropsComment(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := appendWireField(nil, []byte("ssh-ed25519"))
	payload = appendWireField(payload, public)
	encoded := base64.StdEncoding.EncodeToString(payload)
	got, err := normalizeEd25519PublicKey("ssh-ed25519 " + encoded + " disposable-comment\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ssh-ed25519 "+encoded {
		t.Fatalf("normalized public key=%q", got)
	}
}

func TestNormalizeEd25519PublicKeyRejectsUnsafeOrWrongPayload(t *testing.T) {
	for _, value := range []string{
		"ssh-rsa AAAA",
		"ssh-ed25519 %%%",
		"ssh-ed25519 " + base64.StdEncoding.EncodeToString(appendWireField(nil, []byte("ssh-ed25519"))),
		"ssh-ed25519 AAAA\r\n",
		"ssh-ed25519 AAAA\nsecond\n",
	} {
		if _, err := normalizeEd25519PublicKey(value); err == nil {
			t.Fatalf("unsafe public key accepted: %q", value)
		}
	}
}

func TestTargetNamesAreBoundedDistinctAndRoleScoped(t *testing.T) {
	settings := options{runID: "win10-20260901", gatewayPort: 22101, vpsPort: 22102}
	targets := allTargetNames(settings)
	if len(targets) != 2 || targets[0].Role != "gateway" || targets[1].Role != "vps" {
		t.Fatalf("unexpected targets: %+v", targets)
	}
	seen := make(map[string]bool)
	for _, target := range targets {
		for _, name := range []string{target.Stage, target.Final, target.PreparedImage} {
			if len(name) > 63 || seen[name] {
				t.Fatalf("unsafe or duplicate derived name %q", name)
			}
			seen[name] = true
		}
	}
}

func TestImageAndRunIDContractsRejectMutableOrInjectableInput(t *testing.T) {
	if !runIDPattern.MatchString("win10-20260901") {
		t.Fatal("safe run id rejected")
	}
	for _, value := range []string{"", "UPPER", "a_b", "-start", strings.Repeat("a", 21)} {
		if runIDPattern.MatchString(value) {
			t.Fatalf("unsafe run id accepted: %q", value)
		}
	}
	for _, value := range []string{"image", "image:latest", "Image:tag", "image:tag;rm", "image@sha256:" + strings.Repeat("a", 64)} {
		if imagePattern.MatchString(value) && !strings.HasSuffix(value, ":latest") && !strings.Contains(value, "..") {
			t.Fatalf("unsafe image reference accepted by full contract: %q", value)
		}
	}
}

func TestSSHPolicyIsKeyOnlyAndCleanAssertionCoversBothRoles(t *testing.T) {
	for _, required := range []string{
		"PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin prohibit-password", "AllowUsers root",
		"install -d -o root -g root -m 0755 /run/sshd",
		"/opt/gateway-vpn", "/opt/gateway-vpn-vps", "/var/lib/gateway-vpn-privileged", "/var/lib/gateway-vpn-vps-privileged",
	} {
		if !strings.Contains(sshdPolicy+hardenSSHScript+assertCleanTargetScript, required) {
			t.Fatalf("required release-gate policy missing %q", required)
		}
	}
	for _, forbidden := range []string{"PasswordAuthentication yes", "PermitRootLogin yes", "docker rm", "docker image rm", "0.0.0.0"} {
		if strings.Contains(sshdPolicy+hardenSSHScript+assertCleanTargetScript, forbidden) {
			t.Fatalf("forbidden release-gate behavior present %q", forbidden)
		}
	}
}

func TestRunRequiresBothReleaseGateGuardsBeforePlatformOrDocker(t *testing.T) {
	original, present := os.LookupEnv(releaseGateEnvironment)
	if err := os.Unsetenv(releaseGateEnvironment); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if present {
			_ = os.Setenv(releaseGateEnvironment, original)
		} else {
			_ = os.Unsetenv(releaseGateEnvironment)
		}
	}()
	var stdout, stderr strings.Builder
	if code := run([]string{"--release-gate-only"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unguarded run code=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), releaseGateEnvironment) {
		t.Fatalf("unguarded run emitted unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func appendWireField(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}
