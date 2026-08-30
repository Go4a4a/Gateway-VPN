package managementfabric

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPairingStoresOnlyDigestConfirmsAndConsumesExactlyOnce(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("A", 48)
	bundle := testPairingBundle(t, repository, "invite:a", "vps:a", token, "10.80.0.0/24")
	invitation, err := repository.ImportPairing(ctx, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if invitation.State != "IMPORTED" || invitation.ExpectedFingerprint != bundle.ExpectedFingerprint || invitation.AttemptCount != 0 {
		t.Fatalf("imported invitation = %+v", invitation)
	}
	encoded, err := json.Marshal(invitation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "token_sha256") {
		t.Fatalf("pairing read model exposed token evidence: %s", encoded)
	}
	var storedDigest string
	if err := database.QueryRowContext(ctx, "SELECT token_sha256 FROM management_pairing_invitations WHERE id=?", invitation.ID).Scan(&storedDigest); err != nil {
		t.Fatal(err)
	}
	if storedDigest == token || storedDigest != tokenDigest(token) || len(storedDigest) != 64 {
		t.Fatalf("stored pairing token value = %q", storedDigest)
	}

	if _, err := repository.ConfirmPairing(ctx, invitation.ID, token, strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong fingerprint was accepted")
	}
	failed, err := repository.GetPairing(ctx, invitation.ID)
	if err != nil || failed.AttemptCount != 1 || failed.State != "IMPORTED" {
		t.Fatalf("failed confirmation state = %+v, %v", failed, err)
	}
	confirmed, err := repository.ConfirmPairing(ctx, invitation.ID, token, bundle.ExpectedFingerprint)
	if err != nil || confirmed.State != "CONFIRMED" || confirmed.AttemptCount != 1 {
		t.Fatalf("confirmed pairing = %+v, %v", confirmed, err)
	}
	confirmedAgain, err := repository.ConfirmPairing(ctx, invitation.ID, token, bundle.ExpectedFingerprint)
	if err != nil || confirmedAgain.State != "CONFIRMED" {
		t.Fatalf("idempotent pairing confirmation = %+v, %v", confirmedAgain, err)
	}

	link, err := repository.ConsumePairing(ctx, invitation.ID, token, PairingCompletion{
		LinkID: "link:paired", SiteID: "site:home",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:paired.key",
		LocalPublicKey:           testPublicKey(t), UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if link.VPSID != bundle.VPSID || link.ManagementSubnet != bundle.AssignedSubnet || link.Slot != 1 || link.InterfaceName != "gvm1" {
		t.Fatalf("paired link = %+v", link)
	}
	consumed, err := repository.GetPairing(ctx, invitation.ID)
	if err != nil || consumed.State != "CONSUMED" || consumed.ConsumedAt == "" {
		t.Fatalf("consumed invitation = %+v, %v", consumed, err)
	}
	if _, err := repository.ConsumePairing(ctx, invitation.ID, token, PairingCompletion{
		LinkID: "link:second", SiteID: "site:home", LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:second.key",
		LocalPublicKey: testPublicKey(t), UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
	}); err == nil {
		t.Fatal("consumed invitation was reused")
	}
	var links int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_links").Scan(&links); err != nil || links != 1 {
		t.Fatalf("link count after replay = %d, %v", links, err)
	}
}

func TestPairingAttemptBudgetExpiryAndCollisionAreDurable(t *testing.T) {
	t.Run("attempt budget", func(t *testing.T) {
		ctx, _, repository := managementFixture(t)
		if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
			t.Fatal(err)
		}
		token := strings.Repeat("B", 48)
		bundle := testPairingBundle(t, repository, "invite:budget", "vps:budget", token, "10.80.0.0/24")
		if _, err := repository.ImportPairing(ctx, bundle); err != nil {
			t.Fatal(err)
		}
		for attempt := 1; attempt <= pairingAttemptBudget; attempt++ {
			if _, err := repository.ConfirmPairing(ctx, bundle.InvitationID, token, strings.Repeat("0", 64)); err == nil {
				t.Fatalf("wrong fingerprint accepted on attempt %d", attempt)
			}
		}
		item, err := repository.GetPairing(ctx, bundle.InvitationID)
		if err != nil || item.State != "REJECTED" || item.AttemptCount != pairingAttemptBudget {
			t.Fatalf("attempt budget state = %+v, %v", item, err)
		}
		if _, err := repository.ConfirmPairing(ctx, bundle.InvitationID, token, bundle.ExpectedFingerprint); err == nil {
			t.Fatal("rejected invitation was revived")
		}
	})

	t.Run("expiry", func(t *testing.T) {
		ctx, _, repository := managementFixture(t)
		if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
			t.Fatal(err)
		}
		token := strings.Repeat("C", 48)
		bundle := testPairingBundle(t, repository, "invite:expiry", "vps:expiry", token, "10.80.0.0/24")
		if _, err := repository.ImportPairing(ctx, bundle); err != nil {
			t.Fatal(err)
		}
		repository.Now = func() time.Time { return time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC) }
		if _, err := repository.ConfirmPairing(ctx, bundle.InvitationID, token, bundle.ExpectedFingerprint); err == nil {
			t.Fatal("expired invitation was confirmed")
		}
		item, err := repository.GetPairing(ctx, bundle.InvitationID)
		if err != nil || item.State != "EXPIRED" {
			t.Fatalf("expired pairing state = %+v, %v", item, err)
		}
	})

	t.Run("consume proof budget", func(t *testing.T) {
		ctx, database, repository := managementFixture(t)
		if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
			t.Fatal(err)
		}
		token := strings.Repeat("E", 48)
		bundle := testPairingBundle(t, repository, "invite:consume-budget", "vps:consume-budget", token, "10.80.0.0/24")
		if _, err := repository.ImportPairing(ctx, bundle); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.ConfirmPairing(ctx, bundle.InvitationID, token, bundle.ExpectedFingerprint); err != nil {
			t.Fatal(err)
		}
		completion := PairingCompletion{
			LinkID: "link:consume-budget", SiteID: "site:home",
			LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:consume-budget.key",
			LocalPublicKey:           testPublicKey(t), UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
		}
		wrongToken := strings.Repeat("F", 48)
		for attempt := 1; attempt <= pairingAttemptBudget; attempt++ {
			if _, err := repository.ConsumePairing(ctx, bundle.InvitationID, wrongToken, completion); err == nil {
				t.Fatalf("wrong consume proof accepted on attempt %d", attempt)
			}
		}
		item, err := repository.GetPairing(ctx, bundle.InvitationID)
		if err != nil || item.State != "REJECTED" || item.AttemptCount != pairingAttemptBudget {
			t.Fatalf("consume proof budget state = %+v, %v", item, err)
		}
		var links int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_links").Scan(&links); err != nil || links != 0 {
			t.Fatalf("failed consume proof created links = %d, %v", links, err)
		}
	})

	t.Run("network collision rolls back staged VPS", func(t *testing.T) {
		ctx, database, repository := managementFixture(t)
		token := strings.Repeat("D", 48)
		bundle := testPairingBundle(t, repository, "invite:collision", "vps:collision", token, "192.168.200.0/24")
		if _, err := repository.ImportPairing(ctx, bundle); err == nil {
			t.Fatal("pairing subnet collision was accepted")
		}
		var vpsCount, invitationCount, nextVPS int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM vps_nodes").Scan(&vpsCount); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_pairing_invitations").Scan(&invitationCount); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, "SELECT next_vps_number FROM management_fabric_counters WHERE singleton_id=1").Scan(&nextVPS); err != nil {
			t.Fatal(err)
		}
		if vpsCount != 0 || invitationCount != 0 || nextVPS != 1 {
			t.Fatalf("failed import left partial state: VPS=%d invitation=%d next=%d", vpsCount, invitationCount, nextVPS)
		}
	})
}

func testPairingBundle(t *testing.T, repository *Repository, invitationID, vpsID, token, subnet string) PairingBundle {
	t.Helper()
	prefixOctet := "80"
	if strings.HasPrefix(subnet, "192.168.200.") {
		prefixOctet = "200"
	}
	local := "10." + prefixOctet + ".0.2"
	remote := "10." + prefixOctet + ".0.1"
	if prefixOctet == "200" {
		local = "192.168.200.2"
		remote = "192.168.200.1"
	}
	return PairingBundle{
		InvitationID: invitationID, Token: token, VPSID: vpsID, VPSName: "Pairing VPS",
		ExpectedFingerprint: strings.Repeat("e", 64), ExpectedPublicKey: testPublicKey(t),
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
		EndpointHost: "vps-pair.example.net", EndpointPort: 51821,
		AssignedSubnet: subnet, AssignedLocal: local, AssignedRemote: remote,
		ExpiresAt: repository.now().Add(time.Hour).Format(time.RFC3339Nano),
	}
}
