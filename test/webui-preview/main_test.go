package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPreviewServesNetworkAndTopologyContracts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runContext(ctx, address, false, false, false) }()

	client := &http.Client{Timeout: 2 * time.Second}
	var networkBody, topologyBody, updatePolicyBody, updateAutomationBody, restorePointsBody []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		networkBody, err = getPreview(client, "http://"+address+"/api/v1/settings/network")
		if err == nil {
			topologyBody, err = getPreview(client, "http://"+address+"/api/v1/network/topology")
			if err == nil {
				updatePolicyBody, err = getPreview(client, "http://"+address+"/api/v1/settings/software-update")
				if err == nil {
					updateAutomationBody, err = getPreview(client, "http://"+address+"/api/v1/system/update/automation")
					if err == nil {
						restorePointsBody, err = getPreview(client, "http://"+address+"/api/v1/system/update/restore-points")
						if err == nil {
							break
						}
					}
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("preview API did not become ready: %v", err)
	}
	var network map[string]any
	if err := json.Unmarshal(networkBody, &network); err != nil {
		t.Fatal(err)
	}
	if network["interface_name"] != "gateway-vpn-lan" || network["lan_address"] != "192.168.200.1/24" {
		t.Fatalf("network settings = %s", networkBody)
	}
	var topology map[string]any
	if err := json.Unmarshal(topologyBody, &topology); err != nil {
		t.Fatal(err)
	}
	if topology["active_profile"] != "ETHERNET_HILINK" || topology["desired_generation"] != float64(1) {
		t.Fatalf("topology state = %s", topologyBody)
	}
	var updatePolicy map[string]any
	if err := json.Unmarshal(updatePolicyBody, &updatePolicy); err != nil {
		t.Fatal(err)
	}
	if updatePolicy["channel"] != "stable" || updatePolicy["maintenance_start_minute_utc"] != float64(180) {
		t.Fatalf("software update policy = %s", updatePolicyBody)
	}
	var updateAutomation struct {
		RuntimeState string `json:"runtime_state"`
		Status       struct {
			Phase              string `json:"phase"`
			StagedVersion      string `json:"staged_version"`
			CandidateReference string `json:"candidate_reference"`
		} `json:"status"`
	}
	if err := json.Unmarshal(updateAutomationBody, &updateAutomation); err != nil {
		t.Fatal(err)
	}
	if updateAutomation.RuntimeState != "AVAILABLE" || updateAutomation.Status.Phase != "WAITING_WINDOW" || updateAutomation.Status.StagedVersion != "1.2.0" || len(updateAutomation.Status.CandidateReference) < 160 {
		t.Fatalf("software update automation = %s", updateAutomationBody)
	}
	var restorePoints struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(restorePointsBody, &restorePoints); err != nil {
		t.Fatal(err)
	}
	if len(restorePoints.Items) != 2 {
		t.Fatalf("restore point inventory = %s", restorePointsBody)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("preview shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("preview did not shut down")
	}
}

func getPreview(client *http.Client, url string) ([]byte, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("preview HTTP %d: %s", response.StatusCode, body)
	}
	return body, nil
}
