package mihomoruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gateway-vpn/internal/platformexec"
)

type IPLinkInspector struct {
	Executor platformexec.Executor
	IP       string
}

func (inspector IPLinkInspector) RequireReady(ctx context.Context, interfaceName string) error {
	if inspector.Executor == nil || inspector.IP != "/usr/sbin/ip" || !validInterfaceName(interfaceName) {
		return errors.New("fixed Ubuntu ip executor and valid TUN interface are required")
	}
	result, err := inspector.Executor.Run(ctx, platformexec.Request{Executable: inspector.IP, Arguments: []string{"-json", "link", "show", "dev", interfaceName}})
	if err != nil {
		return fmt.Errorf("inspect Mihomo TUN: %w", err)
	}
	var links []struct {
		IfName string   `json:"ifname"`
		Flags  []string `json:"flags"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &links); err != nil || len(links) != 1 || links[0].IfName != interfaceName {
		return errors.New("Mihomo TUN inspection returned an invalid link")
	}
	for _, flag := range links[0].Flags {
		if flag == "UP" {
			return nil
		}
	}
	return errors.New("Mihomo TUN exists but is not UP")
}
