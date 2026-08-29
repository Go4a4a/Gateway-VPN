package wgingress

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
	"gateway-vpn/internal/store"
)

const (
	listenerSetName = "wireguard_ingress_listeners"
	ownedNFTTable   = "gateway_vpn"
)

type Backend struct {
	Repository Repository
	Keys       KeyStore
	Executor   platformexec.Executor
	IP         string
	WG         string
	NFT        string
	Mutate     bool
	mutex      sync.Mutex
}

func (backend *Backend) GetServer(ctx context.Context) (Server, error) {
	if err := backend.ensure(ctx); err != nil {
		return Server{}, err
	}
	return backend.Repository.GetServer(ctx)
}

func (backend *Backend) ListPeers(ctx context.Context) ([]Peer, error) {
	if err := backend.ensure(ctx); err != nil {
		return nil, err
	}
	return backend.Repository.ListPeers(ctx)
}

func (backend *Backend) UpdateServer(ctx context.Context, input ServerUpdate) (Server, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Server{}, err
	}
	_, err := backend.Repository.UpdateServer(ctx, input)
	if err != nil {
		return Server{}, err
	}
	if err := backend.convergeUnlocked(ctx); err != nil {
		return Server{}, err
	}
	return backend.Repository.GetServer(ctx)
}

func (backend *Backend) CreatePeer(ctx context.Context, input PeerCreate) (Peer, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	var pair *KeyPair
	var preshared string
	if input.KeyMode == "MANAGED" {
		generated, err := GenerateKeyPair()
		if err != nil {
			return Peer{}, err
		}
		preshared, err = GeneratePresharedKey()
		if err != nil {
			return Peer{}, err
		}
		pair = &generated
	}
	peer, err := backend.Repository.CreatePeer(ctx, input, pair, preshared, backend.Keys)
	if err != nil {
		return Peer{}, err
	}
	if err := backend.convergeUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	return backend.Repository.GetPeer(ctx, peer.ID)
}

func (backend *Backend) UpdatePeer(ctx context.Context, id string, input PeerUpdate) (Peer, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	peer, err := backend.Repository.UpdatePeer(ctx, id, input)
	if err != nil {
		return Peer{}, err
	}
	if err := backend.convergeUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	return backend.Repository.GetPeer(ctx, peer.ID)
}

func (backend *Backend) RevokePeer(ctx context.Context, id string) (Peer, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	peer, err := backend.Repository.RevokePeer(ctx, id)
	if err != nil {
		return Peer{}, err
	}
	if err := backend.convergeUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	return backend.Repository.GetPeer(ctx, peer.ID)
}

func (backend *Backend) DeletePeer(ctx context.Context, id string) error {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return err
	}
	peer, err := backend.Repository.DeletePeer(ctx, id)
	if err != nil {
		return err
	}
	// The durable peer row is already gone. Remove its client-only secrets even
	// if kernel convergence fails: converge is fail-closed and a later cycle
	// can retry without those secrets because the peer is no longer rendered.
	convergeErr := backend.convergeUnlocked(ctx)
	var cleanupErr error
	if peer.privateKeySecretRef != "" {
		if err := backend.Keys.Remove(peer.privateKeySecretRef); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if peer.presharedKeySecretRef != "" {
		if err := backend.Keys.Remove(peer.presharedKeySecretRef); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return errors.Join(convergeErr, cleanupErr)
}

func (backend *Backend) RotatePeer(ctx context.Context, id string) (Peer, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	peer, err := backend.Repository.GetPeer(ctx, id)
	if err != nil {
		return Peer{}, err
	}
	if peer.KeyMode != "MANAGED" || peer.privateKeySecretRef == "" || peer.presharedKeySecretRef == "" {
		return Peer{}, errors.New("only a managed WireGuard peer key can be rotated")
	}
	oldPrivate, err := backend.Keys.Read(peer.privateKeySecretRef)
	if err != nil {
		return Peer{}, err
	}
	oldPreshared, err := backend.Keys.Read(peer.presharedKeySecretRef)
	if err != nil {
		return Peer{}, err
	}
	pair, err := GenerateKeyPair()
	if err != nil {
		return Peer{}, err
	}
	preshared, err := GeneratePresharedKey()
	if err != nil {
		return Peer{}, err
	}
	if err := backend.Keys.Write(peer.privateKeySecretRef, pair.Private); err != nil {
		return Peer{}, err
	}
	if err := backend.Keys.Write(peer.presharedKeySecretRef, preshared); err != nil {
		_ = backend.Keys.Write(peer.privateKeySecretRef, oldPrivate)
		return Peer{}, err
	}
	rotated, err := backend.Repository.RotatePeerKey(ctx, id, pair.Public)
	if err != nil {
		_ = backend.Keys.Write(peer.privateKeySecretRef, oldPrivate)
		_ = backend.Keys.Write(peer.presharedKeySecretRef, oldPreshared)
		return Peer{}, err
	}
	if err := backend.convergeUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	return backend.Repository.GetPeer(ctx, rotated.ID)
}

func (backend *Backend) RotateServer(ctx context.Context) (Server, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Server{}, err
	}
	server, err := backend.Repository.GetServer(ctx)
	if err != nil {
		return Server{}, err
	}
	oldPrivate, err := backend.Keys.Read(server.PrivateKeySecretRef)
	if err != nil {
		return Server{}, err
	}
	pair, err := GenerateKeyPair()
	if err != nil {
		return Server{}, err
	}
	if err := backend.Keys.Write(server.PrivateKeySecretRef, pair.Private); err != nil {
		return Server{}, err
	}
	if _, err := backend.Repository.RotateServerKey(ctx, server.ID, pair.Public); err != nil {
		_ = backend.Keys.Write(server.PrivateKeySecretRef, oldPrivate)
		return Server{}, err
	}
	if err := backend.convergeUnlocked(ctx); err != nil {
		return Server{}, err
	}
	return backend.Repository.GetServer(ctx)
}

func (backend *Backend) ProbePeer(ctx context.Context, id string) (Peer, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return Peer{}, err
	}
	if _, err := backend.Repository.GetPeer(ctx, id); err != nil {
		return Peer{}, err
	}
	if err := backend.observePeers(ctx); err != nil {
		return Peer{}, err
	}
	return backend.Repository.GetPeer(ctx, id)
}

func (backend *Backend) ExportPeerConfig(ctx context.Context, id string) (ExportedConfig, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return ExportedConfig{}, err
	}
	server, err := backend.Repository.GetServer(ctx)
	if err != nil {
		return ExportedConfig{}, err
	}
	peer, err := backend.Repository.GetPeer(ctx, id)
	if err != nil {
		return ExportedConfig{}, err
	}
	if peer.RevokedAt != "" {
		return ExportedConfig{}, errors.New("revoked WireGuard peer config is unavailable")
	}
	private := "<INSERT_PRIVATE_KEY>"
	preshared := ""
	managed := peer.KeyMode == "MANAGED"
	if managed {
		private, err = backend.Keys.Read(peer.privateKeySecretRef)
		if err != nil {
			return ExportedConfig{}, err
		}
		preshared, err = backend.Keys.Read(peer.presharedKeySecretRef)
		if err != nil {
			return ExportedConfig{}, err
		}
	}
	content, err := RenderClientConfig(server, peer, private, preshared)
	if err != nil {
		return ExportedConfig{}, err
	}
	return ExportedConfig{Filename: safeFilename(peer.Name, peer.DisplayNumber) + ".conf", Content: string(content), Managed: managed}, nil
}

func (backend *Backend) Sync(ctx context.Context) error {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.ensureUnlocked(ctx); err != nil {
		return err
	}
	return backend.convergeUnlocked(ctx)
}

func (backend *Backend) ensure(ctx context.Context) error {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	return backend.ensureUnlocked(ctx)
}

func (backend *Backend) ensureUnlocked(ctx context.Context) error {
	if backend == nil || backend.Repository.Database == nil || backend.Executor == nil || backend.IP != "/usr/sbin/ip" || backend.WG != "/usr/bin/wg" || backend.NFT != "/usr/sbin/nft" || backend.Keys.Root == "" {
		return errors.New("complete fixed WireGuard ingress backend is required")
	}
	_, err := backend.Repository.EnsureDefault(ctx, backend.Keys)
	return err
}

func (backend *Backend) convergeUnlocked(ctx context.Context) (err error) {
	server, err := backend.Repository.GetServer(ctx)
	if err != nil {
		return err
	}
	if !backend.Mutate {
		return nil
	}
	defer func() {
		if err == nil {
			return
		}
		_ = backend.failClosed(ctx, server)
		_ = backend.Repository.SetRuntime(ctx, server.ID, "ERROR", "WIREGUARD_INGRESS_APPLY_FAILED", server.AppliedGeneration)
	}()
	if !server.Enabled {
		if err := backend.disable(ctx, server); err != nil {
			return err
		}
		return backend.Repository.SetRuntime(ctx, server.ID, "DISABLED", "", server.DesiredGeneration)
	}
	if len(server.ListenInterfaces) == 0 || !ValidKey(server.PublicKey) {
		return errors.New("enabled WireGuard ingress server is incomplete")
	}
	privateKey, err := backend.Keys.Read(server.PrivateKeySecretRef)
	if err != nil {
		return err
	}
	derived, err := PublicKey(privateKey)
	if err != nil || derived != server.PublicKey {
		return errors.New("WireGuard ingress server key mismatch")
	}
	peers, err := backend.Repository.ListPeers(ctx)
	if err != nil {
		return err
	}
	mark, err := backend.egressMark(ctx, server)
	if err != nil {
		return err
	}
	configuration, err := backend.renderServerConfig(server, peers, privateKey, mark)
	if err != nil {
		return err
	}
	operations := []operation{
		{"create WireGuard ingress interface", backend.IP, []string{"link", "add", "dev", server.InterfaceName, "type", "wireguard"}, nil, []int{2}},
		{"synchronize WireGuard ingress peers", backend.WG, []string{"syncconf", server.InterfaceName, "/dev/stdin"}, configuration, nil},
		{"set WireGuard ingress address", backend.IP, []string{"-4", "address", "replace", server.ServerAddress, "dev", server.InterfaceName}, nil, nil},
		{"set WireGuard ingress MTU", backend.IP, []string{"link", "set", "dev", server.InterfaceName, "mtu", strconv.Itoa(server.MTU)}, nil, nil},
		{"bring WireGuard ingress up", backend.IP, []string{"link", "set", "dev", server.InterfaceName, "up"}, nil, nil},
		{"remove obsolete owned WireGuard ingress routes", backend.IP, []string{"-4", "route", "flush", "dev", server.InterfaceName, "protocol", strconv.Itoa(routing.OwnedProtocol)}, nil, []int{1, 2}},
	}
	for _, peer := range peers {
		if !peer.Enabled || peer.RevokedAt != "" {
			continue
		}
		for _, route := range peer.BehindSubnets {
			operations = append(operations, operation{"install WireGuard ingress peer route", backend.IP, []string{"-4", "route", "replace", route, "dev", server.InterfaceName, "protocol", strconv.Itoa(routing.OwnedProtocol)}, nil, nil})
		}
	}
	for _, item := range operations {
		if err := backend.run(ctx, item); err != nil {
			return err
		}
	}
	if err := backend.syncListeners(ctx, server); err != nil {
		return err
	}
	if err := backend.observePeers(ctx); err != nil {
		return err
	}
	return backend.Repository.SetRuntime(ctx, server.ID, "ACTIVE", "", server.DesiredGeneration)
}

type operation struct {
	description string
	executable  string
	arguments   []string
	stdin       []byte
	allowed     []int
}

func (backend *Backend) run(ctx context.Context, item operation) error {
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: item.executable, Arguments: item.arguments, Stdin: item.stdin})
	if err == nil || containsInt(item.allowed, result.ExitCode) {
		return nil
	}
	return fmt.Errorf("%s failed", item.description)
}

func (backend *Backend) disable(ctx context.Context, server Server) error {
	if err := backend.syncListeners(ctx, Server{}); err != nil {
		return err
	}
	return backend.run(ctx, operation{"delete WireGuard ingress interface", backend.IP, []string{"link", "delete", "dev", server.InterfaceName}, nil, []int{1, 2}})
}

func (backend *Backend) failClosed(ctx context.Context, server Server) error {
	_ = backend.syncListeners(ctx, Server{})
	return backend.run(ctx, operation{"fail-close WireGuard ingress interface", backend.IP, []string{"link", "delete", "dev", server.InterfaceName}, nil, []int{1, 2}})
}

func (backend *Backend) syncListeners(ctx context.Context, server Server) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "flush set inet %s %s\n", ownedNFTTable, listenerSetName)
	if server.Enabled {
		for _, item := range server.ListenInterfaces {
			if !validInterfaceName(item.InterfaceName) {
				return errors.New("WireGuard ingress listener interface is unavailable")
			}
			fmt.Fprintf(&builder, "add element inet %s %s { %s . %d }\n", ownedNFTTable, listenerSetName, strconv.Quote(item.InterfaceName), server.ListenPort)
		}
	}
	payload := []byte(builder.String())
	if result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--check", "--file", "-"}, Stdin: payload}); err != nil {
		_ = result
		return errors.New("validate WireGuard ingress firewall listener set failed")
	}
	if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--file", "-"}, Stdin: payload}); err != nil {
		return errors.New("apply WireGuard ingress firewall listener set failed")
	}
	return nil
}

func (backend *Backend) renderServerConfig(server Server, peers []Peer, private string, mark uint32) ([]byte, error) {
	if !ValidKey(private) || server.InterfaceName != DefaultInterfaceName || server.ListenPort < 1 || server.ListenPort > 65535 {
		return nil, errors.New("invalid WireGuard ingress server config")
	}
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = ")
	builder.WriteString(private)
	fmt.Fprintf(&builder, "\nListenPort = %d\n", server.ListenPort)
	if mark != 0 {
		fmt.Fprintf(&builder, "FwMark = %#x\n", mark)
	}
	seen := make(map[string]struct{})
	for _, peer := range peers {
		if !peer.Enabled || peer.RevokedAt != "" {
			continue
		}
		if !ValidKey(peer.PublicKey) {
			return nil, errors.New("stored WireGuard ingress peer public key is invalid")
		}
		if _, exists := seen[peer.PublicKey]; exists {
			return nil, errors.New("duplicate WireGuard ingress peer public key")
		}
		seen[peer.PublicKey] = struct{}{}
		builder.WriteString("\n[Peer]\nPublicKey = ")
		builder.WriteString(peer.PublicKey)
		if peer.presharedKeySecretRef != "" {
			preshared, err := backend.Keys.Read(peer.presharedKeySecretRef)
			if err != nil {
				return nil, err
			}
			builder.WriteString("\nPresharedKey = ")
			builder.WriteString(preshared)
		}
		builder.WriteString("\nAllowedIPs = ")
		builder.WriteString(strings.Join(CanonicalPeerNetworks(peer), ", "))
		if peer.EndpointOverride != "" {
			builder.WriteString("\nEndpoint = ")
			builder.WriteString(peer.EndpointOverride)
		}
		fmt.Fprintf(&builder, "\nPersistentKeepalive = %d\n", peer.PersistentKeepalive)
	}
	return []byte(builder.String()), nil
}

func (backend *Backend) egressMark(ctx context.Context, server Server) (uint32, error) {
	if server.NetworkInterfaceID == "" {
		if server.TopologyMode == "ONE_ARM" {
			return 0, errors.New("one-card WireGuard ingress server has no selected uplink interface")
		}
		return 0, nil
	}
	var mark int64
	err := backend.Repository.Database.QueryRowContext(ctx, `
SELECT fwmark FROM uplinks
WHERE network_interface_id=? AND enabled=1
ORDER BY priority, id LIMIT 1`, server.NetworkInterfaceID).Scan(&mark)
	if errors.Is(err, sql.ErrNoRows) {
		if server.TopologyMode == "ONE_ARM" {
			return 0, errors.New("one-card WireGuard ingress interface has no enabled uplink")
		}
		return 0, nil
	}
	if err != nil || mark <= 0 || mark > int64(^uint32(0)) {
		return 0, errors.New("WireGuard ingress uplink mark is invalid")
	}
	return uint32(mark), nil
}

func (backend *Backend) observePeers(ctx context.Context) error {
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.WG, Arguments: []string{"show", DefaultInterfaceName, "dump"}})
	if err != nil {
		return errors.New("observe WireGuard ingress peers failed")
	}
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	// `wg show <interface> dump` emits exactly four interface fields before
	// zero or more eight-field peer rows: private-key, public-key, listen-port,
	// fwmark. An enabled server with no clients is a valid initial state.
	if len(lines) == 0 || len(strings.Split(lines[0], "\t")) < 4 {
		return errors.New("WireGuard ingress dump is invalid")
	}
	values := make([]PeerRuntime, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 || !ValidKey(fields[0]) {
			return errors.New("WireGuard ingress peer dump is invalid")
		}
		handshakeSeconds, err1 := strconv.ParseInt(fields[4], 10, 64)
		rx, err2 := strconv.ParseInt(fields[5], 10, 64)
		tx, err3 := strconv.ParseInt(fields[6], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || handshakeSeconds < 0 || rx < 0 || tx < 0 {
			return errors.New("WireGuard ingress peer counters are invalid")
		}
		var handshake time.Time
		if handshakeSeconds > 0 {
			handshake = time.Unix(handshakeSeconds, 0).UTC()
		}
		values = append(values, PeerRuntime{PublicKey: fields[0], Endpoint: fields[2], HandshakeAt: handshake, RXBytes: rx, TXBytes: tx})
	}
	return backend.Repository.UpdatePeerRuntime(ctx, values)
}

func RenderClientConfig(server Server, peer Peer, privateKey, presharedKey string) ([]byte, error) {
	if !ValidKey(server.PublicKey) || peer.AssignedAddress == "" || server.Endpoint == "" || len(peer.ClientAllowedIPs) == 0 {
		return nil, errors.New("complete WireGuard client configuration is required")
	}
	if peer.KeyMode == "MANAGED" && (!ValidKey(privateKey) || !ValidKey(presharedKey)) {
		return nil, errors.New("managed WireGuard client secrets are unavailable")
	}
	if peer.KeyMode == "EXTERNAL" && privateKey != "<INSERT_PRIVATE_KEY>" {
		return nil, errors.New("external WireGuard client template must not contain a private key")
	}
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = ")
	builder.WriteString(privateKey)
	builder.WriteString("\nAddress = ")
	builder.WriteString(peer.AssignedAddress)
	builder.WriteString("/32\n")
	if peer.ClientDNSEnabled && len(server.DNS) != 0 {
		builder.WriteString("DNS = ")
		builder.WriteString(strings.Join(server.DNS, ", "))
		builder.WriteByte('\n')
	}
	fmt.Fprintf(&builder, "MTU = %d\n\n[Peer]\nPublicKey = %s\n", server.MTU, server.PublicKey)
	if presharedKey != "" {
		builder.WriteString("PresharedKey = ")
		builder.WriteString(presharedKey)
		builder.WriteByte('\n')
	}
	builder.WriteString("Endpoint = ")
	builder.WriteString(server.Endpoint)
	builder.WriteString("\nAllowedIPs = ")
	builder.WriteString(strings.Join(peer.ClientAllowedIPs, ", "))
	fmt.Fprintf(&builder, "\nPersistentKeepalive = %d\n", peer.PersistentKeepalive)
	return []byte(builder.String()), nil
}

func safeFilename(name string, number int64) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var builder strings.Builder
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else if builder.Len() != 0 && !strings.HasSuffix(builder.String(), "-") {
			builder.WriteByte('-')
		}
		if builder.Len() >= 48 {
			break
		}
	}
	value := strings.Trim(builder.String(), "-")
	if value == "" {
		value = "wireguard-client-" + strconv.FormatInt(number, 10)
	}
	return value
}

func containsInt(values []int, expected int) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func sortedPeers(peers []Peer) []Peer {
	result := append([]Peer(nil), peers...)
	sort.Slice(result, func(left, right int) bool { return result[left].DisplayNumber < result[right].DisplayNumber })
	return result
}

var _ = netip.Addr{}
var _ = store.ErrNotFound
