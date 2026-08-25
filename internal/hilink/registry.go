package hilink

import (
	"context"
	"errors"
	"sort"
	"sync"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/store"
)

type DiscoveryView struct {
	DiscoveryID   string `json:"discovery_id"`
	InterfaceName string `json:"interface_name"`
	VendorID      string `json:"vendor_id"`
	ProductID     string `json:"product_id"`
	Driver        string `json:"driver"`
	Carrier       bool   `json:"carrier"`
	IdentityKind  string `json:"identity_kind"`
	MaskedSerial  string `json:"masked_serial"`
	TopologyHint  string `json:"topology_hint"`
	State         string `json:"state"`
	Reason        string `json:"reason,omitempty"`
}

type DiscoveryRegistry struct {
	Modems *modem.Repository
	mutex  sync.RWMutex
	items  map[string]Match
}

func NewDiscoveryRegistry(modems *modem.Repository) *DiscoveryRegistry {
	return &DiscoveryRegistry{Modems: modems, items: make(map[string]Match)}
}

func (registry *DiscoveryRegistry) Replace(matches []Match) {
	if registry == nil {
		return
	}
	next := make(map[string]Match, len(matches))
	for _, match := range matches {
		if match.Candidate.DiscoveryID != "" {
			next[match.Candidate.DiscoveryID] = match
		}
	}
	registry.mutex.Lock()
	registry.items = next
	registry.mutex.Unlock()
}

func (registry *DiscoveryRegistry) List() []DiscoveryView {
	if registry == nil {
		return nil
	}
	registry.mutex.RLock()
	result := make([]DiscoveryView, 0, len(registry.items))
	for _, match := range registry.items {
		candidate := match.Candidate
		result = append(result, DiscoveryView{
			DiscoveryID: candidate.DiscoveryID, InterfaceName: candidate.InterfaceName,
			VendorID: candidate.VendorID, ProductID: candidate.ProductID, Driver: candidate.Driver,
			Carrier: candidate.Carrier, IdentityKind: candidate.IdentityKind,
			MaskedSerial: candidate.MaskedSerial, TopologyHint: candidate.TopologyHint,
			State: match.State, Reason: match.Reason,
		})
	}
	registry.mutex.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].DiscoveryID < result[j].DiscoveryID })
	return result
}

func (registry *DiscoveryRegistry) IsConnected(modemID string) bool {
	if registry == nil || modemID == "" {
		return false
	}
	registry.mutex.RLock()
	defer registry.mutex.RUnlock()
	for _, match := range registry.items {
		if match.State == DiscoveryMatched && match.ModemID == modemID {
			return true
		}
	}
	return false
}

func (registry *DiscoveryRegistry) Adopt(ctx context.Context, discoveryID, modemID, name, operatorLabel string) (modem.Modem, error) {
	if registry == nil || registry.Modems == nil || discoveryID == "" || modemID == "" {
		return modem.Modem{}, errors.New("discovery registry, discovery id, and modem id are required")
	}
	registry.mutex.RLock()
	match, exists := registry.items[discoveryID]
	registry.mutex.RUnlock()
	if !exists {
		return modem.Modem{}, store.ErrNotFound
	}
	if match.State != DiscoveryUnadopted {
		return modem.Modem{}, errors.New("only an unadopted unambiguous modem can be adopted")
	}
	created, err := registry.Modems.Adopt(ctx, modem.AdoptInput{
		ID: modemID, Name: name, OperatorLabel: operatorLabel,
		IdentityKind: match.Candidate.IdentityKind, IdentityHash: match.Candidate.IdentityHash,
		MaskedSerial: match.Candidate.MaskedSerial,
	})
	if err != nil {
		return modem.Modem{}, err
	}
	registry.mutex.Lock()
	delete(registry.items, discoveryID)
	registry.mutex.Unlock()
	return created, nil
}

func (registry *DiscoveryRegistry) ReplaceIdentity(ctx context.Context, discoveryID, modemID string) error {
	if registry == nil || registry.Modems == nil || discoveryID == "" || modemID == "" {
		return errors.New("discovery registry, discovery id, and modem id are required")
	}
	registry.mutex.RLock()
	match, exists := registry.items[discoveryID]
	registry.mutex.RUnlock()
	if !exists {
		return store.ErrNotFound
	}
	if match.State != DiscoveryUnadopted {
		return errors.New("replacement identity must be an unadopted unambiguous modem")
	}
	if err := registry.Modems.ReplaceIdentity(ctx, modemID, modem.ReplaceIdentityInput{
		IdentityKind: match.Candidate.IdentityKind, IdentityHash: match.Candidate.IdentityHash,
		MaskedSerial: match.Candidate.MaskedSerial,
	}); err != nil {
		return err
	}
	registry.mutex.Lock()
	delete(registry.items, discoveryID)
	registry.mutex.Unlock()
	return nil
}
