// Package appconnector provides stateless management of app connector configurations
// and runtime node discovery based on policy file nodeAttrs.
package appconnector

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/notifier"
	v2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/types/views"
)

// Manager provides stateless management of app connector configurations.
// It discovers nodes with required tags at runtime and maintains configuration
// state without database persistence.
type Manager struct {
	mu sync.RWMutex

	// Runtime state (not persisted)
	activeConnectors map[string]*RuntimeConnector
	splitDNSEntries  map[string][]netip.Addr // domain -> connector node IPs

	// Configuration dependencies
	policy *v2.Policy
	users  []types.User
	nodes  views.Slice[types.NodeView]

	// Notification system
	notifier *notifier.Notifier

	// DNS update callback
	dnsUpdateCallback func()

	// Configuration tracking
	lastConfigUpdate time.Time
}

// RuntimeConnector represents an active app connector configuration
// with runtime state derived from current nodes and policy.
type RuntimeConnector struct {
	Name    string
	Tags    []string
	Domains []string
	Enabled bool

	// Runtime state
	AssignedNodes []RuntimeNode
	DNSRoutes     map[string][]netip.Addr
	LastUpdated   time.Time
}

// RuntimeNode represents a node that is serving as an app connector.
type RuntimeNode struct {
	ID       types.NodeID
	Hostname string
	IPv4     netip.Addr
	IPv6     netip.Addr
	Tags     []string
	Online   bool
}

// NewManager creates a new stateless App Connector Manager.
func NewManager(notifier *notifier.Notifier) *Manager {
	return &Manager{
		activeConnectors: make(map[string]*RuntimeConnector),
		splitDNSEntries:  make(map[string][]netip.Addr),
		notifier:         notifier,
		lastConfigUpdate: time.Now(),
	}
}

// UpdateConfiguration updates the manager with new policy, users, and nodes.
// This method handles configuration changes and triggers DNS updates when needed.
func (m *Manager) UpdateConfiguration(policy *v2.Policy, users []types.User, nodes views.Slice[types.NodeView]) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Debug().
		Int("node_count", nodes.Len()).
		Int("user_count", len(users)).
		Msg("Updating app connector configuration")

	// Store new configuration
	m.policy = policy
	m.users = users
	m.nodes = nodes
	m.lastConfigUpdate = time.Now()

	// Rebuild runtime state from configuration
	return m.rebuildRuntimeStateLocked()
}

// rebuildRuntimeStateLocked rebuilds all runtime state from the current configuration.
// Must be called with the lock held.
func (m *Manager) rebuildRuntimeStateLocked() error {
	oldConnectors := m.activeConnectors
	m.activeConnectors = make(map[string]*RuntimeConnector)
	m.splitDNSEntries = make(map[string][]netip.Addr)

	// If no policy is set, clear everything
	if m.policy == nil {
		log.Debug().Msg("No policy set, clearing app connector configuration")
		m.triggerDNSUpdate()
		return nil
	}

	// Process nodeAttrs to find app connector configurations
	for _, nodeAttr := range m.policy.NodeAttrs {
		if len(nodeAttr.App.AppConnectors) == 0 {
			continue
		}

		// Find nodes that match the nodeAttr targets
		matchingNodes, err := m.findMatchingNodesLocked(nodeAttr.Target)
		if err != nil {
			log.Error().Err(err).Msg("Failed to find matching nodes for nodeAttr")
			continue
		}

		// Process each app connector configuration
		for _, appConn := range nodeAttr.App.AppConnectors {
			if err := m.processAppConnectorLocked(appConn, matchingNodes); err != nil {
				log.Error().
					Err(err).
					Str("connector_name", appConn.Name).
					Msg("Failed to process app connector")
				continue
			}
		}
	}

	// Check if configuration changed and trigger DNS update if needed
	if m.hasConfigurationChangedLocked(oldConnectors) {
		log.Info().
			Int("active_connectors", len(m.activeConnectors)).
			Msg("App connector configuration updated")
		m.triggerDNSUpdate()
	}

	return nil
}

// findMatchingNodesLocked finds nodes that match the given nodeAttr targets.
// Must be called with the lock held.
func (m *Manager) findMatchingNodesLocked(targets v2.NodeAttrTargets) ([]RuntimeNode, error) {
	var matchingNodes []RuntimeNode

	for i := 0; i < m.nodes.Len(); i++ {
		node := m.nodes.At(i)

		// Check if node matches any of the targets
		matches := false
		for _, target := range targets {
			if m.nodeMatchesTargetLocked(node, target) {
				matches = true
				break
			}
		}

		if matches {
			runtimeNode := m.nodeToRuntimeNodeLocked(node)
			matchingNodes = append(matchingNodes, runtimeNode)
		}
	}

	return matchingNodes, nil
}

// nodeMatchesTargetLocked checks if a node matches a nodeAttr target.
// Must be called with the lock held.
func (m *Manager) nodeMatchesTargetLocked(node types.NodeView, target v2.NodeAttrTarget) bool {
	switch t := target.(type) {
	case v2.Asterix:
		// Wildcard matches all nodes
		return true
	case *v2.Tag:
		// Check if node has the required tag
		nodeTags := node.ForcedTags()
		for i := 0; i < nodeTags.Len(); i++ {
			if nodeTags.At(i) == string(*t) {
				return true
			}
		}
		return false
	case *v2.Group:
		// Check if node's user is in the group
		nodeUser := node.User()

		// Find group members in policy
		if groups, exists := m.policy.Groups[*t]; exists {
			for _, username := range groups {
				if string(username) == nodeUser.Name {
					return true
				}
			}
		}
		return false
	case *v2.Username:
		// Check if node belongs to the user
		nodeUser := node.User()
		return nodeUser.Name == string(*t)
	default:
		log.Warn().
			Type("target_type", target).
			Msg("Unknown nodeAttr target type")
		return false
	}
}

// nodeToRuntimeNodeLocked converts a NodeView to a RuntimeNode.
// Must be called with the lock held.
func (m *Manager) nodeToRuntimeNodeLocked(node types.NodeView) RuntimeNode {
	var ipv4, ipv6 netip.Addr

	// Extract IPv4 and IPv6 addresses
	if node.IPv4().Valid() {
		ipv4 = node.IPv4().Get()
	}
	if node.IPv6().Valid() {
		ipv6 = node.IPv6().Get()
	}

	// Extract tags - ForcedTags returns a slice, not a views.Slice
	nodeTags := node.ForcedTags()
	var tags []string
	for i := 0; i < nodeTags.Len(); i++ {
		tags = append(tags, nodeTags.At(i))
	}

	// Determine online status
	online := false
	if node.IsOnline().Valid() {
		online = node.IsOnline().Get()
	}

	return RuntimeNode{
		ID:       node.ID(),
		Hostname: node.Hostname(),
		IPv4:     ipv4,
		IPv6:     ipv6,
		Tags:     tags,
		Online:   online,
	}
}

// processAppConnectorLocked processes a single app connector configuration.
// Must be called with the lock held.
func (m *Manager) processAppConnectorLocked(appConn v2.AppConnector, candidateNodes []RuntimeNode) error {
	// Find nodes that match the connector tags
	var connectorNodes []RuntimeNode
	for _, node := range candidateNodes {
		if m.nodeMatchesConnectorLocked(node, appConn.Connectors) {
			connectorNodes = append(connectorNodes, node)
		}
	}

	if len(connectorNodes) == 0 {
		log.Debug().
			Str("connector_name", appConn.Name).
			Msg("No nodes found for app connector")
		return nil
	}

	// Create runtime connector
	runtimeConnector := &RuntimeConnector{
		Name:          appConn.Name,
		Domains:       appConn.Domains,
		Enabled:       true,
		AssignedNodes: connectorNodes,
		DNSRoutes:     make(map[string][]netip.Addr),
		LastUpdated:   time.Now(),
	}

	// Extract tags from connectors
	for _, connector := range appConn.Connectors {
		if tag, ok := connector.(*v2.Tag); ok {
			runtimeConnector.Tags = append(runtimeConnector.Tags, string(*tag))
		}
	}

	// Build DNS routes for split DNS
	for _, domain := range appConn.Domains {
		var ips []netip.Addr
		for _, node := range connectorNodes {
			if node.Online && node.IPv4.IsValid() {
				ips = append(ips, node.IPv4)
			}
			if node.Online && node.IPv6.IsValid() {
				ips = append(ips, node.IPv6)
			}
		}
		runtimeConnector.DNSRoutes[domain] = ips
		m.splitDNSEntries[domain] = ips
	}

	m.activeConnectors[appConn.Name] = runtimeConnector

	log.Debug().
		Str("connector_name", appConn.Name).
		Int("assigned_nodes", len(connectorNodes)).
		Int("domains", len(appConn.Domains)).
		Msg("Processed app connector")

	return nil
}

// nodeMatchesConnectorLocked checks if a node matches the connector requirements.
// Must be called with the lock held.
func (m *Manager) nodeMatchesConnectorLocked(node RuntimeNode, connectors v2.AppConnectorConnectors) bool {
	for _, connector := range connectors {
		if tag, ok := connector.(*v2.Tag); ok {
			for _, nodeTag := range node.Tags {
				if nodeTag == string(*tag) {
					return true
				}
			}
		}
	}
	return false
}

// hasConfigurationChangedLocked checks if the configuration has changed significantly.
// Must be called with the lock held.
func (m *Manager) hasConfigurationChangedLocked(oldConnectors map[string]*RuntimeConnector) bool {
	// Quick check: different number of connectors
	if len(oldConnectors) != len(m.activeConnectors) {
		return true
	}

	// Check each connector
	for name, newConn := range m.activeConnectors {
		oldConn, exists := oldConnectors[name]
		if !exists {
			return true
		}

		// Check if domains changed
		if len(oldConn.Domains) != len(newConn.Domains) {
			return true
		}
		for i, domain := range oldConn.Domains {
			if i >= len(newConn.Domains) || domain != newConn.Domains[i] {
				return true
			}
		}

		// Check if assigned nodes changed
		if len(oldConn.AssignedNodes) != len(newConn.AssignedNodes) {
			return true
		}

		// Check if DNS routes changed
		for domain, oldIPs := range oldConn.DNSRoutes {
			newIPs, exists := newConn.DNSRoutes[domain]
			if !exists || len(oldIPs) != len(newIPs) {
				return true
			}
			for i, oldIP := range oldIPs {
				if i >= len(newIPs) || oldIP != newIPs[i] {
					return true
				}
			}
		}
	}

	return false
}

// triggerDNSUpdate triggers the DNS update callback if configured.
func (m *Manager) triggerDNSUpdate() {
	if m.dnsUpdateCallback != nil {
		go func() {
			log.Debug().Msg("Triggering DNS update for app connectors")
			m.dnsUpdateCallback()
		}()
	}
}

// SetDNSUpdateCallback sets the callback function for DNS updates.
func (m *Manager) SetDNSUpdateCallback(callback func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsUpdateCallback = callback
}

// GetActiveConnectors returns a copy of the current active connectors.
func (m *Manager) GetActiveConnectors() map[string]RuntimeConnector {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]RuntimeConnector)
	for name, connector := range m.activeConnectors {
		// Create a deep copy
		connectorCopy := RuntimeConnector{
			Name:          connector.Name,
			Tags:          make([]string, len(connector.Tags)),
			Domains:       make([]string, len(connector.Domains)),
			Enabled:       connector.Enabled,
			AssignedNodes: make([]RuntimeNode, len(connector.AssignedNodes)),
			DNSRoutes:     make(map[string][]netip.Addr),
			LastUpdated:   connector.LastUpdated,
		}

		copy(connectorCopy.Tags, connector.Tags)
		copy(connectorCopy.Domains, connector.Domains)
		copy(connectorCopy.AssignedNodes, connector.AssignedNodes)

		for domain, ips := range connector.DNSRoutes {
			connectorCopy.DNSRoutes[domain] = make([]netip.Addr, len(ips))
			copy(connectorCopy.DNSRoutes[domain], ips)
		}

		result[name] = connectorCopy
	}

	return result
}

// GetSplitDNSEntries returns a copy of the current split DNS entries.
func (m *Manager) GetSplitDNSEntries() map[string][]netip.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]netip.Addr)
	for domain, ips := range m.splitDNSEntries {
		result[domain] = make([]netip.Addr, len(ips))
		copy(result[domain], ips)
	}

	return result
}

// GetStats returns statistics about the current app connector state.
func (m *Manager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalNodes, onlineNodes, totalDomains int
	for _, connector := range m.activeConnectors {
		totalNodes += len(connector.AssignedNodes)
		totalDomains += len(connector.Domains)
		for _, node := range connector.AssignedNodes {
			if node.Online {
				onlineNodes++
			}
		}
	}

	return ManagerStats{
		ActiveConnectors: len(m.activeConnectors),
		TotalNodes:       totalNodes,
		OnlineNodes:      onlineNodes,
		TotalDomains:     totalDomains,
		LastConfigUpdate: m.lastConfigUpdate,
	}
}

// ManagerStats provides statistics about the app connector manager state.
type ManagerStats struct {
	ActiveConnectors int
	TotalNodes       int
	OnlineNodes      int
	TotalDomains     int
	LastConfigUpdate time.Time
}

// String returns a human-readable string representation of the manager stats.
func (s ManagerStats) String() string {
	return fmt.Sprintf("AppConnectors: %d active, %d/%d nodes online, %d domains",
		s.ActiveConnectors, s.OnlineNodes, s.TotalNodes, s.TotalDomains)
}
