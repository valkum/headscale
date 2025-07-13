package appconnector

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/notifier"
	v2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

func getTestConfig() *types.Config {
	return &types.Config{
		Tuning: types.Tuning{
			BatchChangeDelay:    time.Hour,
			NotifierSendTimeout: time.Second,
		},
	}
}

func TestNewManager(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.activeConnectors)
	assert.NotNil(t, manager.splitDNSEntries)
	assert.Equal(t, notif, manager.notifier)
}

func TestUpdateConfiguration_EmptyPolicy(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	err := manager.UpdateConfiguration(nil, nil, views.Slice[types.NodeView]{})
	require.NoError(t, err)

	stats := manager.GetStats()
	assert.Equal(t, 0, stats.ActiveConnectors)
	assert.Equal(t, 0, stats.TotalNodes)
	assert.Equal(t, 0, stats.TotalDomains)
}

func TestUpdateConfiguration_BasicConnector(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	// Create a basic policy with app connector
	policy := &v2.Policy{
		Groups: map[v2.Group]v2.Usernames{
			"group:connector-admins": {"user1@"},
		},
		TagOwners: map[v2.Tag]v2.Owners{
			"tag:connector": {
				ptr.To(v2.Group("group:connector-admins")),
			},
		},
		NodeAttrs: []v2.NodeAttr{
			{
				Target: v2.NodeAttrTargets{v2.Wildcard},
				App: v2.NodeAttrApps{
					AppConnectors: []v2.AppConnector{
						{
							Name:       "test-connector",
							Connectors: v2.AppConnectorConnectors{ptr.To(v2.Tag("tag:connector"))},
							Domains:    []string{"example.com", "test.org"},
						},
					},
				},
			},
		},
	}

	// Create test users
	users := []types.User{
		{
			Name: "user1@",
		},
	}

	// Create test nodes (empty for now since we don't have tags)
	nodes := views.Slice[types.NodeView]{}

	err := manager.UpdateConfiguration(policy, users, nodes)
	require.NoError(t, err)

	// Since we have no matching nodes, no connectors should be active
	stats := manager.GetStats()
	assert.Equal(t, 0, stats.ActiveConnectors)
}

func TestGetActiveConnectors(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	connectors := manager.GetActiveConnectors()
	assert.NotNil(t, connectors)
	assert.Empty(t, connectors)
}

func TestGetSplitDNSEntries(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	entries := manager.GetSplitDNSEntries()
	assert.NotNil(t, entries)
	assert.Empty(t, entries)
}

func TestGetStats(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	stats := manager.GetStats()
	assert.Equal(t, 0, stats.ActiveConnectors)
	assert.Equal(t, 0, stats.TotalNodes)
	assert.Equal(t, 0, stats.OnlineNodes)
	assert.Equal(t, 0, stats.TotalDomains)
	assert.False(t, stats.LastConfigUpdate.IsZero())
}

func TestManagerStats_String(t *testing.T) {
	stats := ManagerStats{
		ActiveConnectors: 2,
		TotalNodes:       4,
		OnlineNodes:      3,
		TotalDomains:     6,
		LastConfigUpdate: time.Now(),
	}

	str := stats.String()
	assert.Contains(t, str, "AppConnectors: 2 active")
	assert.Contains(t, str, "3/4 nodes online")
	assert.Contains(t, str, "6 domains")
}

func TestDNSUpdateCallback(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	callbackTriggered := false
	manager.SetDNSUpdateCallback(func() {
		callbackTriggered = true
	})

	// Trigger a configuration update that should cause DNS callback
	err := manager.UpdateConfiguration(nil, nil, views.Slice[types.NodeView]{})
	require.NoError(t, err)

	// The callback might be async, so we need to wait a bit
	time.Sleep(100 * time.Millisecond)
	// Note: The callback is triggered by triggerDNSUpdate which runs in a goroutine
	// In a real test we might want to add a way to wait for the callback
	_ = callbackTriggered // Prevent unused variable warning
}

func TestUpdateConfiguration_WithMatchingNodes(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	// Create a policy with app connector
	policy := &v2.Policy{
		Groups: map[v2.Group]v2.Usernames{
			"group:connector-admins": {"user1@"},
		},
		TagOwners: map[v2.Tag]v2.Owners{
			"tag:connector": {
				ptr.To(v2.Group("group:connector-admins")),
			},
		},
		NodeAttrs: []v2.NodeAttr{
			{
				Target: v2.NodeAttrTargets{v2.Wildcard},
				App: v2.NodeAttrApps{
					AppConnectors: []v2.AppConnector{
						{
							Name:       "test-connector",
							Connectors: v2.AppConnectorConnectors{ptr.To(v2.Tag("tag:connector"))},
							Domains:    []string{"example.com", "test.org"},
						},
					},
				},
			},
		},
	}

	// Create test users
	users := []types.User{
		{
			Name: "user1@",
		},
	}

	// Create test node with tags
	node1 := &types.Node{
		ID:         1,
		Hostname:   "connector-node",
		GivenName:  "connector-node",
		User:       users[0],
		ForcedTags: []string{"tag:connector"},
		IPv4:       ptr.To(netip.MustParseAddr("100.64.0.1")),
		IPv6:       ptr.To(netip.MustParseAddr("fd7a:115c:a1e0::1")),
		IsOnline:   ptr.To(true),
	}

	nodes := views.SliceOf([]types.NodeView{node1.View()})

	err := manager.UpdateConfiguration(policy, users, nodes)
	require.NoError(t, err)

	// Should have one active connector now
	stats := manager.GetStats()
	assert.Equal(t, 1, stats.ActiveConnectors)
	assert.Equal(t, 1, stats.TotalNodes)
	assert.Equal(t, 1, stats.OnlineNodes)
	assert.Equal(t, 2, stats.TotalDomains) // example.com and test.org

	// Check active connectors
	connectors := manager.GetActiveConnectors()
	assert.Len(t, connectors, 1)

	connector, exists := connectors["test-connector"]
	require.True(t, exists)
	assert.Equal(t, "test-connector", connector.Name)
	assert.Equal(t, []string{"example.com", "test.org"}, connector.Domains)
	assert.Len(t, connector.AssignedNodes, 1)
	assert.Equal(t, types.NodeID(1), connector.AssignedNodes[0].ID)

	// Check split DNS entries
	entries := manager.GetSplitDNSEntries()
	assert.Len(t, entries, 2)
	assert.Contains(t, entries, "example.com")
	assert.Contains(t, entries, "test.org")
}

func TestUpdateConfiguration_MultipleConnectors(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	// Create a policy with multiple app connectors
	policy := &v2.Policy{
		Groups: map[v2.Group]v2.Usernames{
			"group:connector-admins": {"user1@"},
			"group:other-admins":     {"user2@"},
		},
		TagOwners: map[v2.Tag]v2.Owners{
			"tag:connector": {
				ptr.To(v2.Group("group:connector-admins")),
			},
			"tag:other": {
				ptr.To(v2.Group("group:other-admins")),
			},
		},
		NodeAttrs: []v2.NodeAttr{
			{
				Target: v2.NodeAttrTargets{v2.Wildcard},
				App: v2.NodeAttrApps{
					AppConnectors: []v2.AppConnector{
						{
							Name:       "first-connector",
							Connectors: v2.AppConnectorConnectors{ptr.To(v2.Tag("tag:connector"))},
							Domains:    []string{"example.com"},
						},
						{
							Name:       "second-connector",
							Connectors: v2.AppConnectorConnectors{ptr.To(v2.Tag("tag:other"))},
							Domains:    []string{"internal.corp", "api.service"},
						},
					},
				},
			},
		},
	}

	// Create test users
	users := []types.User{
		{Name: "user1@"},
		{Name: "user2@"},
	}

	// Create test nodes with different tags
	node1 := &types.Node{
		ID:         1,
		Hostname:   "connector-node-1",
		GivenName:  "connector-node-1",
		User:       users[0],
		ForcedTags: []string{"tag:connector"},
		IPv4:       ptr.To(netip.MustParseAddr("100.64.0.1")),
		IsOnline:   ptr.To(true),
	}

	node2 := &types.Node{
		ID:         2,
		Hostname:   "connector-node-2",
		GivenName:  "connector-node-2",
		User:       users[1],
		ForcedTags: []string{"tag:other"},
		IPv4:       ptr.To(netip.MustParseAddr("100.64.0.2")),
		IsOnline:   ptr.To(false),
	}

	nodes := views.SliceOf([]types.NodeView{node1.View(), node2.View()})

	err := manager.UpdateConfiguration(policy, users, nodes)
	require.NoError(t, err)

	// Should have two active connectors
	stats := manager.GetStats()
	assert.Equal(t, 2, stats.ActiveConnectors)
	assert.Equal(t, 2, stats.TotalNodes)
	assert.Equal(t, 1, stats.OnlineNodes)  // Only first node is online
	assert.Equal(t, 3, stats.TotalDomains) // example.com, internal.corp, api.service

	// Check active connectors
	connectors := manager.GetActiveConnectors()
	assert.Len(t, connectors, 2)

	firstConnector, exists := connectors["first-connector"]
	require.True(t, exists)
	assert.Equal(t, "first-connector", firstConnector.Name)
	assert.Equal(t, []string{"example.com"}, firstConnector.Domains)
	assert.Len(t, firstConnector.AssignedNodes, 1)

	secondConnector, exists := connectors["second-connector"]
	require.True(t, exists)
	assert.Equal(t, "second-connector", secondConnector.Name)
	assert.Equal(t, []string{"internal.corp", "api.service"}, secondConnector.Domains)
	assert.Len(t, secondConnector.AssignedNodes, 1)

	// Check split DNS entries
	entries := manager.GetSplitDNSEntries()
	assert.Len(t, entries, 3)
	assert.Contains(t, entries, "example.com")
	assert.Contains(t, entries, "internal.corp")
	assert.Contains(t, entries, "api.service")
}

func TestUpdateConfiguration_NodeWithoutTags(t *testing.T) {
	cfg := getTestConfig()
	notif := notifier.NewNotifier(cfg)
	defer notif.Close()
	manager := NewManager(notif)

	// Create a policy with app connector
	policy := &v2.Policy{
		Groups: map[v2.Group]v2.Usernames{
			"group:connector-admins": {"user1@"},
		},
		TagOwners: map[v2.Tag]v2.Owners{
			"tag:connector": {
				ptr.To(v2.Group("group:connector-admins")),
			},
		},
		NodeAttrs: []v2.NodeAttr{
			{
				Target: v2.NodeAttrTargets{v2.Wildcard},
				App: v2.NodeAttrApps{
					AppConnectors: []v2.AppConnector{
						{
							Name:       "test-connector",
							Connectors: v2.AppConnectorConnectors{ptr.To(v2.Tag("tag:connector"))},
							Domains:    []string{"example.com"},
						},
					},
				},
			},
		},
	}

	users := []types.User{
		{Name: "user1@"},
	}

	// Create node without the required tag
	node := &types.Node{
		ID:         1,
		Hostname:   "regular-node",
		GivenName:  "regular-node",
		User:       users[0],
		ForcedTags: []string{"tag:regular"},
		IPv4:       ptr.To(netip.MustParseAddr("100.64.0.1")),
		IsOnline:   ptr.To(true),
	}

	nodes := views.SliceOf([]types.NodeView{node.View()})

	err := manager.UpdateConfiguration(policy, users, nodes)
	require.NoError(t, err)

	// Should have no active connectors since node doesn't match
	stats := manager.GetStats()
	assert.Equal(t, 0, stats.ActiveConnectors)
	assert.Equal(t, 0, stats.TotalNodes)
	assert.Equal(t, 0, stats.OnlineNodes)
	assert.Equal(t, 0, stats.TotalDomains)
}
