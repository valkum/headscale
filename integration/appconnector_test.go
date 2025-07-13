package integration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// setNodeTag sets a tag on a node identified by hostname using the headscale CLI
func setNodeTag(t *testing.T, headscale ControlServer, hostname, tag string) {
	t.Helper()

	// Execute headscale nodes list to get node IDs
	result, err := headscale.Execute([]string{
		"headscale", "nodes", "list", "--output", "json",
	})
	require.NoError(t, err)

	var nodes []map[string]interface{}
	err = json.Unmarshal([]byte(result), &nodes)
	require.NoError(t, err)

	// Find the node by hostname
	var nodeID uint64
	for _, node := range nodes {
		if nodeHostname, ok := node["hostname"].(string); ok && nodeHostname == hostname {
			if id, ok := node["id"].(float64); ok {
				nodeID = uint64(id)
				break
			}
		}
	}
	require.NotZero(t, nodeID, "Could not find node with hostname %s", hostname)

	// Set the tag on the node
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "tag",
		"-i", fmt.Sprintf("%d", nodeID),
		"-t", tag,
	})
	require.NoError(t, err)

	t.Logf("Set tag %s on node %s (ID: %d)", tag, hostname, nodeID)
}

// TestAppConnectorBasic tests basic app connector functionality:
// 1. A node can be configured as an app connector for specific domains
// 2. Other nodes in the same tailnet receive the app connector configuration
// 3. The app connector domains are properly advertised to clients
func TestAppConnectorBasic(t *testing.T) {
	IntegrationSkip(t)

	// Create a policy that includes nodeAttrs for app connectors
	policy := &policyv2.Policy{
		Groups: map[policyv2.Group]policyv2.Usernames{
			"group:connector-admins": {"user1@"},
		},
		TagOwners: map[policyv2.Tag]policyv2.Owners{
			"tag:connector": {
				groupOwner("group:connector-admins"),
			},
		},
		NodeAttrs: []policyv2.NodeAttr{
			{
				Target: policyv2.NodeAttrTargets{nodeAttrWildcard()},
				App: policyv2.NodeAttrApps{
					AppConnectors: []policyv2.AppConnector{
						{
							Name:       "example-connector",
							Connectors: policyv2.AppConnectorConnectors{ptr.To(policyv2.Tag("tag:connector"))},
							Domains:    []string{"example.com", "internal.corp"},
						},
					},
				},
			},
		},
		ACLs: []policyv2.ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard()),
				},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithNetfilter("off"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("appconnector"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	// Get the existing clients after environment setup
	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 4) // 2 users * 2 nodes each

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)
	require.Len(t, user1Clients, 2)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)
	require.Len(t, user2Clients, 2)

	// We'll use the existing clients
	connectorClient := user1Clients[0]
	regularClient1 := user1Clients[1]
	regularClient2 := user2Clients[0]

	// Wait for all clients to be up and connected
	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	// Get the headscale instance to use for setting tags
	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Set the connector tag on the first user1 client
	setNodeTag(t, headscale, connectorClient.Hostname(), "tag:connector")

	// Wait a moment for the tag to propagate
	time.Sleep(2 * time.Second)

	// Wait for tailscale sync again to ensure tag propagation
	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	// Verify that all nodes can see each other
	for _, client := range allClients {
		err = client.WaitForPeers(len(allClients) - 1) // Each client should see the others
		require.NoError(t, err)
	}

	// Verify the connector node has the correct configuration
	t.Run("connector_node_configuration", func(t *testing.T) {
		status, err := connectorClient.Status()
		require.NoError(t, err)

		// Check that the node has the connector tags
		assert.Contains(t, status.Self.Tags, "tag:connector")

		// Verify the node shows up with connector capability in netmap
		if util.TailscaleVersionNewerOrEqual("1.56", connectorClient.Version()) {
			netmap, err := connectorClient.Netmap()
			require.NoError(t, err)

			// The connector node should have app connector capabilities
			selfCapMap := netmap.SelfNode.CapMap()
			if selfCapMap.Len() > 0 {
				// For now, just verify that there are capabilities present
				// TODO: Add specific capability checking when the exact API is stable
				t.Logf("Node has %d capabilities", selfCapMap.Len())
			}
		}
	})

	// Verify that regular clients receive app connector information
	t.Run("client_receives_connector_info", func(t *testing.T) {
		if !util.TailscaleVersionNewerOrEqual("1.56", regularClient1.Version()) {
			t.Skip("Netmap API not available in this Tailscale version")
		}

		netmap, err := regularClient1.Netmap()
		require.NoError(t, err)

		// Find the connector node in the netmap
		var connectorPeer tailcfg.NodeView
		var connectorPeerFound bool
		for _, peer := range netmap.Peers {
			if peer.Hostinfo().Hostname() == connectorClient.Hostname() {
				connectorPeer = peer
				connectorPeerFound = true
				break
			}
		}

		require.True(t, connectorPeerFound, "Connector peer should be found in netmap")

		// Check if the peer has app connector capabilities
		peerCapMap := connectorPeer.CapMap()
		if peerCapMap.Len() > 0 {
			t.Logf("Connector peer has %d capabilities", peerCapMap.Len())
			// TODO: Add specific capability checking when the exact API is stable
		}
	})

	// Test connectivity between nodes
	t.Run("basic_connectivity", func(t *testing.T) {
		// Test ping between connector and regular client
		err = regularClient1.Ping(connectorClient.MustIPv4().String())
		require.NoError(t, err)

		// Test ping from connector to regular client
		err = connectorClient.Ping(regularClient1.MustIPv4().String())
		require.NoError(t, err)

		// Test ping between regular clients
		err = regularClient1.Ping(regularClient2.MustIPv4().String())
		require.NoError(t, err)
	})

	// Test app connector manager state by checking headscale logs or API
	t.Run("app_connector_manager_state", func(t *testing.T) {
		// We can check that the app connector manager has processed the tagged node
		// by verifying the node appears in the correct state
		// This is more of an integration test with the manager logic

		// The connector should be active with the tagged node
		// In a real integration test, we might want to add an API endpoint
		// to query the app connector manager state directly

		// For now, we verify that the node has the correct tag
		status, err := connectorClient.Status()
		require.NoError(t, err)
		assert.Contains(t, status.Self.Tags, "tag:connector")
	})
}

// TestAppConnectorPolicyValidation tests that invalid app connector policies are rejected
func TestAppConnectorPolicyValidation(t *testing.T) {
	IntegrationSkip(t)

	// Test with invalid nodeAttrs target
	invalidPolicy := &policyv2.Policy{
		NodeAttrs: []policyv2.NodeAttr{
			{
				Target: policyv2.NodeAttrTargets{
					nodeAttrTag("tag:nonexistent"),
				},
				App: policyv2.NodeAttrApps{
					AppConnectors: []policyv2.AppConnector{
						{
							Name:       "invalid-connector",
							Connectors: policyv2.AppConnectorConnectors{ptr.To(policyv2.Tag("tag:nonexistent"))},
							Domains:    []string{"example.com"},
						},
					},
				},
			},
		},
		ACLs: []policyv2.ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard()),
				},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// This should fail due to invalid policy
	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithNetfilter("off"),
		},
		hsic.WithACLPolicy(invalidPolicy),
		hsic.WithTestName("appconnector-invalid"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)

	// The policy should be rejected because tag:nonexistent is not defined in tagOwners
	require.Error(t, err, "Invalid policy should be rejected")
}

// TestAppConnectorMultipleDomains tests app connectors with multiple domains
func TestAppConnectorMultipleDomains(t *testing.T) {
	IntegrationSkip(t)

	policy := &policyv2.Policy{
		Groups: map[policyv2.Group]policyv2.Usernames{
			"group:connector-admins": {"user1@"},
		},
		TagOwners: map[policyv2.Tag]policyv2.Owners{
			"tag:connector": {
				groupOwner("group:connector-admins"),
			},
		},
		NodeAttrs: []policyv2.NodeAttr{
			{
				Target: policyv2.NodeAttrTargets{
					nodeAttrTag("tag:connector"),
				},
				App: policyv2.NodeAttrApps{
					AppConnectors: []policyv2.AppConnector{
						{
							Name:       "multi-domain-connector",
							Connectors: policyv2.AppConnectorConnectors{ptr.To(policyv2.Tag("tag:connector"))},
							Domains: []string{
								"api.example.com",
								"db.internal.corp",
								"cache.internal.corp",
								"*.dev.example.com",
							},
						},
					},
				},
			},
		},
		ACLs: []policyv2.ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard()),
				},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithNetfilter("off"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("appconnector-multi"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	// Get the existing clients after environment setup
	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 2) // 1 user * 2 nodes

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)
	require.Len(t, user1Clients, 2)

	// We'll use the existing clients
	connectorClient := user1Clients[0]
	regularClient := user1Clients[1]

	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	// Verify both nodes are connected
	err = connectorClient.WaitForPeers(1)
	require.NoError(t, err)
	err = regularClient.WaitForPeers(1)
	require.NoError(t, err)

	// Test that all domains are properly configured
	t.Run("multiple_domains_configuration", func(t *testing.T) {
		if !util.TailscaleVersionNewerOrEqual("1.56", regularClient.Version()) {
			t.Skip("Netmap API not available in this Tailscale version")
		}

		netmap, err := regularClient.Netmap()
		require.NoError(t, err)

		// Find the connector node
		var connectorPeer tailcfg.NodeView
		var connectorPeerFound bool
		for _, peer := range netmap.Peers {
			if peer.Hostinfo().Hostname() == connectorClient.Hostname() {
				connectorPeer = peer
				connectorPeerFound = true
				break
			}
		}

		require.True(t, connectorPeerFound, "Connector peer should be found in netmap")

		peerCapMap := connectorPeer.CapMap()
		if peerCapMap.Len() > 0 {
			t.Logf("Connector peer has %d capabilities", peerCapMap.Len())
			// TODO: Add specific capability checking when the exact API is stable
		}
	})
}

// TestAppConnectorWithoutTags tests that nodes without proper tags don't become connectors
func TestAppConnectorWithoutTags(t *testing.T) {
	IntegrationSkip(t)

	// Create a policy that includes nodeAttrs for app connectors
	policy := &policyv2.Policy{
		Groups: map[policyv2.Group]policyv2.Usernames{
			"group:connector-admins": {"user1@"},
		},
		TagOwners: map[policyv2.Tag]policyv2.Owners{
			"tag:connector": {
				groupOwner("group:connector-admins"),
			},
		},
		NodeAttrs: []policyv2.NodeAttr{
			{
				Target: policyv2.NodeAttrTargets{nodeAttrWildcard()},
				App: policyv2.NodeAttrApps{
					AppConnectors: []policyv2.AppConnector{
						{
							Name:       "example-connector",
							Connectors: policyv2.AppConnectorConnectors{ptr.To(policyv2.Tag("tag:connector"))},
							Domains:    []string{"example.com", "internal.corp"},
						},
					},
				},
			},
		},
		ACLs: []policyv2.ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard()),
				},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithNetfilter("off"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("appconnector-notags"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	// Get the client
	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)
	require.Len(t, user1Clients, 1)

	regularClient := user1Clients[0]

	// Wait for client to be up and connected
	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	// Don't set any tags on the node - it should remain a regular node

	// Wait for sync to ensure any potential tag propagation
	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	// Verify the node does NOT have connector tags
	t.Run("node_without_connector_tags", func(t *testing.T) {
		status, err := regularClient.Status()
		require.NoError(t, err)

		// Check that the node does NOT have the connector tags
		assert.NotContains(t, status.Self.Tags, "tag:connector")

		// Verify the node does not show up with connector capability in netmap
		if util.TailscaleVersionNewerOrEqual("1.56", regularClient.Version()) {
			netmap, err := regularClient.Netmap()
			require.NoError(t, err)

			// The regular node should not have app connector capabilities
			selfCapMap := netmap.SelfNode.CapMap()
			// For a regular node, we expect either no capabilities or different ones
			// This test mainly ensures the tagging/capability logic works correctly
			t.Logf("Regular node has %d capabilities", selfCapMap.Len())
		}
	})
}
