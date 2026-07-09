package services

import (
	"testing"

	dto "github.com/orris-inc/orris/internal/shared/hubprotocol/forward"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// A stale read-loop teardown for a superseded connection must not evict the
// live connection that replaced it during a reconnect.
func TestUnregisterAgent_IgnoresSupersededConnection(t *testing.T) {
	h := NewAgentHub(logger.NewLogger(), nil)
	defer h.Shutdown()

	old := &AgentHubConn{AgentID: 1, Send: make(chan *dto.HubMessage, 1)}
	current := &AgentHubConn{AgentID: 1, Send: make(chan *dto.HubMessage, 1)}

	// Simulate a completed reconnect: `current` is the live registered connection.
	h.agentsMu.Lock()
	h.agents[1] = current
	h.agentsMu.Unlock()

	// The old connection's read loop tears down and tries to unregister itself.
	h.UnregisterAgent(1, old)
	if !h.IsAgentOnline(1) {
		t.Fatal("stale unregister evicted the live reconnected agent")
	}

	// The live connection's own teardown removes it.
	h.UnregisterAgent(1, current)
	if h.IsAgentOnline(1) {
		t.Fatal("expected agent offline after unregistering the current connection")
	}
}

// Same guard for node agent connections.
func TestUnregisterNodeAgent_IgnoresSupersededConnection(t *testing.T) {
	h := NewAgentHub(logger.NewLogger(), nil)
	defer h.Shutdown()

	old := &NodeHubConn{NodeID: 1, Send: make(chan []byte, 1)}
	current := &NodeHubConn{NodeID: 1, Send: make(chan []byte, 1)}

	h.nodesMu.Lock()
	h.nodes[1] = current
	h.nodesMu.Unlock()

	h.UnregisterNodeAgent(1, old)
	if !h.IsNodeOnline(1) {
		t.Fatal("stale unregister evicted the live reconnected node agent")
	}

	h.UnregisterNodeAgent(1, current)
	if h.IsNodeOnline(1) {
		t.Fatal("expected node offline after unregistering the current connection")
	}
}
