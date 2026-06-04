package forwarder

import (
	"net"
	"testing"

	"github.com/orris-inc/orris/internal/application/forward/testutil"
)

func TestManagerStartBindsTCPToListenIP(t *testing.T) {
	manager := NewManager(nil, testutil.NewMockLogger())

	if err := manager.Start(1, "127.0.0.1", 0, "127.0.0.1", 1, "tcp", nil); err != nil {
		t.Fatalf("failed to start forwarding rule: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.Stop(1)
	})

	rule := manager.rules[1]
	if rule == nil || rule.tcpListener == nil {
		t.Fatal("expected TCP listener to be created")
	}
	host, _, err := net.SplitHostPort(rule.tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener address: %v", err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("listener host = %q, want 127.0.0.1", host)
	}
}
