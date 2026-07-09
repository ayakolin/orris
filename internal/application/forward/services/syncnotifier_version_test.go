package services

import (
	"sync"
	"testing"
)

// UpdateAgentVersion must never regress: a stale/out-of-order ack for a lower
// version must not overwrite a higher recorded version.
func TestUpdateAgentVersion_NeverRegresses(t *testing.T) {
	n := &SyncNotifier{}

	n.UpdateAgentVersion(1, 5)
	n.UpdateAgentVersion(1, 3) // stale ack, must be ignored
	if got := n.GetAgentVersion(1); got != 5 {
		t.Fatalf("stale ack regressed version: want 5, got %d", got)
	}

	n.UpdateAgentVersion(1, 7) // newer ack, must advance
	if got := n.GetAgentVersion(1); got != 7 {
		t.Fatalf("newer ack did not advance version: want 7, got %d", got)
	}
}

// Concurrent acks must converge to the maximum version, never a lower one.
func TestUpdateAgentVersion_ConcurrentConvergesToMax(t *testing.T) {
	n := &SyncNotifier{}
	var wg sync.WaitGroup
	for v := uint64(1); v <= 100; v++ {
		wg.Add(1)
		go func(version uint64) {
			defer wg.Done()
			n.UpdateAgentVersion(1, version)
		}(v)
	}
	wg.Wait()

	if got := n.GetAgentVersion(1); got != 100 {
		t.Fatalf("concurrent acks did not converge to max: want 100, got %d", got)
	}
}
