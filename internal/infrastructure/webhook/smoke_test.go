package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/orris-inc/orris/internal/domain/shared"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// TestSmokeReceiverContract proves the emitted wire format verifies with an
// independent implementation of the receiver's contract: headers, HMAC over
// "<timestamp>.<raw body>", 300s skew window, 202 response, and body schema.
func TestSmokeReceiverContract(t *testing.T) {
	const secret = "shared-secret"

	var mu sync.Mutex
	var received []Event

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tsRaw := r.Header.Get("X-NodeWatch-Timestamp")
		ts, err := strconv.ParseInt(tsRaw, 10, 64)
		if err != nil {
			http.Error(w, "bad timestamp", http.StatusUnauthorized)
			return
		}
		if skew := time.Since(time.Unix(ts, 0)); skew > 300*time.Second || skew < -300*time.Second {
			http.Error(w, "stale", http.StatusUnauthorized)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(tsRaw + "."))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-NodeWatch-Signature"))) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}

		var ev Event
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if ev.Source != SourceOrris || ev.Event == "" || ev.Entity == "" || ev.TS == 0 {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-NodeWatch-Event") != ev.Event {
			http.Error(w, "event header mismatch", http.StatusBadRequest)
			return
		}

		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	cfg := config.WebhookConfig{URL: srv.URL + "/event?token=secret-in-query", Secret: secret, TrafficThresholdPercent: 90}
	notifier := NewNotifier(cfg, logger.NewLogger())
	defer notifier.Close()

	emitter := NewEmitter(notifier, NewStateStore(nil, logger.NewLogger()), nil, cfg, logger.NewLogger())
	ctx := context.Background()

	agent := testAgent(t)
	emitter.Agent(ctx, agent, EventAgentOffline, "websocket_closed")
	emitter.Agent(ctx, agent, EventAgentOffline, "heartbeat_timeout")
	emitter.Agent(ctx, agent, EventAgentOnline, "websocket_connected")
	emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 3, "synced", "error", "connection refused")
	emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 3, "synced", "running", "")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	got := append([]Event(nil), received...)
	mu.Unlock()

	if len(got) != 4 {
		t.Fatalf("receiver accepted %d events, want 4: %+v", len(got), got)
	}
	want := []struct{ event, typ, entity string }{
		{EventAgentOffline, TypeOffline, "agent:edge-hk"},
		{EventAgentOnline, TypeOnline, "agent:edge-hk"},
		{EventRuleFailed, TypeOffline, "rule:hk->jp"},
		{EventRuleRecovered, TypeOnline, "rule:hk->jp"},
	}
	for i, w := range want {
		if got[i].Event != w.event || got[i].Type != w.typ || got[i].Entity != w.entity {
			t.Errorf("event[%d] = %s/%s/%s, want %s/%s/%s",
				i, got[i].Event, got[i].Type, got[i].Entity, w.event, w.typ, w.entity)
		}
	}

	// The stale-sample guard: a socket closing while last_seen is still fresh
	// must not be reported as recovered by the next watcher pass.
	state := NewStateStore(nil, logger.NewLogger())
	state.Transition(ctx, EntityKey("agent", 99), "offline")
	snap, _ := state.snapshotOne(ctx, stateKeyPrefix+EntityKey("agent", 99))
	if age := time.Since(snap.Since); age < 0 || age > time.Second {
		t.Fatalf("snapshot Since = %v (age %v), want ~now", snap.Since, age)
	}
	if !shared.IsOnline(&snap.Since) {
		t.Fatal("fresh sample should be online")
	}
}
