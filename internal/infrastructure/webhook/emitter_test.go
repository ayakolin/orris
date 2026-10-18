package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/domain/node"
	vo "github.com/orris-inc/orris/internal/domain/node/valueobjects"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/logger"
)

func newTestEmitter(t *testing.T, handler http.HandlerFunc) (*Emitter, *capture, func()) {
	t.Helper()
	capture := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.add(r)
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	notifier := testNotifier(srv.URL, srv.Client())
	state := NewStateStore(nil, logger.NewLogger())
	cfg := config.WebhookConfig{URL: srv.URL, Secret: "s3cr3t", TrafficThresholdPercent: 90}
	emitter := NewEmitter(notifier, state, nil, cfg, logger.NewLogger())
	return emitter, capture, func() {
		notifier.Close()
		srv.Close()
	}
}

func decodeEvents(t *testing.T, reqs []capturedRequest) []Event {
	t.Helper()
	events := make([]Event, 0, len(reqs))
	for _, req := range reqs {
		var ev Event
		if err := json.Unmarshal(req.body, &ev); err != nil {
			t.Fatalf("invalid body %q: %v", req.body, err)
		}
		events = append(events, ev)
	}
	return events
}

func testAgent(t *testing.T) *forward.ForwardAgent {
	t.Helper()
	agent, err := forward.NewForwardAgent(
		"edge-hk", "203.0.113.7", "", "",
		func() (string, error) { return "fa_test", nil },
		func(string) (string, string) { return "token", "hash" },
	)
	if err != nil {
		t.Fatalf("NewForwardAgent: %v", err)
	}
	if err := agent.SetID(7); err != nil {
		t.Fatalf("SetID: %v", err)
	}
	seen := time.Date(2026, 10, 19, 7, 30, 0, 0, time.UTC)
	agent.UpdateLastSeen(seen)
	return agent
}

func TestEmitterAgentEmitsOncePerEdge(t *testing.T) {
	emitter, capture, cleanup := newTestEmitter(t, nil)
	defer cleanup()

	agent := testAgent(t)
	ctx := context.Background()

	emitter.Agent(ctx, agent, EventAgentOffline, "websocket_closed")
	emitter.Agent(ctx, agent, EventAgentOffline, "heartbeat_timeout")

	events := decodeEvents(t, capture.waitFor(t, 1))
	time.Sleep(60 * time.Millisecond)
	if got := capture.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (second offline must be deduped)", got)
	}

	ev := events[0]
	if ev.Event != EventAgentOffline || ev.Type != TypeOffline {
		t.Fatalf("event/type = %q/%q", ev.Event, ev.Type)
	}
	if ev.Entity != "agent:edge-hk" {
		t.Fatalf("entity = %q, want agent:edge-hk", ev.Entity)
	}
	if ev.Detail["sid"] != "fa_test" || ev.Detail["id"] != float64(7) {
		t.Fatalf("detail = %+v", ev.Detail)
	}
	if ev.Detail["last_seen_at"] != "2026-10-19T07:30:00Z" {
		t.Fatalf("last_seen_at = %v, want RFC3339 UTC", ev.Detail["last_seen_at"])
	}
	if ev.Detail["public_ipv4"] != "203.0.113.7" {
		t.Fatalf("public_ipv4 = %v", ev.Detail["public_ipv4"])
	}
	if ev.Detail["reason"] != "websocket_closed" {
		t.Fatalf("reason = %v", ev.Detail["reason"])
	}

	emitter.Agent(ctx, agent, EventAgentOnline, "websocket_connected")
	events = decodeEvents(t, capture.waitFor(t, 2))
	if events[1].Event != EventAgentOnline || events[1].Type != TypeOnline {
		t.Fatalf("second event = %q/%q", events[1].Event, events[1].Type)
	}
}

func TestEmitterRuleFailedAndRecovered(t *testing.T) {
	emitter, capture, cleanup := newTestEmitter(t, nil)
	defer cleanup()

	ctx := context.Background()
	observe := func(sync, run string) {
		emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 3, sync, run, "")
	}

	// Transitional states must not emit and must not disturb dedupe.
	observe("pending", "starting")
	observe("pending", "running")
	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 0 {
		t.Fatalf("requests = %d, want 0 for transitional states", got)
	}

	observe("synced", "error")
	events := decodeEvents(t, capture.waitFor(t, 1))
	if events[0].Event != EventRuleFailed || events[0].Type != TypeOffline {
		t.Fatalf("event/type = %q/%q, want rule.failed/offline", events[0].Event, events[0].Type)
	}
	if events[0].Entity != "rule:hk->jp" {
		t.Fatalf("entity = %q", events[0].Entity)
	}
	if events[0].Detail["rule_id"] != "fr_abc" || events[0].Detail["agent_id"] != float64(3) {
		t.Fatalf("detail = %+v", events[0].Detail)
	}

	// Repeated failure and a stopped state are the same edge.
	observe("synced", "error")
	observe("synced", "stopped")
	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 while failing", got)
	}

	observe("synced", "running")
	events = decodeEvents(t, capture.waitFor(t, 2))
	if events[1].Event != EventRuleRecovered || events[1].Type != TypeOnline {
		t.Fatalf("event/type = %q/%q, want rule.recovered/online", events[1].Event, events[1].Type)
	}
}

func TestEmitterRuleFailureAggregatesAcrossAgents(t *testing.T) {
	emitter, capture, cleanup := newTestEmitter(t, nil)
	defer cleanup()
	ctx := context.Background()

	// Agent 3 fails; agents 4 and 5 stay healthy on every cycle.
	for cycle := 0; cycle < 3; cycle++ {
		emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 3, "failed", "error", "bind failed")
		emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 4, "synced", "running", "")
		emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 5, "synced", "running", "")
	}
	events := decodeEvents(t, capture.waitFor(t, 1))
	time.Sleep(80 * time.Millisecond)
	if got := capture.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (healthy peers must not emit rule.recovered)", got)
	}
	if events[0].Event != EventRuleFailed {
		t.Fatalf("event = %q", events[0].Event)
	}

	// Agent 3 recovers while peers were always healthy: exactly one recovery.
	emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 3, "synced", "running", "")
	emitter.ObserveRuleStatus(ctx, "fr_abc", "hk->jp", 3, "synced", "running", "")
	decodeEvents(t, capture.waitFor(t, 2))
	time.Sleep(80 * time.Millisecond)
	if got := capture.count(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestEmitterForgetRuleStatusAllowsLaterFailure(t *testing.T) {
	emitter, capture, cleanup := newTestEmitter(t, nil)
	defer cleanup()
	ctx := context.Background()

	emitter.ObserveRuleStatus(ctx, "fr_gone", "gone", 3, "failed", "error", "")
	decodeEvents(t, capture.waitFor(t, 1))

	// The rule is disabled while failing; the report path forgets the member.
	emitter.ForgetRuleStatus(ctx, "fr_gone", 3)

	emitter.ObserveRuleStatus(ctx, "fr_gone", "gone", 3, "failed", "error", "")
	decodeEvents(t, capture.waitFor(t, 2))
	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 2 {
		t.Fatalf("requests = %d, want 2 (a new failure after forgetting must emit)", got)
	}
}

func TestEmitterTrafficThreshold(t *testing.T) {
	emitter, capture, cleanup := newTestEmitter(t, nil)
	defer cleanup()

	n := testNode(t)
	emitter.nodes = staticNodeResolver{n}

	ctx := context.Background()
	emitter.ObserveTrafficThreshold(ctx, n.ID(), 42, 920, 1000)
	events := decodeEvents(t, capture.waitFor(t, 1))
	ev := events[0]
	if ev.Event != EventTrafficThreshold || ev.Type != TypeAlert {
		t.Fatalf("event/type = %q/%q", ev.Event, ev.Type)
	}
	if ev.Entity != "node:node-hk" {
		t.Fatalf("entity = %q", ev.Entity)
	}
	if ev.Detail["percent"] != float64(92) {
		t.Fatalf("percent = %v", ev.Detail["percent"])
	}
	if ev.Detail["used_bytes"] != float64(920) || ev.Detail["limit_bytes"] != float64(1000) {
		t.Fatalf("detail = %+v", ev.Detail)
	}

	// Still above threshold: deduped.
	emitter.ObserveTrafficThreshold(ctx, n.ID(), 42, 970, 1000)
	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 while over threshold", got)
	}

	// Drop below: re-arm without an event.
	emitter.ObserveTrafficThreshold(ctx, n.ID(), 42, 100, 1000)
	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (re-arm must be silent)", got)
	}

	// Cross again: new event.
	emitter.ObserveTrafficThreshold(ctx, n.ID(), 42, 910, 1000)
	capture.waitFor(t, 2)
}

func TestEmitterTrafficDisabledThresholdAndUnlimited(t *testing.T) {
	emitter, capture, cleanup := newTestEmitter(t, nil)
	defer cleanup()
	emitter.thresholdPct = 0
	emitter.ObserveTrafficThreshold(context.Background(), 1, 2, 1000, 1000)

	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 0 {
		t.Fatalf("requests = %d, want 0 when threshold is disabled", got)
	}
}

func TestEmitterDisabledIsNoOp(t *testing.T) {
	emitter := NewEmitter(NewNotifier(config.WebhookConfig{}, logger.NewLogger()),
		NewStateStore(nil, logger.NewLogger()), nil, config.WebhookConfig{}, logger.NewLogger())
	ctx := context.Background()
	emitter.Agent(ctx, testAgent(t), EventAgentOffline, "websocket_closed")
	emitter.ObserveRuleStatus(ctx, "fr_abc", "r", 1, "failed", "error", "")
	emitter.ObserveTrafficThreshold(ctx, 1, 2, 100, 100)

	var nilEmitter *Emitter
	nilEmitter.Agent(ctx, nil, EventAgentOnline, "")
	nilEmitter.ObserveRuleStatus(ctx, "", "", 0, "", "", "")
}

type staticNodeResolver []*node.Node

func (s staticNodeResolver) GetByID(_ context.Context, id uint) (*node.Node, error) {
	for _, n := range s {
		if n.ID() == id {
			return n, nil
		}
	}
	return nil, nil
}

func testNode(t *testing.T) *node.Node {
	t.Helper()
	addr, err := vo.NewServerAddress("198.51.100.9")
	if err != nil {
		t.Fatalf("NewServerAddress: %v", err)
	}
	enc, err := vo.NewEncryptionConfig(vo.MethodAES256GCM)
	if err != nil {
		t.Fatalf("NewEncryptionConfig: %v", err)
	}
	seen := time.Date(2026, 10, 19, 7, 30, 0, 0, time.UTC)
	ipv4 := "198.51.100.9"
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)

	n, err := node.ReconstructNode(
		11, "node_hk", "node-hk",
		addr, 8443, nil, vo.ProtocolShadowsocks, enc,
		nil, nil, nil, nil, nil, nil, nil,
		vo.NodeStatusActive, vo.NewNodeMetadata("hk", nil, ""),
		nil, nil, "hash", "", 0, false, nil, nil, nil,
		&seen, &ipv4, nil, nil, nil, nil, nil, nil, 1, now, now,
	)
	if err != nil {
		t.Fatalf("ReconstructNode: %v", err)
	}
	return n
}
