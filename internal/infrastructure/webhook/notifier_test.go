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

	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/logger"
)

type capture struct {
	mu       sync.Mutex
	requests []capturedRequest
}

type capturedRequest struct {
	header http.Header
	body   []byte
}

func (c *capture) add(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, capturedRequest{header: r.Header.Clone(), body: body})
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *capture) waitFor(t *testing.T, n int) []capturedRequest {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.count() >= n {
			c.mu.Lock()
			defer c.mu.Unlock()
			return append([]capturedRequest(nil), c.requests...)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d requests, got %d", n, c.count())
	return nil
}

func testNotifier(url string, client *http.Client) *Notifier {
	return newNotifier(
		config.WebhookConfig{URL: url, Secret: "s3cr3t", TrafficThresholdPercent: 90},
		logger.NewLogger(),
		client,
		[]time.Duration{10 * time.Millisecond, 10 * time.Millisecond},
		nil,
	)
}

func TestNotifierSignsHeadersAndBody(t *testing.T) {
	capture := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.add(r)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	n := testNotifier(srv.URL, srv.Client())
	defer n.Close()

	n.Emit(context.Background(), Event{
		Event:  EventAgentOffline,
		Entity: Entity("agent", "edge-1"),
		Detail: map[string]any{"id": 7, "name": "edge-1"},
	})

	reqs := capture.waitFor(t, 1)
	got := reqs[0]

	if ct := got.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if ev := got.header.Get("X-NodeWatch-Event"); ev != EventAgentOffline {
		t.Fatalf("X-NodeWatch-Event = %q, want %q", ev, EventAgentOffline)
	}
	ts, err := strconv.ParseInt(got.header.Get("X-NodeWatch-Timestamp"), 10, 64)
	if err != nil {
		t.Fatalf("invalid timestamp header: %v", err)
	}

	mac := hmac.New(sha256.New, []byte("s3cr3t"))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(got.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig := got.header.Get("X-NodeWatch-Signature"); sig != want {
		t.Fatalf("signature = %q, want %q", sig, want)
	}

	var body Event
	if err := json.Unmarshal(got.body, &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Source != SourceOrris {
		t.Errorf("source = %q, want %q", body.Source, SourceOrris)
	}
	if body.Event != EventAgentOffline || body.Type != TypeOffline {
		t.Errorf("event/type = %q/%q, want %q/%q", body.Event, body.Type, EventAgentOffline, TypeOffline)
	}
	if body.Entity != "agent:edge-1" {
		t.Errorf("entity = %q, want agent:edge-1", body.Entity)
	}
	if body.TS != ts {
		t.Errorf("body ts = %d, header ts = %d", body.TS, ts)
	}
	if body.Detail["id"] != float64(7) {
		t.Errorf("detail id = %v, want 7", body.Detail["id"])
	}
}

func TestNotifierRetriesOn5xxAndSucceeds(t *testing.T) {
	capture := &capture{}
	var attempts int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		current := attempts
		mu.Unlock()
		capture.add(r)
		if current < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	n := testNotifier(srv.URL, srv.Client())
	defer n.Close()

	n.Emit(context.Background(), Event{Event: EventNodeOffline, Entity: Entity("node", "n1")})
	capture.waitFor(t, 3)

	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestNotifierRetriesOnNetworkError(t *testing.T) {
	var mu sync.Mutex
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		return nil, io.ErrUnexpectedEOF
	})}
	_ = url

	n := newNotifier(
		config.WebhookConfig{URL: "http://127.0.0.1:1/event", Secret: "s3cr3t"},
		logger.NewLogger(), client,
		[]time.Duration{5 * time.Millisecond, 5 * time.Millisecond}, nil,
	)
	defer n.Close()

	n.Emit(context.Background(), Event{Event: EventNodeOnline, Entity: Entity("node", "n1")})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := attempts == 3
		mu.Unlock()
		if done {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("attempts = %d, want 3", attempts)
}

func TestNotifierDoesNotRetryOn4xx(t *testing.T) {
	capture := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.add(r)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	n := testNotifier(srv.URL, srv.Client())
	defer n.Close()

	n.Emit(context.Background(), Event{Event: EventRuleFailed, Entity: Entity("rule", "r1")})
	capture.waitFor(t, 1)
	time.Sleep(80 * time.Millisecond)

	if got := capture.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (4xx must not be retried)", got)
	}
}

func TestNotifierDisabledIsNoOp(t *testing.T) {
	capture := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.add(r)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	for _, cfg := range []config.WebhookConfig{
		{URL: "", Secret: "s3cr3t"},
		{URL: srv.URL, Secret: ""},
		{},
	} {
		n := NewNotifier(cfg, logger.NewLogger())
		if n.Enabled() {
			t.Fatalf("notifier with config %+v should be disabled", cfg)
		}
		n.Emit(context.Background(), Event{Event: EventAgentOnline, Entity: Entity("agent", "a")})
		n.Close()
	}

	nilNotifier := (*Notifier)(nil)
	nilNotifier.Emit(context.Background(), Event{Event: EventAgentOnline})
	nilNotifier.Close()

	time.Sleep(50 * time.Millisecond)
	if got := capture.count(); got != 0 {
		t.Fatalf("requests = %d, want 0 when disabled", got)
	}
}

func TestTypeForEvent(t *testing.T) {
	cases := map[string]string{
		EventAgentOffline:     TypeOffline,
		EventNodeOffline:      TypeOffline,
		EventRuleFailed:       TypeOffline,
		EventAgentOnline:      TypeOnline,
		EventNodeOnline:       TypeOnline,
		EventRuleRecovered:    TypeOnline,
		EventTrafficThreshold: TypeAlert,
	}
	for event, want := range cases {
		if got := TypeForEvent(event); got != want {
			t.Errorf("TypeForEvent(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestStateStoreTransitions(t *testing.T) {
	store := NewStateStore(nil, logger.NewLogger())
	ctx := context.Background()
	key := EntityKey("node", 42)

	if !store.Transition(ctx, key, "online") {
		t.Fatal("first transition should win")
	}
	if store.Transition(ctx, key, "online") {
		t.Fatal("repeated transition must not win")
	}
	if !store.Transition(ctx, key, "offline") {
		t.Fatal("online -> offline should win")
	}
	if got := store.State(ctx, key); got != "offline" {
		t.Fatalf("state = %q, want offline", got)
	}
	snaps := store.Snapshot(ctx, "node:")
	if len(snaps) != 1 {
		t.Fatalf("Snapshot = %v, want one entry", snaps)
	}
	snap, ok := snaps[key]
	if !ok || snap.State != "offline" || snap.Since.IsZero() {
		t.Fatalf("Snapshot[%s] = %+v (ok=%v), want offline with Since", key, snap, ok)
	}
	if !store.Transition(ctx, key, "online") {
		t.Fatal("offline -> online should win")
	}
	if store.State(ctx, key) != "online" {
		t.Fatal("state should be online")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
