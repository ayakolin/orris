// Package webhook emits signed node-watch events to an external receiver.
//
// The wire contract is shared with the xboard plugin:
//
//	POST <url>
//	X-NodeWatch-Timestamp: <unix seconds>
//	X-NodeWatch-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
//	X-NodeWatch-Event: <event>
//
// Delivery is asynchronous: callers enqueue and return. A single worker drains
// the bounded queue, retrying network errors and 5xx responses up to three
// times with 1s/4s backoff. Any other non-2xx status is not retried.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/goroutine"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// Event names defined by the shared contract.
const (
	EventAgentOffline     = "agent.offline"
	EventAgentOnline      = "agent.online"
	EventNodeOffline      = "node.offline"
	EventNodeOnline       = "node.online"
	EventRuleFailed       = "rule.failed"
	EventRuleRecovered    = "rule.recovered"
	EventTrafficThreshold = "traffic.threshold"
)

// Event types (lowercase, part of the JSON body).
const (
	TypeOffline = "offline"
	TypeOnline  = "online"
	TypeAlert   = "alert"
)

// SourceOrris identifies Orris as the event producer.
const SourceOrris = "orris"

const (
	defaultQueueSize = 256
	defaultTimeout   = 5 * time.Second
)

// Event is the JSON body sent to the receiver.
type Event struct {
	Source string         `json:"source"`
	Event  string         `json:"event"`
	Type   string         `json:"type"`
	Entity string         `json:"entity"`
	TS     int64          `json:"ts"`
	Detail map[string]any `json:"detail,omitempty"`
}

// TypeForEvent maps an event name to its contract type.
func TypeForEvent(event string) string {
	switch event {
	case EventAgentOffline, EventNodeOffline, EventRuleFailed:
		return TypeOffline
	case EventAgentOnline, EventNodeOnline, EventRuleRecovered:
		return TypeOnline
	default:
		return TypeAlert
	}
}

// Entity builds the "<kind>:<name>" entity string.
func Entity(kind, name string) string {
	return kind + ":" + name
}

// Notifier signs and delivers events. A nil or disabled Notifier is a no-op,
// so callers never need to guard emissions.
type Notifier struct {
	url    string
	host   string
	secret string
	logger logger.Interface

	client *http.Client
	queue  chan Event

	backoff []time.Duration
	sleep   func(context.Context, time.Duration) bool
	now     func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// NewNotifier creates a Notifier from config. When the webhook is disabled
// (empty URL or secret) no worker goroutine is started and Emit is a no-op.
func NewNotifier(cfg config.WebhookConfig, log logger.Interface) *Notifier {
	return newNotifier(cfg, log, nil, nil, nil)
}

func newNotifier(
	cfg config.WebhookConfig,
	log logger.Interface,
	client *http.Client,
	backoff []time.Duration,
	sleep func(context.Context, time.Duration) bool,
) *Notifier {
	if log == nil {
		log = logger.NewLogger()
	}
	n := &Notifier{
		url:     cfg.URL,
		host:    urlHost(cfg.URL),
		secret:  cfg.Secret,
		logger:  log,
		client:  client,
		backoff: backoff,
		sleep:   sleep,
		now:     time.Now,
	}
	if n.client == nil {
		n.client = &http.Client{Timeout: defaultTimeout}
	}
	if n.backoff == nil {
		n.backoff = []time.Duration{time.Second, 4 * time.Second}
	}
	if n.sleep == nil {
		n.sleep = sleepContext
	}
	if !cfg.IsEnabled() {
		return n
	}

	n.ctx, n.cancel = context.WithCancel(context.Background())
	n.queue = make(chan Event, defaultQueueSize)
	n.wg.Add(1)
	goroutine.SafeGo(log, "webhook-notifier", func() {
		defer n.wg.Done()
		n.run()
	})
	return n
}

// Enabled reports whether the notifier will deliver events.
func (n *Notifier) Enabled() bool {
	return n != nil && n.queue != nil
}

// Emit queues an event for asynchronous delivery. It never blocks the caller:
// when the queue is full the event is dropped and logged.
func (n *Notifier) Emit(_ context.Context, ev Event) {
	if !n.Enabled() {
		return
	}
	if ev.TS == 0 {
		ev.TS = n.now().Unix()
	}
	if ev.Source == "" {
		ev.Source = SourceOrris
	}
	if ev.Type == "" {
		ev.Type = TypeForEvent(ev.Event)
	}

	select {
	case n.queue <- ev:
	default:
		n.logger.Warnw("webhook event dropped: queue full",
			"event", ev.Event,
			"entity", ev.Entity,
		)
	}
}

// Close stops the worker and aborts in-flight retries. Pending events are
// discarded; delivery is best-effort by design.
func (n *Notifier) Close() {
	if n == nil {
		return
	}
	n.once.Do(func() {
		if n.cancel != nil {
			n.cancel()
		}
		n.wg.Wait()
	})
}

func (n *Notifier) run() {
	for {
		select {
		case <-n.ctx.Done():
			return
		case ev := <-n.queue:
			n.deliver(ev)
		}
	}
}

func (n *Notifier) deliver(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		n.logger.Errorw("failed to marshal webhook event",
			"event", ev.Event,
			"entity", ev.Entity,
			"error", err,
		)
		return
	}

	attempts := len(n.backoff) + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		if n.ctx.Err() != nil {
			return
		}

		ts := n.now().Unix()
		req, err := newRequest(n.ctx, n.url, body, n.secret, ts, ev.Event)
		if err != nil {
			n.logger.Errorw("failed to build webhook request",
				"event", ev.Event,
				"entity", ev.Entity,
				"error", err,
			)
			return
		}

		resp, err := n.client.Do(req)
		if err != nil {
			if attempt < attempts && n.wait(attempt) {
				continue
			}
			n.logger.Warnw("webhook delivery failed: request error",
				"event", ev.Event,
				"entity", ev.Entity,
				"host", n.host,
				"attempts", attempt,
				"error", err,
			)
			return
		}

		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return
		case resp.StatusCode >= 500 && attempt < attempts:
			if n.wait(attempt) {
				continue
			}
			return
		default:
			n.logger.Warnw("webhook delivery failed: non-2xx response",
				"event", ev.Event,
				"entity", ev.Entity,
				"host", n.host,
				"status", resp.StatusCode,
				"attempts", attempt,
			)
			return
		}
	}
}

// wait sleeps for the backoff slot after the given attempt. It returns false
// when the notifier is shutting down.
func (n *Notifier) wait(attempt int) bool {
	idx := attempt - 1
	if idx < 0 || idx >= len(n.backoff) {
		return false
	}
	return n.sleep(n.ctx, n.backoff[idx])
}

func newRequest(ctx context.Context, url string, body []byte, secret string, ts int64, event string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NodeWatch-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-NodeWatch-Signature", sign(secret, ts, body))
	req.Header.Set("X-NodeWatch-Event", event)
	return req, nil
}

// sign returns "sha256=<lowercase hex>" for "<timestamp>.<body>".
func sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// LogHost returns the host portion of a URL for logging. Paths and query
// strings may contain credentials and must not be logged.
func LogHost(raw string) string {
	return urlHost(raw)
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
