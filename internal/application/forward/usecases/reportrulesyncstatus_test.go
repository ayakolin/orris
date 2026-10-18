package usecases

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/shared/logger"
)

type stubRuleSyncStatusUpdater struct {
	calls int
	err   error
}

func (s *stubRuleSyncStatusUpdater) UpdateRuleStatus(ctx context.Context, agentID uint, rules []dto.RuleSyncStatusItem) error {
	s.calls++
	return s.err
}

type observedRuleStatus struct {
	ruleSID      string
	ruleName     string
	agentID      uint
	syncStatus   string
	runStatus    string
	errorMessage string
}

type stubRuleStatusObserver struct {
	mu       sync.Mutex
	observed []observedRuleStatus
	forgot   []string
}

func (s *stubRuleStatusObserver) ObserveRuleStatus(ctx context.Context, ruleSID, ruleName string, agentID uint, syncStatus, runStatus, errorMessage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observed = append(s.observed, observedRuleStatus{
		ruleSID:      ruleSID,
		ruleName:     ruleName,
		agentID:      agentID,
		syncStatus:   syncStatus,
		runStatus:    runStatus,
		errorMessage: errorMessage,
	})
}

func newReportRuleSyncStatusTestUseCase(t *testing.T, observer RuleStatusObserver) (*ReportRuleSyncStatusUseCase, *testutil.MockForwardRuleRepository) {
	t.Helper()

	agentRepo := testutil.NewMockForwardAgentRepository()
	ruleRepo := testutil.NewMockForwardRuleRepository()

	agent := mustTestAgent(t, 7, "fa_observer", "203.0.113.7", "10.0.0.7")
	agentRepo.AddAgent(agent)

	updater := &stubRuleSyncStatusUpdater{}
	uc := NewReportRuleSyncStatusUseCase(agentRepo, updater, ruleRepo, logger.NewLogger())
	uc.SetRuleStatusObserver(observer)

	return uc, ruleRepo
}

func TestReportRuleSyncStatus_ObservesEnabledRuleOnly(t *testing.T) {
	observer := &stubRuleStatusObserver{}
	uc, ruleRepo := newReportRuleSyncStatusTestUseCase(t, observer)

	enabled := mustTestRule(t, "fr_enabled", 7, 18080, "127.0.0.1")
	if err := enabled.Enable(); err != nil {
		t.Fatalf("enable rule: %v", err)
	}
	ruleRepo.AddRule(enabled)

	disabled := mustTestRule(t, "fr_disabled", 7, 18081, "127.0.0.1")
	ruleRepo.AddRule(disabled)

	input := &dto.ReportRuleSyncStatusInput{
		AgentID: 7,
		Rules: []dto.RuleSyncStatusItem{
			{RuleID: enabled.SID(), SyncStatus: "failed", RunStatus: "error", ErrorMessage: "boom"},
			{RuleID: disabled.SID(), SyncStatus: "failed", RunStatus: "error", ErrorMessage: "ignored"},
			{RuleID: "", SyncStatus: "failed", RunStatus: "error"},
			{RuleID: "fr_unknown", SyncStatus: "failed", RunStatus: "error"},
		},
	}

	if err := uc.Execute(context.Background(), input); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	observed := waitObserved(t, observer, 1)
	if len(observed) != 1 {
		t.Fatalf("observed %d statuses, want 1: %+v", len(observed), observed)
	}
	if observed[0].ruleSID != enabled.SID() || observed[0].ruleName != enabled.Name() {
		t.Errorf("unexpected rule identity: %+v", observed[0])
	}
	if observed[0].agentID != 7 {
		t.Errorf("agentID = %d, want 7", observed[0].agentID)
	}
	if observed[0].syncStatus != "failed" || observed[0].runStatus != "error" || observed[0].errorMessage != "boom" {
		t.Errorf("unexpected status payload: %+v", observed[0])
	}
}

// A rule repeated within one message must not emit a failed/recovered pair: the
// last entry is the state the agent ended in.
func TestReportRuleSyncStatus_DuplicateEntriesCollapseToLast(t *testing.T) {
	observer := &stubRuleStatusObserver{}
	uc, ruleRepo := newReportRuleSyncStatusTestUseCase(t, observer)

	rule := mustTestRule(t, "fr_dup", 7, 18083, "127.0.0.1")
	if err := rule.Enable(); err != nil {
		t.Fatalf("enable rule: %v", err)
	}
	ruleRepo.AddRule(rule)

	input := &dto.ReportRuleSyncStatusInput{
		AgentID: 7,
		Rules: []dto.RuleSyncStatusItem{
			{RuleID: rule.SID(), SyncStatus: "failed", RunStatus: "error"},
			{RuleID: rule.SID(), SyncStatus: "synced", RunStatus: "running"},
		},
	}
	if err := uc.Execute(context.Background(), input); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	observed := waitObserved(t, observer, 1)
	time.Sleep(50 * time.Millisecond)
	observed = observer.snapshot()
	if len(observed) != 1 || observed[0].syncStatus != "synced" {
		t.Fatalf("observed = %+v, want only the last entry", observed)
	}
}

// Observation must not block Execute even when the observer is slow.
func TestReportRuleSyncStatus_ObserverDoesNotBlockExecute(t *testing.T) {
	block := make(chan struct{})
	observer := &blockingObserver{release: block, started: make(chan struct{})}
	uc, ruleRepo := newReportRuleSyncStatusTestUseCase(t, observer)

	rule := mustTestRule(t, "fr_slow", 7, 18084, "127.0.0.1")
	if err := rule.Enable(); err != nil {
		t.Fatalf("enable rule: %v", err)
	}
	ruleRepo.AddRule(rule)

	start := time.Now()
	err := uc.Execute(context.Background(), &dto.ReportRuleSyncStatusInput{
		AgentID: 7,
		Rules:   []dto.RuleSyncStatusItem{{RuleID: rule.SID(), SyncStatus: "failed", RunStatus: "error"}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Execute blocked for %v", elapsed)
	}
	select {
	case <-observer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("observer never ran")
	}
	close(block)
}

type blockingObserver struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockingObserver) ObserveRuleStatus(context.Context, string, string, uint, string, string, string) {
	b.once.Do(func() { close(b.started) })
	<-b.release
}

// waitObserved blocks until at least want observations arrived and returns a
// copy of them.
func waitObserved(t *testing.T, observer *stubRuleStatusObserver, want int) []observedRuleStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := observer.snapshot(); len(got) >= want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return observer.snapshot()
}

func (s *stubRuleStatusObserver) snapshot() []observedRuleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]observedRuleStatus(nil), s.observed...)
}

func TestReportRuleSyncStatus_NilObserverDoesNotPanic(t *testing.T) {
	uc, ruleRepo := newReportRuleSyncStatusTestUseCase(t, nil)

	rule := mustTestRule(t, "fr_nil_observer", 7, 18082, "127.0.0.1")
	if err := rule.Enable(); err != nil {
		t.Fatalf("enable rule: %v", err)
	}
	ruleRepo.AddRule(rule)

	input := &dto.ReportRuleSyncStatusInput{
		AgentID: 7,
		Rules:   []dto.RuleSyncStatusItem{{RuleID: rule.SID(), SyncStatus: "failed", RunStatus: "stopped"}},
	}

	if err := uc.Execute(context.Background(), input); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}
