package usecases

import (
	"context"
	"testing"

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
	observed []observedRuleStatus
}

func (s *stubRuleStatusObserver) ObserveRuleStatus(ctx context.Context, ruleSID, ruleName string, agentID uint, syncStatus, runStatus, errorMessage string) {
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
			{RuleID: enabled.SID(), SyncStatus: "synced", RunStatus: "running"},
		},
	}

	if err := uc.Execute(context.Background(), input); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(observer.observed) != 2 {
		t.Fatalf("observed %d statuses, want 2: %+v", len(observer.observed), observer.observed)
	}

	first := observer.observed[0]
	if first.ruleSID != enabled.SID() {
		t.Errorf("ruleSID = %q, want %q", first.ruleSID, enabled.SID())
	}
	if first.ruleName != enabled.Name() {
		t.Errorf("ruleName = %q, want %q", first.ruleName, enabled.Name())
	}
	if first.agentID != 7 {
		t.Errorf("agentID = %d, want 7", first.agentID)
	}
	if first.syncStatus != "failed" || first.runStatus != "error" || first.errorMessage != "boom" {
		t.Errorf("unexpected status payload: %+v", first)
	}

	second := observer.observed[1]
	if second.ruleSID != enabled.SID() || second.syncStatus != "synced" || second.runStatus != "running" {
		t.Errorf("unexpected second status payload: %+v", second)
	}
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
