// Package usecases contains the application use cases for forward domain.
package usecases

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// RuleSyncStatusUpdater defines the interface for updating rule sync status in cache.
type RuleSyncStatusUpdater interface {
	UpdateRuleStatus(ctx context.Context, agentID uint, rules []dto.RuleSyncStatusItem) error
}

// RuleStatusObserver receives per-rule sync/run status after it has been persisted.
type RuleStatusObserver interface {
	ObserveRuleStatus(ctx context.Context, ruleSID, ruleName string, agentID uint, syncStatus, runStatus, errorMessage string)
}

// ReportRuleSyncStatusUseCase handles rule sync status reporting from agents.
type ReportRuleSyncStatusUseCase struct {
	agentRepo          forward.AgentRepository
	statusUpdater      RuleSyncStatusUpdater
	ruleRepo           forward.Repository
	logger             logger.Interface
	ruleStatusObserver RuleStatusObserver
}

// SetRuleStatusObserver wires an optional observer notified about per-rule status
// after it has been persisted. Call before the use case is used concurrently.
func (uc *ReportRuleSyncStatusUseCase) SetRuleStatusObserver(observer RuleStatusObserver) {
	uc.ruleStatusObserver = observer
}

// NewReportRuleSyncStatusUseCase creates a new ReportRuleSyncStatusUseCase.
func NewReportRuleSyncStatusUseCase(
	agentRepo forward.AgentRepository,
	statusUpdater RuleSyncStatusUpdater,
	ruleRepo forward.Repository,
	logger logger.Interface,
) *ReportRuleSyncStatusUseCase {
	return &ReportRuleSyncStatusUseCase{
		agentRepo:     agentRepo,
		statusUpdater: statusUpdater,
		ruleRepo:      ruleRepo,
		logger:        logger,
	}
}

// Execute validates agent and updates rule sync status.
func (uc *ReportRuleSyncStatusUseCase) Execute(ctx context.Context, input *dto.ReportRuleSyncStatusInput) error {
	// Verify agent exists
	agent, err := uc.agentRepo.GetByID(ctx, input.AgentID)
	if err != nil {
		uc.logger.Errorw("failed to get agent", "agent_id", input.AgentID, "error", err)
		return fmt.Errorf("get agent: %w", err)
	}
	if agent == nil {
		return fmt.Errorf("agent not found: %d", input.AgentID)
	}

	// Update rule sync status in cache
	if err := uc.statusUpdater.UpdateRuleStatus(ctx, input.AgentID, input.Rules); err != nil {
		uc.logger.Errorw("failed to update rule sync status", "agent_id", input.AgentID, "error", err)
		return fmt.Errorf("update rule status: %w", err)
	}

	uc.logger.Debugw("rule sync status reported",
		"agent_id", input.AgentID,
		"rules_count", len(input.Rules),
	)

	uc.observeRuleStatuses(ctx, input)

	return nil
}

// observeRuleStatuses notifies the optional observer about each reported rule
// that resolves to an enabled rule. Observation is best-effort: failures are
// logged and never surface to the caller.
func (uc *ReportRuleSyncStatusUseCase) observeRuleStatuses(ctx context.Context, input *dto.ReportRuleSyncStatusInput) {
	if uc.ruleStatusObserver == nil || uc.ruleRepo == nil {
		return
	}

	// Dedupe reported SIDs, preserving report order, so resolved lookups are batched.
	sids := make([]string, 0, len(input.Rules))
	seen := make(map[string]struct{}, len(input.Rules))
	for _, item := range input.Rules {
		if item.RuleID == "" {
			continue
		}
		if _, ok := seen[item.RuleID]; ok {
			continue
		}
		seen[item.RuleID] = struct{}{}
		sids = append(sids, item.RuleID)
	}
	if len(sids) == 0 {
		return
	}

	rules, err := uc.ruleRepo.GetBySIDs(ctx, sids)
	if err != nil {
		uc.logger.Warnw("failed to resolve rules for status observation",
			"agent_id", input.AgentID,
			"error", err,
		)
		return
	}

	for _, item := range input.Rules {
		if item.RuleID == "" {
			continue
		}
		rule, ok := rules[item.RuleID]
		if !ok || rule == nil || !rule.IsEnabled() {
			continue
		}
		uc.ruleStatusObserver.ObserveRuleStatus(
			ctx,
			rule.SID(),
			rule.Name(),
			input.AgentID,
			item.SyncStatus,
			item.RunStatus,
			item.ErrorMessage,
		)
	}
}

// String implements fmt.Stringer for logging purposes.
func (uc *ReportRuleSyncStatusUseCase) String() string {
	return "ReportRuleSyncStatusUseCase"
}

// HandleMessage processes rule sync status messages from agents via WebSocket.
// Implements agent.MessageHandler interface.
func (uc *ReportRuleSyncStatusUseCase) HandleMessage(agentID uint, msgType string, data any) bool {
	if msgType != dto.MsgTypeRuleSyncStatus {
		return false
	}

	// Parse the rule sync status data
	dataBytes, err := json.Marshal(data)
	if err != nil {
		uc.logger.Warnw("failed to marshal rule sync status data",
			"agent_id", agentID,
			"error", err,
		)
		return true
	}

	var statusData struct {
		Rules []dto.RuleSyncStatusItem `json:"rules"`
	}
	if err := json.Unmarshal(dataBytes, &statusData); err != nil {
		uc.logger.Warnw("failed to unmarshal rule sync status data",
			"agent_id", agentID,
			"error", err,
		)
		return true
	}

	// Execute the use case
	input := &dto.ReportRuleSyncStatusInput{
		AgentID: agentID,
		Rules:   statusData.Rules,
	}

	if err := uc.Execute(context.Background(), input); err != nil {
		uc.logger.Warnw("failed to process rule sync status via websocket",
			"agent_id", agentID,
			"error", err,
		)
	}

	return true
}
