// Package usecases contains the application use cases for forward domain.
package usecases

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/shared/goroutine"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// maxConcurrentRuleObservations bounds the number of in-flight observation
// jobs. Observation runs off the agent read path: resolving rule SIDs and
// writing dedupe state touch Redis, and a slow Redis must not stall the
// WebSocket read loop or the REST handler.
const maxConcurrentRuleObservations = 8

// RuleSyncStatusUpdater defines the interface for updating rule sync status in cache.
type RuleSyncStatusUpdater interface {
	UpdateRuleStatus(ctx context.Context, agentID uint, rules []dto.RuleSyncStatusItem) error
}

// RuleStatusForgetter is implemented by observers that keep per-agent dedupe
// state and need it cleared when a rule is no longer eligible for events.
type RuleStatusForgetter interface {
	ForgetRuleStatus(ctx context.Context, ruleSID string, agentID uint)
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

	// observationSlots is a counting semaphore; a full pool drops the sample.
	observationSlots chan struct{}
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
		agentRepo:        agentRepo,
		statusUpdater:    statusUpdater,
		ruleRepo:         ruleRepo,
		logger:           logger,
		observationSlots: make(chan struct{}, maxConcurrentRuleObservations),
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

	uc.observeRuleStatuses(input)

	return nil
}

// observeRuleStatuses schedules background notification of the optional
// observer about each reported rule that resolves to an enabled rule.
//
// The work deliberately runs on its own goroutine: resolving SIDs and writing
// dedupe state hit Redis, and this method is called from the agent WebSocket
// read loop. A bounded semaphore caps concurrency; a saturated pool drops the
// sample (and logs it) rather than blocking the report path. Failures are
// logged and never surface to the caller.
func (uc *ReportRuleSyncStatusUseCase) observeRuleStatuses(input *dto.ReportRuleSyncStatusInput) {
	if uc.ruleStatusObserver == nil || uc.ruleRepo == nil {
		return
	}

	// Copy the report: the caller may reuse or mutate its slice after returning.
	rules := make([]dto.RuleSyncStatusItem, len(input.Rules))
	copy(rules, input.Rules)
	agentID := input.AgentID

	select {
	case uc.observationSlots <- struct{}{}:
	default:
		uc.logger.Warnw("rule status observation dropped: pool saturated",
			"agent_id", agentID,
			"rules_count", len(rules),
		)
		return
	}

	goroutine.SafeGo(uc.logger, "rule-status-observer", func() {
		defer func() { <-uc.observationSlots }()
		uc.observeRuleStatusesSync(context.Background(), agentID, rules)
	})
}

// observeRuleStatusesSync resolves rule metadata and feeds the observer.
func (uc *ReportRuleSyncStatusUseCase) observeRuleStatusesSync(ctx context.Context, agentID uint, items []dto.RuleSyncStatusItem) {
	// Dedupe reported SIDs, preserving report order, so resolved lookups are batched.
	sids := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
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

	latest := make(map[string]dto.RuleSyncStatusItem, len(sids))
	for _, item := range items {
		if item.RuleID == "" {
			continue
		}
		latest[item.RuleID] = item
	}

	rules, err := uc.ruleRepo.GetBySIDs(ctx, sids)
	if err != nil {
		uc.logger.Warnw("failed to resolve rules for status observation",
			"agent_id", agentID,
			"error", err,
		)
		return
	}

	for _, sid := range sids {
		item := latest[sid]
		rule, ok := rules[sid]
		if !ok || rule == nil {
			continue
		}
		if !rule.IsEnabled() {
			// A rule disabled while failing must not keep its agents in the
			// dedupe set, otherwise a later failure would never be emitted.
			if forgetter, ok := uc.ruleStatusObserver.(RuleStatusForgetter); ok {
				forgetter.ForgetRuleStatus(ctx, sid, agentID)
			}
			continue
		}
		uc.ruleStatusObserver.ObserveRuleStatus(
			ctx,
			rule.SID(),
			rule.Name(),
			agentID,
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
