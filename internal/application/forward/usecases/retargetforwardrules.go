package usecases

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/shared/db"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// RetargetCommand represents the input for retargeting forward rules from one
// static landing address to another.
type RetargetCommand struct {
	FromAddress string   // required: current static target address
	ToAddress   string   // required: replacement static target address
	ToPort      *uint16  // optional: replacement target port (kept per-rule when nil)
	RuleSIDs    []string // optional: restrict the operation to these rule IDs
	DryRun      bool     // when true, report the changes without writing or notifying
}

// RetargetRuleResult describes one affected rule.
type RetargetRuleResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AgentID   string `json:"agent_id"`
	OldTarget string `json:"old_target"`
	NewTarget string `json:"new_target"`
	Status    string `json:"status"`
	WillSync  bool   `json:"will_sync"` // true when the rule is enabled and its agent will be pushed the change
}

// RetargetResult is the response of a retarget operation.
type RetargetResult struct {
	DryRun   bool                 `json:"dry_run"`
	From     string               `json:"from_address"`
	To       string               `json:"to_address"`
	ToPort   *uint16              `json:"to_port,omitempty"`
	Matched  int                  `json:"matched"`
	Affected []RetargetRuleResult `json:"affected"`
}

// retargetRuleLocker re-reads the selected rules inside the transaction while
// holding a row lock, so the pre-transaction selection can be revalidated against
// committed state before anything is overwritten.
type retargetRuleLocker interface {
	GetBySIDsForUpdate(ctx context.Context, sids []string) (map[string]*forward.ForwardRule, error)
}

// RetargetForwardRulesUseCase moves every rule pointing at one static landing
// address to another address in a single transaction.
type RetargetForwardRulesUseCase struct {
	repo      forward.Repository
	agentRepo forward.AgentRepository
	updateUC  *UpdateForwardRuleUseCase
	txMgr     db.TransactionRunner
	locker    retargetRuleLocker
	logger    logger.Interface
}

// NewRetargetForwardRulesUseCase creates a new RetargetForwardRulesUseCase.
func NewRetargetForwardRulesUseCase(
	repo forward.Repository,
	agentRepo forward.AgentRepository,
	updateUC *UpdateForwardRuleUseCase,
	txMgr db.TransactionRunner,
	logger logger.Interface,
) *RetargetForwardRulesUseCase {
	uc := &RetargetForwardRulesUseCase{
		repo:      repo,
		agentRepo: agentRepo,
		updateUC:  updateUC,
		txMgr:     txMgr,
		logger:    logger,
	}
	// The repository owns the dialect-specific locking read. Requiring it for
	// writes (checked below) keeps a concurrent edit from being overwritten.
	if locker, ok := repo.(retargetRuleLocker); ok {
		uc.locker = locker
	}
	return uc
}

// Execute retargets all matching rules. Validation happens before any write, and
// the writes run in one transaction: either every rule is retargeted or none is.
func (uc *RetargetForwardRulesUseCase) Execute(ctx context.Context, cmd RetargetCommand) (*RetargetResult, error) {
	if cmd.FromAddress == "" {
		return nil, errors.NewValidationError("from_address is required")
	}
	if cmd.ToAddress == "" {
		return nil, errors.NewValidationError("to_address is required")
	}
	if cmd.ToPort != nil && *cmd.ToPort == 0 {
		return nil, errors.NewValidationError("to_port must be greater than 0")
	}
	if err := forward.ValidateTargetAddress(cmd.FromAddress); err != nil {
		return nil, errors.NewValidationError("invalid from_address: " + err.Error())
	}
	if err := forward.ValidateTargetAddress(cmd.ToAddress); err != nil {
		return nil, errors.NewValidationError("invalid to_address: " + err.Error())
	}
	// Same address with no port change is a no-op and is rejected outright.
	if cmd.FromAddress == cmd.ToAddress && cmd.ToPort == nil {
		return nil, errors.NewValidationError("from_address and to_address are identical and no to_port change was requested")
	}

	// Resolve the optional rule restriction first so we only load the rules we need.
	var restricted map[string]*forward.ForwardRule
	if len(cmd.RuleSIDs) > 0 {
		if len(cmd.RuleSIDs) > dto.BatchLimit {
			return nil, errors.NewValidationError(fmt.Sprintf("rule_ids exceeds limit of %d", dto.BatchLimit))
		}
		for _, sid := range cmd.RuleSIDs {
			if err := id.ValidatePrefix(sid, id.PrefixForwardRule); err != nil {
				return nil, errors.NewValidationError("invalid rule_id format, expected fr_xxxxx: " + sid)
			}
		}
		rules, err := uc.repo.GetBySIDs(ctx, cmd.RuleSIDs)
		if err != nil {
			uc.logger.Errorw("failed to load rules for retarget", "error", err)
			return nil, fmt.Errorf("failed to load rules: %w", err)
		}
		restricted = rules
	}

	candidates, err := uc.repo.ListByTargetAddress(ctx, cmd.FromAddress)
	if err != nil {
		uc.logger.Errorw("failed to list rules by target address", "from_address", cmd.FromAddress, "error", err)
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	matched := make([]*forward.ForwardRule, 0, len(candidates))
	for _, rule := range candidates {
		if restricted != nil {
			if _, ok := restricted[rule.SID()]; !ok {
				continue
			}
		}
		// Node-linked rules have no static target of their own; they are never retargeted.
		if rule.TargetNodeID() != nil {
			continue
		}
		if rule.TargetAddress() != cmd.FromAddress {
			continue
		}
		// A rule whose effective target would not change is not a candidate: a
		// retarget that changes nothing is a no-op, not an operation.
		newPort := rule.TargetPort()
		if cmd.ToPort != nil {
			newPort = *cmd.ToPort
		}
		if rule.TargetAddress() == cmd.ToAddress && rule.TargetPort() == newPort {
			continue
		}
		matched = append(matched, rule)
	}
	// Deterministic order for both the response and the transaction.
	sort.Slice(matched, func(i, j int) bool { return matched[i].SID() < matched[j].SID() })

	// When the address is unchanged only the port can make the operation
	// meaningful. If every candidate would keep its current port, the request is
	// a no-op and is rejected instead of reporting a successful empty retarget.
	if cmd.FromAddress == cmd.ToAddress && len(matched) == 0 {
		return nil, errors.NewValidationError(
			"from_address and to_address are identical and no matched rule would change its port; nothing to retarget")
	}

	result := &RetargetResult{
		DryRun:   cmd.DryRun,
		From:     cmd.FromAddress,
		To:       cmd.ToAddress,
		ToPort:   cmd.ToPort,
		Matched:  len(matched),
		Affected: make([]RetargetRuleResult, 0, len(matched)),
	}
	if len(matched) == 0 {
		return result, nil
	}

	agentSIDs, err := uc.resolveAgentSIDs(ctx, matched)
	if err != nil {
		return nil, err
	}

	// Build and validate every update before touching the database so a validation
	// error cannot leave a half-applied retarget behind.
	updates := make([]UpdateForwardRuleCommand, 0, len(matched))
	// projectedResults describes the plan from the pre-transaction snapshot. It is
	// what a dry run returns; a real run replaces it with the applied state read
	// under the row lock, so the response cannot report a status that changed
	// concurrently.
	projectedResults := make([]RetargetRuleResult, 0, len(matched))
	plannedOldPorts := make(map[string]uint16, len(matched))
	plannedNewPorts := make(map[string]uint16, len(matched))
	for _, rule := range matched {
		newPort := rule.TargetPort()
		if cmd.ToPort != nil {
			newPort = *cmd.ToPort
		}
		plannedOldPorts[rule.SID()] = rule.TargetPort()
		plannedNewPorts[rule.SID()] = newPort

		// Validate exactly like a single PUT would, before any write. This keeps a
		// dry run honest: it cannot announce a change the real run would reject.
		if err := forward.ValidateTarget(cmd.ToAddress, newPort); err != nil {
			return nil, errors.NewValidationError(fmt.Sprintf("invalid target for rule %s: %s", rule.SID(), err.Error()))
		}

		toAddress := cmd.ToAddress
		updates = append(updates, UpdateForwardRuleCommand{
			ShortID:       rule.SID(),
			TargetAddress: &toAddress,
			TargetPort:    &newPort,
		})

		projectedResults = append(projectedResults, RetargetRuleResult{
			ID:        rule.SID(),
			Name:      rule.Name(),
			AgentID:   agentSIDs[rule.AgentID()],
			OldTarget: formatTarget(rule.TargetAddress(), rule.TargetPort()),
			NewTarget: formatTarget(cmd.ToAddress, newPort),
			Status:    rule.Status().String(),
			WillSync:  rule.IsEnabled(),
		})
	}

	if cmd.DryRun {
		result.Affected = projectedResults
		return result, nil
	}

	if uc.locker == nil {
		return nil, errors.NewInternalError("retarget requires a repository with row locking support")
	}

	// Run every update in one transaction. The selected rules are re-read under a
	// row lock first, so an edit that landed between selection and commit aborts
	// the whole operation instead of being silently overwritten.
	// The update use case then validates the new target through the same domain
	// path as a single PUT and persists with the transaction-bound context.
	// Notifications and node re-syncs are collected and flushed only after commit.
	var appliedResults []RetargetRuleResult

	txCtx, notifications := WithDeferredRuleNotifications(ctx)
	txErr := uc.txMgr.RunInTransaction(txCtx, func(txCtx context.Context) error {
		locked, err := uc.locker.GetBySIDsForUpdate(txCtx, ruleSIDs(matched))
		if err != nil {
			return fmt.Errorf("failed to lock rules for retarget: %w", err)
		}

		for i := range updates {
			sid := updates[i].ShortID
			current, ok := locked[sid]
			if !ok || current == nil {
				return errors.NewConflictError(
					"a retargeted rule was deleted concurrently", sid)
			}
			if current.TargetNodeID() != nil {
				return errors.NewConflictError(
					"a retargeted rule was linked to a node concurrently; it no longer has a static target", sid)
			}
			if current.TargetAddress() != cmd.FromAddress {
				return errors.NewConflictError(
					fmt.Sprintf("a retargeted rule no longer points at %s", cmd.FromAddress), sid)
			}
			if current.TargetPort() != plannedOldPorts[sid] {
				return errors.NewConflictError(
					fmt.Sprintf("a retargeted rule changed its target port concurrently (planned %d, found %d)",
						plannedOldPorts[sid], current.TargetPort()), sid)
			}
		}

		for i := range updates {
			if err := uc.updateUC.Execute(txCtx, updates[i]); err != nil {
				return fmt.Errorf("failed to retarget rule %s: %w", updates[i].ShortID, err)
			}
		}

		// Report the state the operation actually applied. The locked entities are
		// read under the row lock, so a concurrent enable/disable is reflected here
		// and in will_sync; the push decision itself is made by the update use case
		// from the same fresh row.
		applied := make([]RetargetRuleResult, 0, len(updates))
		for _, update := range updates {
			sid := update.ShortID
			current := locked[sid]
			if current == nil {
				return errors.NewConflictError("a retargeted rule was deleted concurrently", sid)
			}
			applied = append(applied, RetargetRuleResult{
				ID:        sid,
				Name:      current.Name(),
				AgentID:   agentSIDs[current.AgentID()],
				OldTarget: formatTarget(cmd.FromAddress, plannedOldPorts[sid]),
				NewTarget: formatTarget(cmd.ToAddress, plannedNewPorts[sid]),
				Status:    current.Status().String(),
				WillSync:  current.IsEnabled(),
			})
		}
		appliedResults = applied

		return nil
	})
	if txErr != nil {
		uc.logger.Errorw("retarget transaction rolled back",
			"from_address", cmd.FromAddress,
			"to_address", cmd.ToAddress,
			"error", txErr,
		)
		return nil, fmt.Errorf("failed to retarget rules: %w", txErr)
	}

	notifications.Flush(uc.updateUC.ConfigSyncNotifier(), uc.logger)
	// Node subscription snapshots are re-read from committed state only after the
	// transaction, never from inside it.
	notifications.FlushNodeSyncs(uc.updateUC.NodeSubscriptionSyncer(), uc.logger)

	result.Affected = appliedResults
	uc.logger.Infow("retargeted forward rules",
		"from_address", cmd.FromAddress,
		"to_address", cmd.ToAddress,
		"count", len(appliedResults),
	)

	return result, nil
}

// ruleSIDs returns the SIDs of the given rules in their existing order.
func ruleSIDs(rules []*forward.ForwardRule) []string {
	sids := make([]string, 0, len(rules))
	for _, rule := range rules {
		sids = append(sids, rule.SID())
	}
	return sids
}

// formatTarget renders "host:port", bracketing IPv6 literals.
func formatTarget(address string, port uint16) string {
	return net.JoinHostPort(address, strconv.Itoa(int(port)))
}

// resolveAgentSIDs maps internal agent IDs to their SIDs for the response.
func (uc *RetargetForwardRulesUseCase) resolveAgentSIDs(ctx context.Context, rules []*forward.ForwardRule) (map[uint]string, error) {
	if uc.agentRepo == nil {
		return map[uint]string{}, nil
	}

	agentIDs := make([]uint, 0, len(rules))
	seen := make(map[uint]struct{}, len(rules))
	for _, rule := range rules {
		if _, ok := seen[rule.AgentID()]; ok {
			continue
		}
		seen[rule.AgentID()] = struct{}{}
		agentIDs = append(agentIDs, rule.AgentID())
	}

	sidMap, err := uc.agentRepo.GetSIDsByIDs(ctx, agentIDs)
	if err != nil {
		uc.logger.Errorw("failed to resolve agent SIDs for retarget", "error", err)
		return nil, fmt.Errorf("failed to resolve agent IDs: %w", err)
	}
	return sidMap, nil
}
