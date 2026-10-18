package usecases

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/domain/forward"
	vo "github.com/orris-inc/orris/internal/domain/forward/valueobjects"
	"github.com/orris-inc/orris/internal/domain/node"
)

// directTxRunner runs the transaction callback with the context it was given,
// simulating a successful commit.
type directTxRunner struct {
	calls int
}

func (r *directTxRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	r.calls++
	return fn(ctx)
}

// failingTxRunner fails before the callback runs, simulating a transaction that
// never started.
type failingTxRunner struct{}

func (r *failingTxRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return errors.New("transaction failed")
}

// rollbackTxRunner runs the callback and then reports an error, simulating a
// transaction that was rolled back after the work was attempted.
type rollbackTxRunner struct{}

func (r *rollbackTxRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := fn(ctx); err != nil {
		return err
	}
	return errors.New("transaction rolled back")
}

func batchStringPtr(s string) *string { return &s }

func batchUint16Ptr(v uint16) *uint16 { return &v }

func batchIntPtr(v int) *int { return &v }

// batchTestAgent builds a forward agent with a fixed internal ID and SID.
func batchTestAgent(t *testing.T, id uint, sid, publicAddress, tunnelAddress string) *forward.ForwardAgent {
	t.Helper()

	agent, err := forward.NewForwardAgent(
		"agent-"+sid,
		publicAddress,
		tunnelAddress,
		"",
		func() (string, error) { return sid, nil },
		func(shortID string) (string, string) { return "token-" + shortID, "hash-" + shortID },
	)
	require.NoError(t, err)
	require.NoError(t, agent.SetID(id))

	return agent
}

// batchTestRule builds a direct forward rule with a static target.
func batchTestRule(
	t *testing.T,
	sid string,
	agentID uint,
	listenPort uint16,
	targetAddress string,
	targetPort uint16,
) *forward.ForwardRule {
	t.Helper()

	rule, err := forward.NewForwardRule(
		agentID,
		nil,
		nil,
		vo.ForwardRuleTypeDirect,
		0,
		nil,
		vo.DefaultLoadBalanceStrategy,
		nil,
		nil,
		nil,
		vo.TunnelTypeWS,
		"rule-"+sid,
		listenPort,
		targetAddress,
		targetPort,
		nil,
		"",
		vo.IPVersionAuto,
		vo.ForwardProtocolTCP,
		"",
		nil,
		0,
		vo.AddressPreferenceAuto,
		func() (string, error) { return sid, nil },
	)
	require.NoError(t, err)

	return rule
}

// batchTestNodeLinkedRule builds a direct forward rule whose target is a node
// instead of a static address.
func batchTestNodeLinkedRule(t *testing.T, sid string, agentID uint, listenPort uint16, nodeID uint) *forward.ForwardRule {
	t.Helper()

	rule, err := forward.NewForwardRule(
		agentID,
		nil,
		nil,
		vo.ForwardRuleTypeDirect,
		0,
		nil,
		vo.DefaultLoadBalanceStrategy,
		nil,
		nil,
		nil,
		vo.TunnelTypeWS,
		"rule-"+sid,
		listenPort,
		"",
		0,
		&nodeID,
		"",
		vo.IPVersionAuto,
		vo.ForwardProtocolTCP,
		"",
		nil,
		0,
		vo.AddressPreferenceAuto,
		func() (string, error) { return sid, nil },
	)
	require.NoError(t, err)

	return rule
}

func batchEnableRule(t *testing.T, rule *forward.ForwardRule) *forward.ForwardRule {
	t.Helper()
	require.NoError(t, rule.Enable())
	return rule
}

func batchNewUseCase(
	repo *testutil.MockForwardRuleRepository,
	agentRepo *testutil.MockForwardAgentRepository,
	notifier *testutil.MockConfigSyncNotifier,
	txMgr interface {
		RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	},
) *BatchForwardRuleUseCase {
	updateUC := NewUpdateForwardRuleUseCase(
		repo,
		agentRepo,
		nil,
		nil,
		nil,
		nil,
		notifier,
		testutil.NewMockLogger(),
	)
	return NewBatchForwardRuleUseCase(
		repo,
		nil,
		nil,
		nil,
		nil,
		nil,
		updateUC,
		txMgr,
		testutil.NewMockLogger(),
	)
}

// waitForNotifyCalls waits for the asynchronous notification flush to deliver at
// least want calls and returns them.
func waitForNotifyCalls(t *testing.T, notifier *testutil.MockConfigSyncNotifier, want int) []testutil.NotifyCall {
	t.Helper()

	var calls []testutil.NotifyCall
	require.Eventually(t, func() bool {
		calls = notifier.GetCalls()
		return len(calls) >= want
	}, 2*time.Second, 10*time.Millisecond, "expected at least %d notification calls", want)
	return calls
}

func notifyCallsWith(calls []testutil.NotifyCall, ruleSID, changeType string) []testutil.NotifyCall {
	matched := make([]testutil.NotifyCall, 0, len(calls))
	for _, call := range calls {
		if call.RuleShortID == ruleSID && call.ChangeType == changeType {
			matched = append(matched, call)
		}
	}
	return matched
}

func TestBatchUpdate_TargetAddressAndPortUpdatesEveryRule(t *testing.T) {
	ctx := context.Background()

	agent := batchTestAgent(t, 1, "fa_batchagent1", "203.0.113.10", "10.0.0.10")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	repo := testutil.NewMockForwardRuleRepository()
	ruleA := batchEnableRule(t, batchTestRule(t, "fr_000000000001", agent.ID(), 18001, "192.0.2.10", 443))
	ruleB := batchEnableRule(t, batchTestRule(t, "fr_000000000002", agent.ID(), 18002, "192.0.2.11", 8443))
	repo.AddRule(ruleA)
	repo.AddRule(ruleB)

	notifier := testutil.NewMockConfigSyncNotifier()
	uc := batchNewUseCase(repo, agentRepo, notifier, &directTxRunner{})

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{
			{
				RuleSID:       ruleA.SID(),
				TargetAddress: batchStringPtr("10.1.1.1"),
				TargetPort:    batchUint16Ptr(8080),
			},
			{
				RuleSID:       ruleB.SID(),
				TargetAddress: batchStringPtr("10.1.1.2"),
				TargetPort:    batchUint16Ptr(8081),
			},
		},
	})
	require.NoError(t, err)
	require.Empty(t, result.Failed)
	require.ElementsMatch(t, []string{ruleA.SID(), ruleB.SID()}, result.Succeeded)

	storedA, err := repo.GetBySID(ctx, ruleA.SID())
	require.NoError(t, err)
	require.Equal(t, "10.1.1.1", storedA.TargetAddress())
	require.Equal(t, uint16(8080), storedA.TargetPort())

	storedB, err := repo.GetBySID(ctx, ruleB.SID())
	require.NoError(t, err)
	require.Equal(t, "10.1.1.2", storedB.TargetAddress())
	require.Equal(t, uint16(8081), storedB.TargetPort())

	calls := waitForNotifyCalls(t, notifier, 2)
	for _, sid := range []string{ruleA.SID(), ruleB.SID()} {
		updated := notifyCallsWith(calls, sid, "updated")
		require.Len(t, updated, 1, "expected one updated notification for %s", sid)
		require.Equal(t, agent.ID(), updated[0].AgentID)
	}
	require.Len(t, notifyCallsWith(calls, ruleA.SID(), "deleted"), 0)
	require.Len(t, notifyCallsWith(calls, ruleB.SID(), "deleted"), 0)
}

func TestBatchUpdate_TargetAddressClearsTargetNodeID(t *testing.T) {
	ctx := context.Background()

	agent := batchTestAgent(t, 1, "fa_batchagent2", "203.0.113.11", "10.0.0.11")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	repo := testutil.NewMockForwardRuleRepository()
	rule := batchEnableRule(t, batchTestNodeLinkedRule(t, "fr_000000000011", agent.ID(), 18011, 42))
	require.NotNil(t, rule.TargetNodeID())
	repo.AddRule(rule)

	notifier := testutil.NewMockConfigSyncNotifier()
	uc := batchNewUseCase(repo, agentRepo, notifier, &directTxRunner{})

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{{
			RuleSID:       rule.SID(),
			TargetAddress: batchStringPtr("10.2.2.2"),
			TargetPort:    batchUint16Ptr(9090),
		}},
	})
	require.NoError(t, err)
	require.Empty(t, result.Failed)
	require.Equal(t, []string{rule.SID()}, result.Succeeded)

	stored, err := repo.GetBySID(ctx, rule.SID())
	require.NoError(t, err)
	require.Nil(t, stored.TargetNodeID())
	require.Equal(t, "10.2.2.2", stored.TargetAddress())
	require.Equal(t, uint16(9090), stored.TargetPort())

	calls := waitForNotifyCalls(t, notifier, 1)
	require.Len(t, notifyCallsWith(calls, rule.SID(), "updated"), 1)
}

func TestBatchUpdate_InvalidTargetAddressDoesNotChangeRule(t *testing.T) {
	invalidAddresses := []string{"invalid..address", ""}

	for _, address := range invalidAddresses {
		address := address
		t.Run("address="+address, func(t *testing.T) {
			ctx := context.Background()

			agent := batchTestAgent(t, 1, "fa_batchagent3", "203.0.113.12", "10.0.0.12")
			agentRepo := testutil.NewMockForwardAgentRepository()
			agentRepo.AddAgent(agent)

			repo := testutil.NewMockForwardRuleRepository()
			rule := batchEnableRule(t, batchTestRule(t, "fr_000000000021", agent.ID(), 18021, "10.0.0.1", 443))
			repo.AddRule(rule)

			notifier := testutil.NewMockConfigSyncNotifier()
			uc := batchNewUseCase(repo, agentRepo, notifier, &directTxRunner{})

			result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
				Updates: []BatchUpdateItem{{
					RuleSID:       rule.SID(),
					TargetAddress: batchStringPtr(address),
				}},
			})
			require.NoError(t, err)
			require.Empty(t, result.Succeeded)
			require.Len(t, result.Failed, 1)
			require.Equal(t, rule.SID(), result.Failed[0].ID)

			stored, err := repo.GetBySID(ctx, rule.SID())
			require.NoError(t, err)
			require.Equal(t, "10.0.0.1", stored.TargetAddress())
			require.Equal(t, uint16(443), stored.TargetPort())

			time.Sleep(100 * time.Millisecond)
			require.Empty(t, notifier.GetCalls())
		})
	}

	// The same command on a failing transaction reports nothing as succeeded and
	// never reaches the notifier.
	t.Run("failed transaction", func(t *testing.T) {
		agent := batchTestAgent(t, 1, "fa_batchagent4", "203.0.113.13", "10.0.0.13")
		agentRepo := testutil.NewMockForwardAgentRepository()
		agentRepo.AddAgent(agent)

		repo := testutil.NewMockForwardRuleRepository()
		rule := batchEnableRule(t, batchTestRule(t, "fr_000000000022", agent.ID(), 18022, "10.0.0.1", 443))
		repo.AddRule(rule)

		notifier := testutil.NewMockConfigSyncNotifier()
		uc := batchNewUseCase(repo, agentRepo, notifier, &failingTxRunner{})

		result, err := uc.BatchUpdate(context.Background(), BatchUpdateCommand{
			Updates: []BatchUpdateItem{{
				RuleSID:       rule.SID(),
				TargetAddress: batchStringPtr("10.3.3.3"),
			}},
		})
		require.NoError(t, err)
		require.Empty(t, result.Succeeded)

		stored, err := repo.GetBySID(context.Background(), rule.SID())
		require.NoError(t, err)
		require.Equal(t, "10.0.0.1", stored.TargetAddress())

		time.Sleep(100 * time.Millisecond)
		require.Empty(t, notifier.GetCalls())
	})
}

func TestBatchUpdate_TargetPortZeroIsRejected(t *testing.T) {
	ctx := context.Background()

	agent := batchTestAgent(t, 1, "fa_batchagent5", "203.0.113.14", "10.0.0.14")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	repo := testutil.NewMockForwardRuleRepository()
	rule := batchEnableRule(t, batchTestRule(t, "fr_000000000031", agent.ID(), 18031, "10.0.0.1", 443))
	repo.AddRule(rule)

	notifier := testutil.NewMockConfigSyncNotifier()
	uc := batchNewUseCase(repo, agentRepo, notifier, &directTxRunner{})

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{{
			RuleSID:    rule.SID(),
			TargetPort: batchUint16Ptr(0),
		}},
	})
	require.NoError(t, err)
	require.Empty(t, result.Succeeded)
	require.Len(t, result.Failed, 1)
	require.Contains(t, result.Failed[0].Reason, "target port cannot be zero")

	stored, err := repo.GetBySID(ctx, rule.SID())
	require.NoError(t, err)
	require.Equal(t, uint16(443), stored.TargetPort())

	time.Sleep(100 * time.Millisecond)
	require.Empty(t, notifier.GetCalls())
}

func TestBatchUpdate_TransactionErrorSuppressesNotifications(t *testing.T) {
	ctx := context.Background()

	agent := batchTestAgent(t, 1, "fa_batchagent6", "203.0.113.15", "10.0.0.15")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	repo := testutil.NewMockForwardRuleRepository()
	rule := batchEnableRule(t, batchTestRule(t, "fr_000000000041", agent.ID(), 18041, "10.0.0.1", 443))
	repo.AddRule(rule)

	notifier := testutil.NewMockConfigSyncNotifier()
	uc := batchNewUseCase(repo, agentRepo, notifier, &failingTxRunner{})

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{{
			RuleSID:       rule.SID(),
			TargetAddress: batchStringPtr("10.4.4.4"),
			TargetPort:    batchUint16Ptr(8443),
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Succeeded)

	stored, err := repo.GetBySID(ctx, rule.SID())
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1", stored.TargetAddress())
	require.Equal(t, uint16(443), stored.TargetPort())

	time.Sleep(100 * time.Millisecond)
	require.Empty(t, notifier.GetCalls())
}

func TestBatchUpdate_NameRemarkSortOrderAndAgentStillWork(t *testing.T) {
	ctx := context.Background()

	oldAgent := batchTestAgent(t, 1, "fa_batchagent7", "203.0.113.16", "10.0.0.16")
	newAgent := batchTestAgent(t, 2, "fa_batchagent8", "203.0.113.17", "10.0.0.17")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(oldAgent)
	agentRepo.AddAgent(newAgent)

	repo := testutil.NewMockForwardRuleRepository()
	rule := batchEnableRule(t, batchTestRule(t, "fr_000000000051", oldAgent.ID(), 18051, "10.0.0.1", 443))
	repo.AddRule(rule)

	notifier := testutil.NewMockConfigSyncNotifier()
	uc := batchNewUseCase(repo, agentRepo, notifier, &directTxRunner{})

	newAgentSID := newAgent.SID()
	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{{
			RuleSID:       rule.SID(),
			Name:          batchStringPtr("renamed rule"),
			Remark:        batchStringPtr("updated remark"),
			SortOrder:     batchIntPtr(5),
			AgentShortID:  &newAgentSID,
			TargetAddress: batchStringPtr("10.5.5.5"),
			TargetPort:    batchUint16Ptr(7443),
		}},
	})
	require.NoError(t, err)
	require.Empty(t, result.Failed)
	require.Equal(t, []string{rule.SID()}, result.Succeeded)

	stored, err := repo.GetBySID(ctx, rule.SID())
	require.NoError(t, err)
	require.Equal(t, "renamed rule", stored.Name())
	require.Equal(t, "updated remark", stored.Remark())
	require.Equal(t, 5, stored.SortOrder())
	require.Equal(t, newAgent.ID(), stored.AgentID())
	require.Equal(t, "10.5.5.5", stored.TargetAddress())
	require.Equal(t, uint16(7443), stored.TargetPort())

	calls := waitForNotifyCalls(t, notifier, 2)
	updated := notifyCallsWith(calls, rule.SID(), "updated")
	require.Len(t, updated, 1)
	require.Equal(t, newAgent.ID(), updated[0].AgentID)
	deleted := notifyCallsWith(calls, rule.SID(), "deleted")
	require.Len(t, deleted, 1)
	require.Equal(t, oldAgent.ID(), deleted[0].AgentID)
}

func TestBatchUpdate_InvalidRuleSIDIsRejectedBeforeTransaction(t *testing.T) {
	ctx := context.Background()

	repo := testutil.NewMockForwardRuleRepository()
	notifier := testutil.NewMockConfigSyncNotifier()

	runner := &directTxRunner{}
	uc := batchNewUseCase(repo, testutil.NewMockForwardAgentRepository(), notifier, runner)

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{{
			RuleSID: "not-a-rule-id",
			Name:    batchStringPtr("nope"),
		}},
	})
	require.NoError(t, err)
	require.Empty(t, result.Succeeded)
	require.Len(t, result.Failed, 1)
	require.True(t, strings.Contains(result.Failed[0].Reason, "invalid"))
	require.Zero(t, runner.calls)
	require.Empty(t, notifier.GetCalls())
}

// failNthUpdateRepo wraps the mock rule repository so that the first
// succeedUpdates Update calls reach the mock and every later call fails. It
// simulates a batch whose second rule cannot be persisted.
type failNthUpdateRepo struct {
	*testutil.MockForwardRuleRepository

	mu            sync.Mutex
	updateCalls   int
	succeedUpdate int
	updateErr     error
}

func (r *failNthUpdateRepo) Update(ctx context.Context, rule *forward.ForwardRule) error {
	r.mu.Lock()
	r.updateCalls++
	call := r.updateCalls
	r.mu.Unlock()

	if call > r.succeedUpdate {
		return r.updateErr
	}
	return r.MockForwardRuleRepository.Update(ctx, rule)
}

// UpdateCalls returns how many times Update has been invoked.
func (r *failNthUpdateRepo) UpdateCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.updateCalls
}

// commitTrackingTxRunner marks the transaction as committed only after the
// callback returns successfully, which lets a notifier detect a push that
// happened before the commit point.
type commitTrackingTxRunner struct {
	committed *atomic.Bool
	calls     int
}

func (r *commitTrackingTxRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	r.calls++
	if err := fn(ctx); err != nil {
		return err
	}
	r.committed.Store(true)
	return nil
}

// commitAwareNotifier records every NotifyRuleChange that arrives before the
// transaction is reported as committed.
type commitAwareNotifier struct {
	*testutil.MockConfigSyncNotifier

	committed *atomic.Bool

	mu         sync.Mutex
	violations []string
}

func (n *commitAwareNotifier) NotifyRuleChange(ctx context.Context, agentID uint, ruleShortID string, changeType string) error {
	if !n.committed.Load() {
		n.mu.Lock()
		n.violations = append(n.violations, ruleShortID+":"+changeType)
		n.mu.Unlock()
	}
	return n.MockConfigSyncNotifier.NotifyRuleChange(ctx, agentID, ruleShortID, changeType)
}

// Violations returns the notifications that were dispatched before commit.
func (n *commitAwareNotifier) Violations() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.violations...)
}

// batchNewUseCaseWithNotifier builds a batch use case whose notifier is any
// ConfigSyncNotifier, so tests can wrap the mock and observe dispatch timing.
func batchNewUseCaseWithNotifier(
	repo forward.Repository,
	agentRepo *testutil.MockForwardAgentRepository,
	notifier ConfigSyncNotifier,
	txMgr interface {
		RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	},
) *BatchForwardRuleUseCase {
	updateUC := NewUpdateForwardRuleUseCase(
		repo,
		agentRepo,
		nil,
		nil,
		nil,
		nil,
		notifier,
		testutil.NewMockLogger(),
	)
	return NewBatchForwardRuleUseCase(
		repo,
		nil,
		nil,
		nil,
		nil,
		nil,
		updateUC,
		txMgr,
		testutil.NewMockLogger(),
	)
}

// TestBatchUpdate_PartialUpdateFailureSuppressesNotifications covers a failure
// halfway through the batch: the first rule is updated, the second one fails, and
// the transaction is rolled back. Nothing may be reported as succeeded and no
// agent or node may be told about the change.
//
// This proves control flow and side-effect suppression, not storage rollback: the
// mock repository has no transactional storage, so reverted rows are the
// database's responsibility.
func TestBatchUpdate_PartialUpdateFailureSuppressesNotifications(t *testing.T) {
	ctx := context.Background()

	agent := batchTestAgent(t, 1, "fa_batchagent9", "203.0.113.20", "10.0.0.20")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	baseRepo := testutil.NewMockForwardRuleRepository()
	ruleA := batchEnableRule(t, batchTestRule(t, "fr_000000000061", agent.ID(), 18061, "10.0.0.1", 443))
	ruleB := batchEnableRule(t, batchTestRule(t, "fr_000000000062", agent.ID(), 18062, "10.0.0.2", 443))
	baseRepo.AddRule(ruleA)
	baseRepo.AddRule(ruleB)

	repo := &failNthUpdateRepo{
		MockForwardRuleRepository: baseRepo,
		succeedUpdate:             1,
		updateErr:                 errors.New("write conflict"),
	}

	notifier := testutil.NewMockConfigSyncNotifier()
	uc := batchNewUseCaseWithNotifier(repo, agentRepo, notifier, &rollbackTxRunner{})

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{
			{
				RuleSID:       ruleA.SID(),
				TargetAddress: batchStringPtr("10.6.6.1"),
				TargetPort:    batchUint16Ptr(8080),
			},
			{
				RuleSID:       ruleB.SID(),
				TargetAddress: batchStringPtr("10.6.6.2"),
				TargetPort:    batchUint16Ptr(8081),
			},
		},
	})

	// BatchUpdate reports the rollback through the result, not through an error.
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Succeeded)
	require.Empty(t, result.Succeeded, "a rolled back batch must not report successes")
	require.Len(t, result.Failed, 1, "only the rule whose update failed is reported")
	require.Equal(t, ruleB.SID(), result.Failed[0].ID)
	require.Contains(t, result.Failed[0].Reason, "failed to update forward rule")

	// The failure really happened mid-way: both updates were attempted.
	require.Equal(t, 2, repo.UpdateCalls())

	time.Sleep(150 * time.Millisecond)
	require.Empty(t, notifier.GetCalls(), "no agent may be notified for a rolled back batch")
}

// TestBatchUpdate_NotificationsDispatchedOnlyAfterCommit pins the ordering
// guarantee: agent pushes are collected during the transaction and only sent
// once the transaction callback has returned successfully.
func TestBatchUpdate_NotificationsDispatchedOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()

	agent := batchTestAgent(t, 1, "fa_batchagent10", "203.0.113.21", "10.0.0.21")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	repo := testutil.NewMockForwardRuleRepository()
	ruleA := batchEnableRule(t, batchTestRule(t, "fr_000000000071", agent.ID(), 18071, "10.0.0.3", 443))
	ruleB := batchEnableRule(t, batchTestRule(t, "fr_000000000072", agent.ID(), 18072, "10.0.0.4", 443))
	repo.AddRule(ruleA)
	repo.AddRule(ruleB)

	committed := &atomic.Bool{}
	runner := &commitTrackingTxRunner{committed: committed}
	notifier := &commitAwareNotifier{
		MockConfigSyncNotifier: testutil.NewMockConfigSyncNotifier(),
		committed:              committed,
	}
	uc := batchNewUseCaseWithNotifier(repo, agentRepo, notifier, runner)

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{
			{
				RuleSID:       ruleA.SID(),
				TargetAddress: batchStringPtr("10.7.7.1"),
				TargetPort:    batchUint16Ptr(9000),
			},
			{
				RuleSID:       ruleB.SID(),
				TargetAddress: batchStringPtr("10.7.7.2"),
				TargetPort:    batchUint16Ptr(9001),
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Failed)
	require.ElementsMatch(t, []string{ruleA.SID(), ruleB.SID()}, result.Succeeded)
	require.Equal(t, 1, runner.calls)
	require.True(t, committed.Load())

	calls := waitForNotifyCalls(t, notifier.MockConfigSyncNotifier, 2)
	for _, sid := range []string{ruleA.SID(), ruleB.SID()} {
		require.Len(t, notifyCallsWith(calls, sid, "updated"), 1)
	}

	time.Sleep(50 * time.Millisecond)
	require.Empty(t, notifier.Violations(), "notifications must not be dispatched before the transaction commits")
}

// batchNewUseCaseWithNodeSync builds a batch use case whose update use case is
// wired with both a node repository and a node subscription syncer. The batch
// therefore collects affected node IDs inside the transaction and re-syncs them
// only after the transaction commits.
func batchNewUseCaseWithNodeSync(
	repo forward.Repository,
	agentRepo *testutil.MockForwardAgentRepository,
	notifier ConfigSyncNotifier,
	nodeRepo node.NodeRepository,
	syncer NodeSubscriptionSyncer,
	txMgr interface {
		RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	},
) *BatchForwardRuleUseCase {
	updateUC := NewUpdateForwardRuleUseCase(
		repo,
		agentRepo,
		nodeRepo,
		nil,
		nil,
		nil,
		notifier,
		testutil.NewMockLogger(),
	)
	updateUC.SetNodeSubscriptionSyncer(syncer)

	return NewBatchForwardRuleUseCase(
		repo,
		nil,
		nil,
		nil,
		nil,
		nil,
		updateUC,
		txMgr,
		testutil.NewMockLogger(),
	)
}

// batchNodeSyncsRule builds an enabled direct rule bound to groupID so that
// collectAffectedNodeIDs resolves the group's nodes for it.
func batchNodeSyncsRule(t *testing.T, sid string, agentID uint, listenPort uint16, groupID uint) *forward.ForwardRule {
	t.Helper()

	rule := batchEnableRule(t, batchTestRule(t, sid, agentID, listenPort, "10.0.0.1", 443))
	rule.SetGroupIDs([]uint{groupID})
	return rule
}

// TestBatchUpdate_NodeSyncsFlushedOncePerNodeAfterCommit pins the node
// subscription side of the deferred batch update: two rules bound to the same
// resource group produce one re-sync per affected node (deduplicated across
// both rules and across the before/after collection of a single update), and
// every sync is dispatched only after the transaction is reported committed.
func TestBatchUpdate_NodeSyncsFlushedOncePerNodeAfterCommit(t *testing.T) {
	ctx := context.Background()

	const groupID uint = 42
	nodeIDs := []uint{7, 9}

	agent := batchTestAgent(t, 1, "fa_batchagent11", "203.0.113.30", "10.0.0.30")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	repo := testutil.NewMockForwardRuleRepository()
	ruleA := batchNodeSyncsRule(t, "fr_000000000081", agent.ID(), 18081, groupID)
	ruleB := batchNodeSyncsRule(t, "fr_000000000082", agent.ID(), 18082, groupID)
	repo.AddRule(ruleA)
	repo.AddRule(ruleB)

	committed := &atomic.Bool{}
	runner := &retargetCommitFlagRunner{committed: committed}
	syncer := &retargetRecordingNodeSyncer{committed: committed}
	nodeRepo := &retargetGroupNodeRepo{groups: map[uint][]uint{groupID: nodeIDs}}
	notifier := testutil.NewMockConfigSyncNotifier()

	uc := batchNewUseCaseWithNodeSync(repo, agentRepo, notifier, nodeRepo, syncer, runner)

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{
			{
				RuleSID:       ruleA.SID(),
				TargetAddress: batchStringPtr("10.8.8.1"),
				TargetPort:    batchUint16Ptr(9100),
			},
			{
				RuleSID:       ruleB.SID(),
				TargetAddress: batchStringPtr("10.8.8.2"),
				TargetPort:    batchUint16Ptr(9101),
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Failed)
	require.ElementsMatch(t, []string{ruleA.SID(), ruleB.SID()}, result.Succeeded)
	require.True(t, committed.Load(), "the runner must report a commit")

	require.Eventually(t, func() bool {
		return len(syncer.NodeIDs()) >= len(nodeIDs)
	}, 2*time.Second, 10*time.Millisecond, "expected a node re-sync per affected node")

	// Give any duplicate dispatch a chance to arrive before asserting equality.
	time.Sleep(100 * time.Millisecond)

	syncedNodeIDs := syncer.NodeIDs()
	require.Len(t, syncedNodeIDs, len(nodeIDs),
		"each affected node must be re-synced exactly once, got %v", syncedNodeIDs)
	require.ElementsMatch(t, nodeIDs, syncedNodeIDs)
	for _, nodeID := range nodeIDs {
		occurrences := 0
		for _, got := range syncedNodeIDs {
			if got == nodeID {
				occurrences++
			}
		}
		require.Equal(t, 1, occurrences, "node %d must be synced exactly once", nodeID)
	}
	require.Zero(t, syncer.BeforeCommitCalls(),
		"node re-syncs must never be dispatched before the transaction commits")
}

// TestBatchUpdate_NoNodeSyncsOnRollback locks the other half of the guarantee:
// when the transaction rolls back, the node IDs collected during the abandoned
// work are never re-synced and no agent is notified.
func TestBatchUpdate_NoNodeSyncsOnRollback(t *testing.T) {
	ctx := context.Background()

	const groupID uint = 43
	nodeIDs := []uint{7, 9}

	agent := batchTestAgent(t, 1, "fa_batchagent12", "203.0.113.31", "10.0.0.31")
	agentRepo := testutil.NewMockForwardAgentRepository()
	agentRepo.AddAgent(agent)

	baseRepo := testutil.NewMockForwardRuleRepository()
	ruleA := batchNodeSyncsRule(t, "fr_000000000091", agent.ID(), 18091, groupID)
	ruleB := batchNodeSyncsRule(t, "fr_000000000092", agent.ID(), 18092, groupID)
	baseRepo.AddRule(ruleA)
	baseRepo.AddRule(ruleB)

	repo := &failNthUpdateRepo{
		MockForwardRuleRepository: baseRepo,
		succeedUpdate:             1,
		updateErr:                 errors.New("write conflict"),
	}

	syncer := &retargetRecordingNodeSyncer{}
	nodeRepo := &retargetGroupNodeRepo{groups: map[uint][]uint{groupID: nodeIDs}}
	notifier := testutil.NewMockConfigSyncNotifier()

	uc := batchNewUseCaseWithNodeSync(repo, agentRepo, notifier, nodeRepo, syncer, &rollbackTxRunner{})

	result, err := uc.BatchUpdate(ctx, BatchUpdateCommand{
		Updates: []BatchUpdateItem{
			{
				RuleSID:       ruleA.SID(),
				TargetAddress: batchStringPtr("10.9.9.1"),
				TargetPort:    batchUint16Ptr(9200),
			},
			{
				RuleSID:       ruleB.SID(),
				TargetAddress: batchStringPtr("10.9.9.2"),
				TargetPort:    batchUint16Ptr(9201),
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Succeeded, "a rolled back batch must not report successes")
	require.Len(t, result.Failed, 1)
	require.Equal(t, ruleB.SID(), result.Failed[0].ID)
	require.Equal(t, 2, repo.UpdateCalls(), "the failure really happened mid-way")

	time.Sleep(150 * time.Millisecond)
	require.Empty(t, syncer.NodeIDs(), "no node may be re-synced for a rolled back batch")
	require.Empty(t, notifier.GetCalls(), "no agent may be notified for a rolled back batch")
}
