package usecases

import (
	"context"
	stderrors "errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/domain/node"
	sharederrors "github.com/orris-inc/orris/internal/shared/errors"
)

const (
	retargetFromAddress = "10.0.0.1"
	retargetToAddress   = "10.0.1.1"
)

func retargetUint16Ptr(v uint16) *uint16 { return &v }

func retargetExpectedTarget(address string, port uint16) string {
	return net.JoinHostPort(address, strconv.Itoa(int(port)))
}

// retargetOldTargets snapshots each rule's target before Execute runs. The mock
// repository stores the same pointers the tests hold, so reading a rule after a
// successful Execute would observe the retargeted value instead of the original.
func retargetOldTargets(rules ...*forward.ForwardRule) map[string]string {
	targets := make(map[string]string, len(rules))
	for _, rule := range rules {
		targets[rule.SID()] = retargetExpectedTarget(rule.TargetAddress(), rule.TargetPort())
	}
	return targets
}

// retargetPorts snapshots each rule's target port before Execute runs.
func retargetPorts(rules ...*forward.ForwardRule) map[string]uint16 {
	ports := make(map[string]uint16, len(rules))
	for _, rule := range rules {
		ports[rule.SID()] = rule.TargetPort()
	}
	return ports
}

// retargetTxRunner mirrors db.TransactionRunner so each test can plug in its own
// commit/rollback semantics.
type retargetTxRunner interface {
	RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// retargetFixtureOptions customises the fixture for tests that need to observe or
// replace individual collaborators.
type retargetFixtureOptions struct {
	txMgr        retargetTxRunner
	repo         *testutil.MockForwardRuleRepository // nil: fresh mock
	rulesRepo    forward.Repository                  // nil: repo
	wrapNotifier func(inner ConfigSyncNotifier) ConfigSyncNotifier
	syncer       NodeSubscriptionSyncer
	nodeRepo     node.NodeRepository
}

// retargetFixture bundles the mocks and use case used by the retarget tests.
type retargetFixture struct {
	repo      *testutil.MockForwardRuleRepository
	agentRepo *testutil.MockForwardAgentRepository
	notifier  *testutil.MockConfigSyncNotifier
	updateUC  *UpdateForwardRuleUseCase
	uc        *RetargetForwardRulesUseCase
}

func newRetargetFixture(t *testing.T, txMgr retargetTxRunner) *retargetFixture {
	t.Helper()
	return newRetargetFixtureWith(t, retargetFixtureOptions{txMgr: txMgr})
}

func newRetargetFixtureWith(t *testing.T, opts retargetFixtureOptions) *retargetFixture {
	t.Helper()

	repo := opts.repo
	if repo == nil {
		repo = testutil.NewMockForwardRuleRepository()
	}
	rulesRepo := opts.rulesRepo
	if rulesRepo == nil {
		rulesRepo = repo
	}

	agentRepo := testutil.NewMockForwardAgentRepository()
	notifier := testutil.NewMockConfigSyncNotifier()
	var notifySink ConfigSyncNotifier = notifier
	if opts.wrapNotifier != nil {
		notifySink = opts.wrapNotifier(notifier)
	}

	agent := batchTestAgent(t, 7, "fa_retargetagnt", "203.0.113.77", "10.0.0.77")
	agentRepo.AddAgent(agent)

	updateUC := NewUpdateForwardRuleUseCase(
		rulesRepo,
		agentRepo,
		opts.nodeRepo,
		nil,
		nil,
		nil,
		notifySink,
		testutil.NewMockLogger(),
	)
	if opts.syncer != nil {
		updateUC.SetNodeSubscriptionSyncer(opts.syncer)
	}

	return &retargetFixture{
		repo:      repo,
		agentRepo: agentRepo,
		notifier:  notifier,
		updateUC:  updateUC,
		uc: NewRetargetForwardRulesUseCase(
			rulesRepo,
			agentRepo,
			updateUC,
			opts.txMgr,
			testutil.NewMockLogger(),
		),
	}
}

func (f *retargetFixture) addRule(t *testing.T, rule *forward.ForwardRule) *forward.ForwardRule {
	t.Helper()
	f.repo.AddRule(rule)
	return rule
}

func (f *retargetFixture) mustRule(t *testing.T, sid string) *forward.ForwardRule {
	t.Helper()
	rule, err := f.repo.GetBySID(context.Background(), sid)
	require.NoError(t, err)
	require.NotNil(t, rule)
	return rule
}

// addRetargetRules creates the standard fixture: three enabled/disabled rules on
// the source address plus one rule pointing somewhere else.
func (f *retargetFixture) addRetargetRules(t *testing.T) (enabled443, disabled8443, enabled9443, other *forward.ForwardRule) {
	t.Helper()

	enabled443 = batchEnableRule(t, batchTestRule(t, "fr_000000000101", 7, 19001, retargetFromAddress, 443))
	disabled8443 = batchTestRule(t, "fr_000000000102", 7, 19002, retargetFromAddress, 8443)
	enabled9443 = batchEnableRule(t, batchTestRule(t, "fr_000000000103", 7, 19003, retargetFromAddress, 9443))
	other = batchEnableRule(t, batchTestRule(t, "fr_000000000104", 7, 19004, "10.0.0.2", 443))

	f.addRule(t, enabled443)
	f.addRule(t, disabled8443)
	f.addRule(t, enabled9443)
	f.addRule(t, other)

	return enabled443, disabled8443, enabled9443, other
}

func TestRetarget_DryRunReportsWithoutWriting(t *testing.T) {
	ctx := context.Background()
	fixture := newRetargetFixture(t, &directTxRunner{})
	rule443, rule8443, rule9443, other := fixture.addRetargetRules(t)
	oldTargets := retargetOldTargets(rule443, rule8443, rule9443, other)
	oldPorts := retargetPorts(rule443, rule8443, rule9443, other)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
		DryRun:      true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.DryRun)
	require.Equal(t, retargetFromAddress, result.From)
	require.Equal(t, retargetToAddress, result.To)
	require.Nil(t, result.ToPort)
	require.Equal(t, 3, result.Matched)
	require.Len(t, result.Affected, 3)

	byID := make(map[string]RetargetRuleResult, len(result.Affected))
	for _, entry := range result.Affected {
		byID[entry.ID] = entry
	}

	for _, rule := range []*forward.ForwardRule{rule443, rule8443, rule9443} {
		entry, ok := byID[rule.SID()]
		require.True(t, ok, "missing affected entry for %s", rule.SID())
		require.Equal(t, rule.Name(), entry.Name)
		require.Equal(t, "fa_retargetagnt", entry.AgentID)
		require.Equal(t, oldTargets[rule.SID()], entry.OldTarget)
		require.Equal(t, retargetExpectedTarget(retargetToAddress, oldPorts[rule.SID()]), entry.NewTarget)
		require.Equal(t, rule.Status().String(), entry.Status)
		require.Equal(t, rule.IsEnabled(), entry.WillSync)
	}

	require.False(t, byID[rule8443.SID()].WillSync)
	require.True(t, byID[rule443.SID()].WillSync)
	require.True(t, byID[rule9443.SID()].WillSync)
	_, otherAffected := byID[other.SID()]
	require.False(t, otherAffected)

	// Nothing was written and no agent was told to reload.
	for _, rule := range []*forward.ForwardRule{rule443, rule8443, rule9443, other} {
		stored := fixture.mustRule(t, rule.SID())
		require.Equal(t, oldTargets[rule.SID()], retargetExpectedTarget(stored.TargetAddress(), stored.TargetPort()))
	}
	require.Empty(t, fixture.notifier.GetCalls())
}

func TestRetarget_DryRunWithRuleIDsReportsSubset(t *testing.T) {
	ctx := context.Background()
	fixture := newRetargetFixture(t, &directTxRunner{})
	rule443, _, rule9443, _ := fixture.addRetargetRules(t)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
		RuleSIDs:    []string{rule443.SID(), rule9443.SID()},
		DryRun:      true,
	})
	require.NoError(t, err)
	require.Equal(t, 2, result.Matched)
	require.Len(t, result.Affected, 2)

	ids := []string{result.Affected[0].ID, result.Affected[1].ID}
	require.ElementsMatch(t, []string{rule443.SID(), rule9443.SID()}, ids)

	require.Empty(t, fixture.notifier.GetCalls())
}

func TestRetarget_RealRunKeepsExistingPortsWhenToPortIsNil(t *testing.T) {
	ctx := context.Background()
	fixture := newRetargetFixture(t, &directTxRunner{})
	rule443, rule8443, rule9443, other := fixture.addRetargetRules(t)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
	})
	require.NoError(t, err)
	require.False(t, result.DryRun)
	require.Equal(t, 3, result.Matched)
	require.Len(t, result.Affected, 3)

	wantPorts := map[string]uint16{
		rule443.SID():  443,
		rule8443.SID(): 8443,
		rule9443.SID(): 9443,
	}
	for sid, wantPort := range wantPorts {
		stored := fixture.mustRule(t, sid)
		require.Equal(t, retargetToAddress, stored.TargetAddress())
		require.Equal(t, wantPort, stored.TargetPort())
	}

	storedOther := fixture.mustRule(t, other.SID())
	require.Equal(t, "10.0.0.2", storedOther.TargetAddress())
	require.Equal(t, uint16(443), storedOther.TargetPort())

	// Only enabled rules notify, and every notification is an "updated" push.
	calls := waitForNotifyCalls(t, fixture.notifier, 2)
	require.Len(t, calls, 2)
	for _, call := range calls {
		require.Equal(t, "updated", call.ChangeType)
		require.Equal(t, uint(7), call.AgentID)
	}
	require.Len(t, notifyCallsWith(calls, rule8443.SID(), "updated"), 0)
	require.Len(t, notifyCallsWith(calls, rule443.SID(), "updated"), 1)
	require.Len(t, notifyCallsWith(calls, rule9443.SID(), "updated"), 1)
}

func TestRetarget_RealRunAppliesProvidedPort(t *testing.T) {
	ctx := context.Background()
	fixture := newRetargetFixture(t, &directTxRunner{})
	rule443, rule8443, rule9443, _ := fixture.addRetargetRules(t)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
		ToPort:      retargetUint16Ptr(10443),
	})
	require.NoError(t, err)
	require.NotNil(t, result.ToPort)
	require.Equal(t, uint16(10443), *result.ToPort)

	for _, rule := range []*forward.ForwardRule{rule443, rule8443, rule9443} {
		stored := fixture.mustRule(t, rule.SID())
		require.Equal(t, retargetToAddress, stored.TargetAddress())
		require.Equal(t, uint16(10443), stored.TargetPort())
	}

	affectedByID := make(map[string]RetargetRuleResult, len(result.Affected))
	for _, entry := range result.Affected {
		affectedByID[entry.ID] = entry
	}
	originalPorts := map[string]uint16{
		rule443.SID():  443,
		rule8443.SID(): 8443,
		rule9443.SID(): 9443,
	}
	for sid, oldPort := range originalPorts {
		entry, ok := affectedByID[sid]
		require.True(t, ok)
		require.Equal(t, retargetExpectedTarget(retargetFromAddress, oldPort), entry.OldTarget)
		require.Equal(t, retargetExpectedTarget(retargetToAddress, 10443), entry.NewTarget)
	}

	waitForNotifyCalls(t, fixture.notifier, 2)
}

func TestRetarget_RuleIDsRestrictsChanges(t *testing.T) {
	ctx := context.Background()
	fixture := newRetargetFixture(t, &directTxRunner{})
	rule443, rule8443, rule9443, other := fixture.addRetargetRules(t)

	// The rule on another address is explicitly listed but must stay untouched.
	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
		RuleSIDs:    []string{rule443.SID(), other.SID()},
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.Matched)

	stored443 := fixture.mustRule(t, rule443.SID())
	require.Equal(t, retargetToAddress, stored443.TargetAddress())
	require.Equal(t, uint16(443), stored443.TargetPort())

	storedOther := fixture.mustRule(t, other.SID())
	require.Equal(t, "10.0.0.2", storedOther.TargetAddress())

	stored8443 := fixture.mustRule(t, rule8443.SID())
	require.Equal(t, retargetFromAddress, stored8443.TargetAddress())

	stored9443 := fixture.mustRule(t, rule9443.SID())
	require.Equal(t, retargetFromAddress, stored9443.TargetAddress())

	calls := waitForNotifyCalls(t, fixture.notifier, 1)
	require.Len(t, calls, 1)
	require.Equal(t, rule443.SID(), calls[0].RuleShortID)
	require.Equal(t, "updated", calls[0].ChangeType)
}

func TestRetarget_NeverMatchesNodeLinkedRules(t *testing.T) {
	ctx := context.Background()
	fixture := newRetargetFixture(t, &directTxRunner{})
	rule443, _, _, _ := fixture.addRetargetRules(t)

	nodeID := uint(99)
	nodeLinked := batchEnableRule(t, batchTestNodeLinkedRule(t, "fr_000000000201", 7, 19021, nodeID))
	fixture.addRule(t, nodeLinked)
	require.NotNil(t, nodeLinked.TargetNodeID())

	// Setting a static address on the node-linked rule is not part of this test;
	// the rule must simply be skipped because its target is a node.
	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
	})
	require.NoError(t, err)
	require.Equal(t, 3, result.Matched)
	for _, entry := range result.Affected {
		require.NotEqual(t, nodeLinked.SID(), entry.ID)
	}

	stored := fixture.mustRule(t, nodeLinked.SID())
	require.NotNil(t, stored.TargetNodeID())
	require.Equal(t, nodeID, *stored.TargetNodeID())

	stored443 := fixture.mustRule(t, rule443.SID())
	require.Equal(t, retargetToAddress, stored443.TargetAddress())
}

func TestRetarget_ValidationErrors(t *testing.T) {
	testCases := []struct {
		name string
		cmd  RetargetCommand
	}{
		{
			name: "empty from_address",
			cmd:  RetargetCommand{FromAddress: "", ToAddress: retargetToAddress},
		},
		{
			name: "empty to_address",
			cmd:  RetargetCommand{FromAddress: retargetFromAddress, ToAddress: ""},
		},
		{
			name: "invalid to_address",
			cmd:  RetargetCommand{FromAddress: retargetFromAddress, ToAddress: "invalid..address"},
		},
		{
			name: "identical addresses without to_port",
			cmd:  RetargetCommand{FromAddress: retargetFromAddress, ToAddress: retargetFromAddress},
		},
		{
			name: "invalid rule_id format",
			cmd: RetargetCommand{
				FromAddress: retargetFromAddress,
				ToAddress:   retargetToAddress,
				RuleSIDs:    []string{"not-a-rule-id"},
			},
		},
		{
			name: "to_port zero",
			cmd: RetargetCommand{
				FromAddress: retargetFromAddress,
				ToAddress:   retargetToAddress,
				ToPort:      retargetUint16Ptr(0),
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newRetargetFixture(t, &directTxRunner{})
			fixture.addRetargetRules(t)

			result, err := fixture.uc.Execute(context.Background(), testCase.cmd)
			require.Error(t, err)
			require.Nil(t, result)

			appErr := sharederrors.GetAppError(err)
			require.NotNil(t, appErr, "expected app error, got %v", err)
			require.Equal(t, 400, appErr.Code)

			require.Empty(t, fixture.notifier.GetCalls())
		})
	}
}

func TestRetarget_SameAddressRequiresPortChange(t *testing.T) {
	t.Run("without to_port is rejected", func(t *testing.T) {
		ctx := context.Background()
		fixture := newRetargetFixture(t, &directTxRunner{})
		rule443, rule8443, rule9443, other := fixture.addRetargetRules(t)
		oldTargets := retargetOldTargets(rule443, rule8443, rule9443, other)

		result, err := fixture.uc.Execute(ctx, RetargetCommand{
			FromAddress: retargetFromAddress,
			ToAddress:   retargetFromAddress,
		})
		require.Error(t, err)
		require.Nil(t, result)

		appErr := sharederrors.GetAppError(err)
		require.NotNil(t, appErr, "expected app error, got %v", err)
		require.Equal(t, 400, appErr.Code)

		for _, rule := range []*forward.ForwardRule{rule443, rule8443, rule9443, other} {
			stored := fixture.mustRule(t, rule.SID())
			require.Equal(t, oldTargets[rule.SID()],
				retargetExpectedTarget(stored.TargetAddress(), stored.TargetPort()))
		}
		require.Empty(t, fixture.notifier.GetCalls())
		time.Sleep(150 * time.Millisecond)
		require.Empty(t, fixture.notifier.GetCalls())
	})

	t.Run("with the rules' current port is rejected", func(t *testing.T) {
		ctx := context.Background()
		fixture := newRetargetFixture(t, &directTxRunner{})
		rule := batchEnableRule(t, batchTestRule(t, "fr_000000000301", 7, 19301, retargetFromAddress, 443))
		fixture.addRule(t, rule)
		oldTarget := retargetExpectedTarget(rule.TargetAddress(), rule.TargetPort())

		result, err := fixture.uc.Execute(ctx, RetargetCommand{
			FromAddress: retargetFromAddress,
			ToAddress:   retargetFromAddress,
			ToPort:      retargetUint16Ptr(443),
		})
		require.Error(t, err)
		require.Nil(t, result)

		appErr := sharederrors.GetAppError(err)
		require.NotNil(t, appErr, "expected app error, got %v", err)
		require.Equal(t, 400, appErr.Code)
		require.Contains(t, appErr.Message, "nothing to retarget")

		stored := fixture.mustRule(t, rule.SID())
		require.Equal(t, oldTarget, retargetExpectedTarget(stored.TargetAddress(), stored.TargetPort()))
		require.Empty(t, fixture.notifier.GetCalls())
		time.Sleep(150 * time.Millisecond)
		require.Empty(t, fixture.notifier.GetCalls())
	})

	t.Run("with a new port rewrites every rule", func(t *testing.T) {
		ctx := context.Background()
		fixture := newRetargetFixture(t, &directTxRunner{})
		rule443, rule8443, rule9443, other := fixture.addRetargetRules(t)

		result, err := fixture.uc.Execute(ctx, RetargetCommand{
			FromAddress: retargetFromAddress,
			ToAddress:   retargetFromAddress,
			ToPort:      retargetUint16Ptr(10443),
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 3, result.Matched)
		require.Len(t, result.Affected, 3)
		require.NotNil(t, result.ToPort)
		require.Equal(t, uint16(10443), *result.ToPort)

		for _, rule := range []*forward.ForwardRule{rule443, rule8443, rule9443} {
			stored := fixture.mustRule(t, rule.SID())
			require.Equal(t, retargetFromAddress, stored.TargetAddress())
			require.Equal(t, uint16(10443), stored.TargetPort())
		}
		// The rule on another address is never part of the retarget.
		storedOther := fixture.mustRule(t, other.SID())
		require.Equal(t, "10.0.0.2", storedOther.TargetAddress())
		require.Equal(t, uint16(443), storedOther.TargetPort())

		calls := waitForNotifyCalls(t, fixture.notifier, 2)
		for _, rule := range []*forward.ForwardRule{rule443, rule9443} {
			require.Len(t, notifyCallsWith(calls, rule.SID(), "updated"), 1)
		}
		require.Len(t, notifyCallsWith(calls, rule8443.SID(), "updated"), 0)
	})
}

// TestRetarget_RollbackSuppressesSideEffects covers rollback control flow.
// The mock repository has no transactional storage, so these cases prove that a
// failed transaction suppresses every post-commit side effect (agent pushes and
// node re-syncs) and propagates the error; they do not prove that rows were
// restored, which is the database's responsibility.
func TestRetarget_RollbackSuppressesSideEffects(t *testing.T) {
	t.Run("transaction fails before the callback runs", func(t *testing.T) {
		ctx := context.Background()
		fixture := newRetargetFixture(t, &failingTxRunner{})
		rule443, rule8443, rule9443, other := fixture.addRetargetRules(t)
		oldTargets := retargetOldTargets(rule443, rule8443, rule9443, other)

		result, err := fixture.uc.Execute(ctx, RetargetCommand{
			FromAddress: retargetFromAddress,
			ToAddress:   retargetToAddress,
		})
		require.Error(t, err)
		require.Nil(t, result)

		for _, rule := range []*forward.ForwardRule{rule443, rule8443, rule9443, other} {
			stored := fixture.mustRule(t, rule.SID())
			require.Equal(t, oldTargets[rule.SID()],
				retargetExpectedTarget(stored.TargetAddress(), stored.TargetPort()))
		}

		time.Sleep(150 * time.Millisecond)
		require.Empty(t, fixture.notifier.GetCalls())
	})

	t.Run("transaction rolls back after the callback ran", func(t *testing.T) {
		ctx := context.Background()
		var committed atomic.Bool
		syncer := &retargetRecordingNodeSyncer{committed: &committed}
		fixture := newRetargetFixtureWith(t, retargetFixtureOptions{
			txMgr:    &rollbackTxRunner{},
			syncer:   syncer,
			nodeRepo: &retargetGroupNodeRepo{groups: map[uint][]uint{retargetGroupID: {7, 9}}},
		})
		rule443, _, _, _ := fixture.addRetargetRules(t)
		rule443.SetGroupIDs([]uint{retargetGroupID})

		result, err := fixture.uc.Execute(ctx, RetargetCommand{
			FromAddress: retargetFromAddress,
			ToAddress:   retargetToAddress,
		})
		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorContains(t, err, "transaction rolled back")

		// The rollback must suppress every post-commit side effect.
		time.Sleep(150 * time.Millisecond)
		require.Empty(t, fixture.notifier.GetCalls())
		require.Empty(t, syncer.NodeIDs())
		require.Zero(t, syncer.BeforeCommitCalls())
	})

	t.Run("a write fails midway through the batch", func(t *testing.T) {
		ctx := context.Background()
		mockRepo := testutil.NewMockForwardRuleRepository()
		repo := &retargetFailingUpdateRepo{
			MockForwardRuleRepository: mockRepo,
			failOn:                    2,
		}
		var committed atomic.Bool
		syncer := &retargetRecordingNodeSyncer{committed: &committed}
		fixture := newRetargetFixtureWith(t, retargetFixtureOptions{
			txMgr:     &rollbackTxRunner{},
			repo:      mockRepo,
			rulesRepo: repo,
			syncer:    syncer,
			nodeRepo:  &retargetGroupNodeRepo{groups: map[uint][]uint{retargetGroupID: {7, 9}}},
		})
		rule443, rule8443, rule9443, _ := fixture.addRetargetRules(t)
		rule443.SetGroupIDs([]uint{retargetGroupID})
		rule8443.SetGroupIDs([]uint{retargetGroupID})
		rule9443.SetGroupIDs([]uint{retargetGroupID})

		result, err := fixture.uc.Execute(ctx, RetargetCommand{
			FromAddress: retargetFromAddress,
			ToAddress:   retargetToAddress,
		})
		require.Error(t, err)
		require.Nil(t, result)
		// The failure of the second write aborts the batch and is propagated.
		require.ErrorIs(t, err, errRetargetWriteFailed)
		require.ErrorContains(t, err, "failed to retarget rule "+rule8443.SID())
		require.Equal(t, 2, repo.UpdateCalls())

		// Nothing is flushed when the transaction does not commit.
		time.Sleep(150 * time.Millisecond)
		require.Empty(t, fixture.notifier.GetCalls())
		require.Empty(t, syncer.NodeIDs())
	})
}

func TestRetarget_ConcurrentEditAbortsWithConflict(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(t *testing.T, fixture *retargetFixture, target *forward.ForwardRule)
		verify func(t *testing.T, rule *forward.ForwardRule)
	}{
		{
			name: "target address changed concurrently",
			mutate: func(t *testing.T, fixture *retargetFixture, target *forward.ForwardRule) {
				t.Helper()
				require.NoError(t, target.UpdateTarget("10.9.9.9", target.TargetPort()))
				// Persist the concurrent edit like another request committing first.
				require.NoError(t, fixture.repo.Update(context.Background(), target))
			},
			verify: func(t *testing.T, rule *forward.ForwardRule) {
				t.Helper()
				require.Equal(t, "10.9.9.9", rule.TargetAddress())
				require.Equal(t, uint16(443), rule.TargetPort())
			},
		},
		{
			name: "target port changed concurrently",
			mutate: func(t *testing.T, fixture *retargetFixture, target *forward.ForwardRule) {
				t.Helper()
				require.NoError(t, target.UpdateTarget(retargetFromAddress, 8443))
				require.NoError(t, fixture.repo.Update(context.Background(), target))
			},
			verify: func(t *testing.T, rule *forward.ForwardRule) {
				t.Helper()
				require.Equal(t, retargetFromAddress, rule.TargetAddress())
				require.Equal(t, uint16(8443), rule.TargetPort())
			},
		},
		{
			name: "rule linked to a node concurrently",
			mutate: func(t *testing.T, fixture *retargetFixture, target *forward.ForwardRule) {
				t.Helper()
				nodeID := uint(77)
				nodeLinked := batchEnableRule(t, batchTestNodeLinkedRule(
					t, target.SID(), target.AgentID(), target.ListenPort(), nodeID))
				// Same SID, different row: the locking read returns the node-linked rule.
				fixture.repo.AddRule(nodeLinked)
			},
			verify: func(t *testing.T, rule *forward.ForwardRule) {
				t.Helper()
				require.NotNil(t, rule.TargetNodeID())
				require.Equal(t, uint(77), *rule.TargetNodeID())
				require.Empty(t, rule.TargetAddress())
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			var fixture *retargetFixture
			fixture = newRetargetFixture(t, &retargetMutatingTxRunner{mutate: func(ctx context.Context) {
				testCase.mutate(t, fixture, fixture.mustRule(t, "fr_000000000101"))
			}})
			rule443, _, _, _ := fixture.addRetargetRules(t)
			require.NotNil(t, rule443)

			result, err := fixture.uc.Execute(ctx, RetargetCommand{
				FromAddress: retargetFromAddress,
				ToAddress:   retargetToAddress,
			})
			require.Error(t, err)
			require.Nil(t, result)

			appErr := sharederrors.GetAppError(err)
			require.NotNil(t, appErr, "expected app error, got %v", err)
			require.Equal(t, 409, appErr.Code)

			// No rule was rewritten to the new target and no agent was notified.
			for _, rule := range []*forward.ForwardRule{
				fixture.mustRule(t, "fr_000000000101"),
				fixture.mustRule(t, "fr_000000000102"),
				fixture.mustRule(t, "fr_000000000103"),
			} {
				require.NotEqual(t, retargetToAddress, rule.TargetAddress())
			}
			testCase.verify(t, fixture.mustRule(t, "fr_000000000101"))

			time.Sleep(150 * time.Millisecond)
			require.Empty(t, fixture.notifier.GetCalls())
		})
	}
}

// TestRetarget_ResponseReflectsConcurrentDisable covers response fidelity: a rule
// disabled between selection and the transaction is still retargeted (the target
// change is valid), but the response must report the state that was applied under
// the row lock and must not claim a push that will not happen.
func TestRetarget_ResponseReflectsConcurrentDisable(t *testing.T) {
	ctx := context.Background()

	var fixture *retargetFixture
	fixture = newRetargetFixture(t, &retargetMutatingTxRunner{mutate: func(ctx context.Context) {
		rule := fixture.mustRule(t, "fr_000000000101")
		require.NoError(t, rule.Disable())
		require.NoError(t, fixture.repo.Update(ctx, rule))
	}})
	fixture.addRetargetRules(t)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// The retarget itself applied to every matched rule.
	for _, sid := range []string{"fr_000000000101", "fr_000000000102", "fr_000000000103"} {
		stored := fixture.mustRule(t, sid)
		require.Equal(t, retargetToAddress, stored.TargetAddress())
	}

	byID := make(map[string]RetargetRuleResult, len(result.Affected))
	for _, entry := range result.Affected {
		byID[entry.ID] = entry
	}
	disabled, ok := byID["fr_000000000101"]
	require.True(t, ok)
	require.Equal(t, "disabled", disabled.Status, "status must come from the applied state")
	require.False(t, disabled.WillSync, "a disabled rule is not pushed")

	// Only the still-enabled rule is pushed.
	require.Eventually(t, func() bool {
		return len(fixture.notifier.GetCalls()) >= 1
	}, 2*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	calls := fixture.notifier.GetCalls()
	require.Len(t, notifyCallsWith(calls, "fr_000000000101", "updated"), 0,
		"a rule disabled during the transaction must not be pushed")
	require.Len(t, notifyCallsWith(calls, "fr_000000000103", "updated"), 1)
}

func TestRetarget_NotificationsAreDispatchedOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	var committed atomic.Bool
	notifier := &retargetCommitAwareNotifier{
		inner:     testutil.NewMockConfigSyncNotifier(),
		committed: &committed,
	}

	fixture := newRetargetFixtureWith(t, retargetFixtureOptions{
		txMgr:        &retargetCommitFlagRunner{committed: &committed},
		wrapNotifier: func(ConfigSyncNotifier) ConfigSyncNotifier { return notifier },
	})
	rule443, _, rule9443, _ := fixture.addRetargetRules(t)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, committed.Load(), "the runner must report a commit")

	require.Eventually(t, func() bool {
		return len(notifier.Calls()) >= 2
	}, 2*time.Second, 10*time.Millisecond)
	require.Zero(t, notifier.BeforeCommitCalls(),
		"notifications must never be emitted before the transaction commits")

	calls := notifier.Calls()
	require.Len(t, calls, 2)
	for _, rule := range []*forward.ForwardRule{rule443, rule9443} {
		require.Len(t, notifyCallsWith(calls, rule.SID(), "updated"), 1)
	}
}

func TestRetarget_NodeSyncsAreDispatchedOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	var committed atomic.Bool
	syncer := &retargetRecordingNodeSyncer{committed: &committed}

	fixture := newRetargetFixtureWith(t, retargetFixtureOptions{
		txMgr:    &retargetCommitFlagRunner{committed: &committed},
		syncer:   syncer,
		nodeRepo: &retargetGroupNodeRepo{groups: map[uint][]uint{retargetGroupID: {7, 9}}},
	})
	rule443, _, rule9443, _ := fixture.addRetargetRules(t)
	rule443.SetGroupIDs([]uint{retargetGroupID})
	rule9443.SetGroupIDs([]uint{retargetGroupID})

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Eventually(t, func() bool {
		return len(syncer.NodeIDs()) >= 2
	}, 2*time.Second, 10*time.Millisecond)
	require.ElementsMatch(t, []uint{7, 9}, syncer.NodeIDs())
	require.Zero(t, syncer.BeforeCommitCalls(),
		"node subscriptions must never be re-synced before the transaction commits")
	require.Equal(t, 2, len(syncer.NodeIDs()), "each affected node is re-synced exactly once")
}

func TestRetarget_DirectRulesDoNotTriggerNodeSyncs(t *testing.T) {
	ctx := context.Background()
	var committed atomic.Bool
	syncer := &retargetRecordingNodeSyncer{committed: &committed}

	fixture := newRetargetFixtureWith(t, retargetFixtureOptions{
		txMgr:    &retargetCommitFlagRunner{committed: &committed},
		syncer:   syncer,
		nodeRepo: &retargetGroupNodeRepo{groups: map[uint][]uint{retargetGroupID: {7, 9}}},
	})
	fixture.addRetargetRules(t)

	result, err := fixture.uc.Execute(ctx, RetargetCommand{
		FromAddress: retargetFromAddress,
		ToAddress:   retargetToAddress,
	})
	require.NoError(t, err)
	require.Equal(t, 3, result.Matched)

	waitForNotifyCalls(t, fixture.notifier, 2)
	time.Sleep(150 * time.Millisecond)
	require.Empty(t, syncer.NodeIDs(), "a rule without groups or target node affects no node")
}

// TestRetarget_CollectorFlushesNodeSyncsOnceEach covers the collector contract the
// retarget use case relies on for its post-commit node re-syncs.
func TestRetarget_CollectorFlushesNodeSyncsOnceEach(t *testing.T) {
	_, collector := WithDeferredRuleNotifications(context.Background())
	collector.addNodeSyncs(7, 7, 9)
	require.Equal(t, []uint{7, 9}, collector.NodeIDs())

	syncer := &retargetRecordingNodeSyncer{}
	collector.FlushNodeSyncs(syncer, testutil.NewMockLogger())

	require.Eventually(t, func() bool {
		return len(syncer.NodeIDs()) >= 2
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, []uint{7, 9}, syncer.NodeIDs())
}

// --- test doubles -----------------------------------------------------------

const retargetGroupID = uint(42)

var errRetargetWriteFailed = stderrors.New("simulated update failure")

// rollbackTxRunner already lives in batchforwardrule_test.go: it runs the callback
// and then reports an error, which is exactly what a rolled back commit looks like.

// retargetMutatingTxRunner simulates a concurrent commit that lands after the
// rules were selected but before they are re-read under the row lock.
type retargetMutatingTxRunner struct {
	mutate func(ctx context.Context)
}

func (r *retargetMutatingTxRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if r.mutate != nil {
		r.mutate(ctx)
	}
	return fn(ctx)
}

// retargetCommitFlagRunner flips committed after the callback succeeds, so side
// effects can assert they only ran on committed state.
type retargetCommitFlagRunner struct {
	committed *atomic.Bool
}

func (r *retargetCommitFlagRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := fn(ctx); err != nil {
		return err
	}
	r.committed.Store(true)
	return nil
}

// retargetFailingUpdateRepo fails the Nth Update call while delegating everything
// else (including the row-locking read) to the mock repository.
type retargetFailingUpdateRepo struct {
	*testutil.MockForwardRuleRepository

	failOn int

	mu          sync.Mutex
	updateCalls int
}

func (r *retargetFailingUpdateRepo) Update(ctx context.Context, rule *forward.ForwardRule) error {
	r.mu.Lock()
	r.updateCalls++
	calls := r.updateCalls
	r.mu.Unlock()

	if calls == r.failOn {
		return errRetargetWriteFailed
	}
	return r.MockForwardRuleRepository.Update(ctx, rule)
}

// UpdateCalls reports how many Update calls reached the repository.
func (r *retargetFailingUpdateRepo) UpdateCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.updateCalls
}

// retargetCommitAwareNotifier records whether a push happened before the
// transaction was reported as committed.
type retargetCommitAwareNotifier struct {
	inner     ConfigSyncNotifier
	committed *atomic.Bool

	mu           sync.Mutex
	beforeCommit int
}

func (n *retargetCommitAwareNotifier) NotifyRuleChange(ctx context.Context, agentID uint, ruleShortID string, changeType string) error {
	if n.committed != nil && !n.committed.Load() {
		n.mu.Lock()
		n.beforeCommit++
		n.mu.Unlock()
	}

	return n.inner.NotifyRuleChange(ctx, agentID, ruleShortID, changeType)
}

func (n *retargetCommitAwareNotifier) BeforeCommitCalls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.beforeCommit
}

func (n *retargetCommitAwareNotifier) Calls() []testutil.NotifyCall {
	if inner, ok := n.inner.(*testutil.MockConfigSyncNotifier); ok {
		return inner.GetCalls()
	}
	return nil
}

// retargetRecordingNodeSyncer records node re-syncs and how many happened before
// the commit flag was raised.
type retargetRecordingNodeSyncer struct {
	committed *atomic.Bool // nil: ordering is not checked

	mu           sync.Mutex
	nodeIDs      []uint
	beforeCommit int
}

func (s *retargetRecordingNodeSyncer) SyncSubscriptionsToNode(ctx context.Context, nodeID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.committed != nil && !s.committed.Load() {
		s.beforeCommit++
	}
	s.nodeIDs = append(s.nodeIDs, nodeID)
	return nil
}

func (s *retargetRecordingNodeSyncer) NodeIDs() []uint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint(nil), s.nodeIDs...)
}

func (s *retargetRecordingNodeSyncer) BeforeCommitCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.beforeCommit
}

// retargetGroupNodeRepo implements just the lookup collectAffectedNodeIDs needs;
// the embedded interface keeps the unused methods out of the test.
type retargetGroupNodeRepo struct {
	node.NodeRepository

	groups map[uint][]uint
}

func (r *retargetGroupNodeRepo) GetIDsByGroupID(ctx context.Context, groupID uint) ([]uint, error) {
	return append([]uint(nil), r.groups[groupID]...), nil
}
