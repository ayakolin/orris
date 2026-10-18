package usecases

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/domain/forward"
)

// listFixture bundles the mocks used by the list filter tests.
type listFixture struct {
	repo      *testutil.MockForwardRuleRepository
	agentRepo *testutil.MockForwardAgentRepository
	uc        *ListForwardRulesUseCase
	agent     *forward.ForwardAgent
}

func newListFixture(t *testing.T) *listFixture {
	t.Helper()

	repo := testutil.NewMockForwardRuleRepository()
	agentRepo := testutil.NewMockForwardAgentRepository()

	agent := batchTestAgent(t, 3, "fa_listagent001", "203.0.113.30", "10.0.0.30")
	agentRepo.AddAgent(agent)

	return &listFixture{
		repo:      repo,
		agentRepo: agentRepo,
		uc: NewListForwardRulesUseCase(
			repo,
			agentRepo,
			nil,
			nil,
			nil,
			testutil.NewMockLogger(),
		),
		agent: agent,
	}
}

func (f *listFixture) addRule(t *testing.T, rule *forward.ForwardRule) *forward.ForwardRule {
	t.Helper()
	f.repo.AddRule(rule)
	return rule
}

func TestListForwardRules_AgentSIDFilterResolvesInternalID(t *testing.T) {
	ctx := context.Background()
	fixture := newListFixture(t)

	other := batchTestAgent(t, 4, "fa_listagent002", "203.0.113.31", "10.0.0.31")
	fixture.agentRepo.AddAgent(other)

	matching := batchEnableRule(t, batchTestRule(t, "fr_000000000301", fixture.agent.ID(), 19101, "10.9.0.1", 443))
	notMatching := batchEnableRule(t, batchTestRule(t, "fr_000000000302", other.ID(), 19102, "10.9.0.1", 443))
	fixture.addRule(t, matching)
	fixture.addRule(t, notMatching)

	result, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page:     1,
		PageSize: 20,
		AgentSID: fixture.agent.SID(),
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), result.Total)
	require.Len(t, result.Rules, 1)
	require.Equal(t, matching.SID(), result.Rules[0].ID)
	require.Equal(t, fixture.agent.SID(), result.Rules[0].AgentID)
}

func TestListForwardRules_UnknownAgentSIDReturnsEmptyPage(t *testing.T) {
	ctx := context.Background()
	fixture := newListFixture(t)

	fixture.addRule(t, batchEnableRule(t, batchTestRule(t, "fr_000000000311", fixture.agent.ID(), 19111, "10.9.0.1", 443)))

	result, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page:     1,
		PageSize: 20,
		AgentSID: "fa_doesnotexist",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, int64(0), result.Total)
	require.Empty(t, result.Rules)
	require.Equal(t, 0, result.Pages)
}

func TestListForwardRules_TargetAddressExactMatchFilters(t *testing.T) {
	ctx := context.Background()
	fixture := newListFixture(t)

	matchA := batchEnableRule(t, batchTestRule(t, "fr_000000000321", fixture.agent.ID(), 19121, "10.9.1.1", 443))
	matchB := batchEnableRule(t, batchTestRule(t, "fr_000000000322", fixture.agent.ID(), 19122, "10.9.1.1", 8443))
	fixture.addRule(t, matchA)
	fixture.addRule(t, matchB)
	fixture.addRule(t, batchEnableRule(t, batchTestRule(t, "fr_000000000323", fixture.agent.ID(), 19123, "10.9.1.2", 443)))

	result, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page:          1,
		PageSize:      20,
		TargetAddress: "10.9.1.1",
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), result.Total)
	require.Len(t, result.Rules, 2)
	ids := []string{result.Rules[0].ID, result.Rules[1].ID}
	require.ElementsMatch(t, []string{matchA.SID(), matchB.SID()}, ids)
	for _, rule := range result.Rules {
		require.Equal(t, "10.9.1.1", rule.TargetAddress)
	}

	// A prefix of an existing address is not a match.
	partial, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page:          1,
		PageSize:      20,
		TargetAddress: "10.9.1",
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), partial.Total)
	require.Empty(t, partial.Rules)

	missing, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page:          1,
		PageSize:      20,
		TargetAddress: "10.9.9.9",
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), missing.Total)
	require.Empty(t, missing.Rules)
}

func TestListForwardRules_ExistingFiltersStillApply(t *testing.T) {
	ctx := context.Background()
	fixture := newListFixture(t)

	named := batchEnableRule(t, batchTestRule(t, "fr_000000000331", fixture.agent.ID(), 19131, "10.9.2.1", 443))
	require.NoError(t, named.UpdateName("target-name"))
	fixture.addRule(t, named)

	udpRule := batchEnableRule(t, batchTestRule(t, "fr_000000000332", fixture.agent.ID(), 19132, "10.9.2.2", 443))
	require.NoError(t, udpRule.UpdateProtocol("udp"))
	fixture.addRule(t, udpRule)

	disabled := batchTestRule(t, "fr_000000000333", fixture.agent.ID(), 19133, "10.9.2.3", 443)
	fixture.addRule(t, disabled)

	byName, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page: 1, PageSize: 20, Name: "target-name",
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), byName.Total)
	require.Len(t, byName.Rules, 1)
	require.Equal(t, named.SID(), byName.Rules[0].ID)

	byProtocol, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page: 1, PageSize: 20, Protocol: "udp",
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), byProtocol.Total)
	require.Len(t, byProtocol.Rules, 1)
	require.Equal(t, udpRule.SID(), byProtocol.Rules[0].ID)

	byStatus, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page: 1, PageSize: 20, Status: "disabled",
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), byStatus.Total)
	require.Len(t, byStatus.Rules, 1)
	require.Equal(t, disabled.SID(), byStatus.Rules[0].ID)
}

func TestListForwardRules_PageDefaultsAndSizeCapAreApplied(t *testing.T) {
	ctx := context.Background()
	fixture := newListFixture(t)

	for i := 0; i < 3; i++ {
		sid := []string{"fr_000000000341", "fr_000000000342", "fr_000000000343"}[i]
		fixture.addRule(t, batchEnableRule(t,
			batchTestRule(t, sid, fixture.agent.ID(), uint16(19141+i), "10.9.3.1", 443)))
	}

	defaults, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{})
	require.NoError(t, err)
	require.Equal(t, 1, defaults.Page)
	require.Equal(t, int64(3), defaults.Total)
	require.Len(t, defaults.Rules, 3)
	require.Equal(t, 1, defaults.Pages)

	// A page size above the cap is clamped to 100, so the page count stays 1.
	capped, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{PageSize: 500})
	require.NoError(t, err)
	require.Equal(t, 1, capped.Page)
	require.Equal(t, 1, capped.Pages)
	require.Len(t, capped.Rules, 3)

	secondPage, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{Page: 2, PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, 2, secondPage.Page)
	require.Equal(t, int64(3), secondPage.Total)
	require.Len(t, secondPage.Rules, 1)
	require.Equal(t, 2, secondPage.Pages)
}

func TestListForwardRules_AgentSIDAndTargetAddressCombine(t *testing.T) {
	ctx := context.Background()
	fixture := newListFixture(t)

	other := batchTestAgent(t, 4, "fa_listagent002", "203.0.113.31", "10.0.0.31")
	fixture.agentRepo.AddAgent(other)

	wanted := batchEnableRule(t, batchTestRule(t, "fr_000000000351", fixture.agent.ID(), 19151, "10.9.4.1", 443))
	fixture.addRule(t, wanted)
	fixture.addRule(t, batchEnableRule(t, batchTestRule(t, "fr_000000000352", other.ID(), 19152, "10.9.4.1", 443)))
	fixture.addRule(t, batchEnableRule(t, batchTestRule(t, "fr_000000000353", fixture.agent.ID(), 19153, "10.9.4.2", 443)))

	result, err := fixture.uc.Execute(ctx, ListForwardRulesQuery{
		Page:          1,
		PageSize:      20,
		AgentSID:      fixture.agent.SID(),
		TargetAddress: "10.9.4.1",
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), result.Total)
	require.Len(t, result.Rules, 1)
	require.Equal(t, wanted.SID(), result.Rules[0].ID)
}
