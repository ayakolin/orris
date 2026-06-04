package usecases

import (
	"context"
	"testing"

	"github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/domain/forward"
	vo "github.com/orris-inc/orris/internal/domain/forward/valueobjects"
	sharederrors "github.com/orris-inc/orris/internal/shared/errors"
)

func TestUpdateForwardRule_AllowsSamePortOnSameAgentWhenListenIPDiffers(t *testing.T) {
	ctx := context.Background()

	ruleRepo := testutil.NewMockForwardRuleRepository()
	agentRepo := testutil.NewMockForwardAgentRepository()

	oldAgent := mustTestAgent(t, 1, "fa_oldagent", "203.0.113.10", "10.0.0.10")
	targetAgent := mustTestAgent(t, 2, "fa_targetagent", "203.0.113.20", "10.0.0.20")
	agentRepo.AddAgent(oldAgent)
	agentRepo.AddAgent(targetAgent)

	existingPublicRule := mustTestRule(t, "fr_existing", targetAgent.ID(), 18080, "127.0.0.1")
	ruleRepo.AddRule(existingPublicRule)

	ruleToMove := mustTestRule(t, "fr_move", oldAgent.ID(), 18080, "127.0.0.1")
	ruleRepo.AddRule(ruleToMove)

	targetAgentSID := targetAgent.SID()
	listenIP := "127.0.0.2"
	uc := NewUpdateForwardRuleUseCase(
		ruleRepo,
		agentRepo,
		nil,
		nil,
		nil,
		nil,
		nil,
		testutil.NewMockLogger(),
	)

	err := uc.Execute(ctx, UpdateForwardRuleCommand{
		ShortID:      ruleToMove.SID(),
		AgentShortID: &targetAgentSID,
		ListenIP:     &listenIP,
	})
	if err != nil {
		t.Fatalf("expected update to allow same port on different listen IP, got error: %v", err)
	}
}

func TestUpdateForwardRule_RejectsSamePortOnSameAgentWhenListenIPMatches(t *testing.T) {
	ctx := context.Background()

	ruleRepo := testutil.NewMockForwardRuleRepository()
	agentRepo := testutil.NewMockForwardAgentRepository()

	oldAgent := mustTestAgent(t, 1, "fa_oldagent", "203.0.113.10", "10.0.0.10")
	targetAgent := mustTestAgent(t, 2, "fa_targetagent", "203.0.113.20", "10.0.0.20")
	agentRepo.AddAgent(oldAgent)
	agentRepo.AddAgent(targetAgent)

	existingPublicRule := mustTestRule(t, "fr_existing", targetAgent.ID(), 18080, "127.0.0.1")
	ruleRepo.AddRule(existingPublicRule)

	ruleToMove := mustTestRule(t, "fr_move", oldAgent.ID(), 18080, "127.0.0.2")
	ruleRepo.AddRule(ruleToMove)

	targetAgentSID := targetAgent.SID()
	listenIP := "127.0.0.1"
	uc := NewUpdateForwardRuleUseCase(
		ruleRepo,
		agentRepo,
		nil,
		nil,
		nil,
		nil,
		nil,
		testutil.NewMockLogger(),
	)

	err := uc.Execute(ctx, UpdateForwardRuleCommand{
		ShortID:      ruleToMove.SID(),
		AgentShortID: &targetAgentSID,
		ListenIP:     &listenIP,
	})
	if err == nil {
		t.Fatal("expected conflict when same port uses the same listen IP")
	}
	if !sharederrors.IsConflictError(err) {
		t.Fatalf("expected conflict error, got: %v", err)
	}
}

func TestUpdateForwardRule_RejectsSamePortOnSameAgentWhenExistingListenIPIsWildcard(t *testing.T) {
	ctx := context.Background()

	ruleRepo := testutil.NewMockForwardRuleRepository()
	agentRepo := testutil.NewMockForwardAgentRepository()

	oldAgent := mustTestAgent(t, 1, "fa_oldagent", "203.0.113.10", "10.0.0.10")
	targetAgent := mustTestAgent(t, 2, "fa_targetagent", "203.0.113.20", "10.0.0.20")
	agentRepo.AddAgent(oldAgent)
	agentRepo.AddAgent(targetAgent)

	existingWildcardRule := mustTestRule(t, "fr_existing", targetAgent.ID(), 18080, "")
	ruleRepo.AddRule(existingWildcardRule)

	ruleToMove := mustTestRule(t, "fr_move", oldAgent.ID(), 18080, "127.0.0.2")
	ruleRepo.AddRule(ruleToMove)

	targetAgentSID := targetAgent.SID()
	listenIP := "127.0.0.1"
	uc := NewUpdateForwardRuleUseCase(
		ruleRepo,
		agentRepo,
		nil,
		nil,
		nil,
		nil,
		nil,
		testutil.NewMockLogger(),
	)

	err := uc.Execute(ctx, UpdateForwardRuleCommand{
		ShortID:      ruleToMove.SID(),
		AgentShortID: &targetAgentSID,
		ListenIP:     &listenIP,
	})
	if err == nil {
		t.Fatal("expected conflict when existing rule listens on all local addresses")
	}
	if !sharederrors.IsConflictError(err) {
		t.Fatalf("expected conflict error, got: %v", err)
	}
}

func mustTestAgent(t *testing.T, id uint, sid, publicAddress, tunnelAddress string) *forward.ForwardAgent {
	t.Helper()

	agent, err := forward.NewForwardAgent(
		"agent-"+sid,
		publicAddress,
		tunnelAddress,
		"",
		func() (string, error) { return sid, nil },
		func(shortID string) (string, string) { return "token-" + shortID, "hash-" + shortID },
	)
	if err != nil {
		t.Fatalf("failed to create test agent: %v", err)
	}
	if err := agent.SetID(id); err != nil {
		t.Fatalf("failed to set test agent ID: %v", err)
	}

	return agent
}

func mustTestRule(t *testing.T, sid string, agentID uint, listenPort uint16, listenIP string) *forward.ForwardRule {
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
		"192.0.2.10",
		443,
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
	if err != nil {
		t.Fatalf("failed to create test rule: %v", err)
	}
	if err := rule.UpdateListenIP(listenIP); err != nil {
		t.Fatalf("failed to set test rule listen IP: %v", err)
	}

	return rule
}
