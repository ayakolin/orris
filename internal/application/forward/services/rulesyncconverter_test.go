package services

import (
	"context"
	"testing"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	apptest "github.com/orris-inc/orris/internal/application/forward/testutil"
	domaintest "github.com/orris-inc/orris/internal/domain/forward/testutil"
	"github.com/orris-inc/orris/internal/infrastructure/auth"
)

type fakeSyncHub struct{}

func (fakeSyncHub) IsAgentOnline(uint) bool { return true }
func (fakeSyncHub) SendMessageToAgent(uint, *dto.HubMessage) error {
	return nil
}
func (fakeSyncHub) GetAgentObservedAddress(uint) string { return "" }

func TestRuleSyncConverterDirectChainRelayPreservesListenIP(t *testing.T) {
	ctx := context.Background()

	agentRepo := apptest.NewMockForwardAgentRepository()
	for id := uint(1); id <= 3; id++ {
		agent, err := domaintest.NewTestForwardAgent(domaintest.ValidAgentParams())
		if err != nil {
			t.Fatalf("NewTestForwardAgent() error = %v", err)
		}
		if err := agent.SetID(id); err != nil {
			t.Fatalf("SetID(%d) error = %v", id, err)
		}
		agentRepo.AddAgent(agent)
	}

	statusQuerier := apptest.NewMockAgentStatusQuerier()
	converter := NewRuleSyncConverter(
		agentRepo,
		nil,
		statusQuerier,
		auth.NewAgentTokenService("test-secret"),
		fakeSyncHub{},
		apptest.NewMockLogger(),
	)

	rule, err := domaintest.NewTestForwardRule(domaintest.ValidDirectChainRuleParams(
		domaintest.WithChainAgents([]uint{2, 3}),
		domaintest.WithChainPortConfig(map[uint]uint16{2: 7001, 3: 7002}),
	))
	if err != nil {
		t.Fatalf("NewTestForwardRule() error = %v", err)
	}
	if err := rule.UpdateListenIP("10.10.0.2"); err != nil {
		t.Fatalf("UpdateListenIP() error = %v", err)
	}

	syncData, err := converter.Convert(ctx, rule, 2)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	if syncData.Role != "relay" {
		t.Fatalf("Role = %q, want relay", syncData.Role)
	}
	if syncData.ListenPort != 7001 {
		t.Fatalf("ListenPort = %d, want 7001", syncData.ListenPort)
	}
	if syncData.ListenIP != "10.10.0.2" {
		t.Fatalf("ListenIP = %q, want 10.10.0.2", syncData.ListenIP)
	}
	if syncData.BindIP != "" {
		t.Fatalf("BindIP = %q, want empty for non-exit relay", syncData.BindIP)
	}
}
