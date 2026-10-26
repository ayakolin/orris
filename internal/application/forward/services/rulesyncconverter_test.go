package services

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	apptest "github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/domain/forward"
	domaintest "github.com/orris-inc/orris/internal/domain/forward/testutil"
	vo "github.com/orris-inc/orris/internal/domain/forward/valueobjects"
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

// agentRuleView is the field set compared by the agent's ruleConfigChanged
// (orris-client internal/agent/hub.go). The hub push (RuleSyncData) and the
// periodic pull (ForwardRuleDTO) must agree on every field here, otherwise the
// agent restarts the forwarder each time the two sources alternate.
type agentRuleView struct {
	NextHopAddress    string
	NextHopPort       uint16
	NextHopWsPort     uint16
	NextHopTlsPort    uint16
	TargetAddress     string
	TargetPort        uint16
	BindIP            string
	ListenPort        uint16
	ListenIP          string
	Protocol          string
	TunnelType        string
	IsLastInChain     bool
	HopMode           string
	OutboundMode      string
	AddressPreference string
	ExitAgents        []string
}

// pushExitAgentKeys renders exit agents as "sid/weight" pairs. The agent drops
// offline exit agents when handling a push, so the test drives every exit agent
// online to keep both paths comparable. Offline filtering on the pull path is a
// known, intentionally unfixed divergence (out of scope here).
func pushExitAgentKeys(in []dto.ExitAgentSyncData) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, ea := range in {
		out[i] = fmt.Sprintf("%s/%d", ea.AgentID, ea.Weight)
	}
	return out
}

// newConsistencyTestAgent builds an enabled agent with a stable, unique SID.
func newConsistencyTestAgent(t *testing.T, id uint) *forward.ForwardAgent {
	t.Helper()
	now := time.Now().UTC()
	agent, err := forward.ReconstructForwardAgent(
		id,
		fmt.Sprintf("fa_test%d", id),
		fmt.Sprintf("test-agent-%d", id),
		fmt.Sprintf("token-hash-%d", id),
		"",
		forward.AgentStatusEnabled,
		"203.0.113.1",  // public address
		"198.51.100.1", // tunnel address
		"",
		nil, // groupIDs
		"",
		"",
		"",
		nil, // allowedPortRange
		nil, // blockedProtocols
		0,
		false,
		nil, // lastSeenAt
		nil, // expiresAt
		nil, // costLabel
		now,
		now,
	)
	if err != nil {
		t.Fatalf("ReconstructForwardAgent(%d) error = %v", id, err)
	}
	return agent
}

// tunnelTypeLabel renders the tunnel type for subtest names, keeping the unset
// case distinct from an explicit "ws" (both serialize to "ws").
func tunnelTypeLabel(t vo.TunnelType) string {
	if t == "" {
		return "unset"
	}
	return string(t)
}

// mustAgentWeights builds exit agent weights for load-balancing fixtures.
func mustAgentWeights(t *testing.T, weights map[uint]uint16) []vo.AgentWeight {
	t.Helper()
	out := make([]vo.AgentWeight, 0, len(weights))
	for _, id := range []uint{2, 3, 4} {
		if w, ok := weights[id]; ok {
			aw, err := vo.NewAgentWeight(id, w)
			if err != nil {
				t.Fatalf("NewAgentWeight(%d, %d) error = %v", id, w, err)
			}
			out = append(out, aw)
		}
	}
	return out
}

func pullExitAgentKeys(in []dto.ExitAgentDTO) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, ea := range in {
		out[i] = fmt.Sprintf("%s/%d", ea.AgentID, ea.Weight)
	}
	return out
}

func agentRuleViewFromPush(d *dto.RuleSyncData) agentRuleView {
	return agentRuleView{
		NextHopAddress:    d.NextHopAddress,
		NextHopPort:       d.NextHopPort,
		NextHopWsPort:     d.NextHopWsPort,
		NextHopTlsPort:    d.NextHopTlsPort,
		TargetAddress:     d.TargetAddress,
		TargetPort:        d.TargetPort,
		BindIP:            d.BindIP,
		ListenPort:        d.ListenPort,
		ListenIP:          d.ListenIP,
		Protocol:          d.Protocol,
		TunnelType:        d.TunnelType,
		IsLastInChain:     d.IsLastInChain,
		HopMode:           d.HopMode,
		OutboundMode:      d.OutboundMode,
		AddressPreference: d.AddressPreference,
		ExitAgents:        pushExitAgentKeys(d.ExitAgents),
	}
}

func agentRuleViewFromPull(d *dto.ForwardRuleDTO) agentRuleView {
	return agentRuleView{
		NextHopAddress:    d.NextHopAddress,
		NextHopPort:       d.NextHopPort,
		NextHopWsPort:     d.NextHopWsPort,
		NextHopTlsPort:    d.NextHopTlsPort,
		TargetAddress:     d.TargetAddress,
		TargetPort:        d.TargetPort,
		BindIP:            d.BindIP,
		ListenPort:        d.ListenPort,
		ListenIP:          d.ListenIP,
		Protocol:          d.Protocol,
		TunnelType:        d.TunnelType,
		IsLastInChain:     d.IsLastInChain,
		HopMode:           d.HopMode,
		OutboundMode:      d.OutboundMode,
		AddressPreference: d.AddressPreference,
		ExitAgents:        pullExitAgentKeys(d.ExitAgents),
	}
}

// TestAgentPullConversionMatchesHubPush verifies that the hub push conversion
// (RuleSyncConverter.Convert) and the agent pull conversion
// (AgentRuleConverter.ConvertForAgent) produce identical values for every field
// the agent compares in ruleConfigChanged.
func TestAgentPullConversionMatchesHubPush(t *testing.T) {
	ctx := context.Background()

	const testSecret = "test-secret"

	agentRepo := apptest.NewMockForwardAgentRepository()
	statusQuerier := apptest.NewMockAgentStatusQuerier()
	// Distinct SIDs and tunnel ports per agent so agent-ID comparisons in the
	// rule views are meaningful.
	for id := uint(1); id <= 4; id++ {
		agent := newConsistencyTestAgent(t, id)
		agentRepo.AddAgent(agent)
		statusQuerier.SetStatus(id, &dto.AgentStatusDTO{
			WsListenPort:  uint16(20000 + id),
			TlsListenPort: uint16(30000 + id),
		})
	}

	pushConverter := NewRuleSyncConverter(
		agentRepo,
		nil,
		statusQuerier,
		auth.NewAgentTokenService(testSecret),
		fakeSyncHub{},
		apptest.NewMockLogger(),
	)
	pullConverter := dto.NewAgentRuleConverter(
		agentRepo,
		nil,
		statusQuerier,
		auth.NewAgentTokenService(testSecret),
		fakeSyncHub{},
		apptest.NewMockLogger(),
	)

	chainPorts := map[uint]uint16{3: 7001, 4: 7002}
	hybridHops := 1

	type buildCase struct {
		name    string
		params  func() domaintest.RuleParams
		agentID uint
	}

	cases := []buildCase{
		{
			name: "direct/entry-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidDirectRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 1,
		},
		{
			name: "entry/single-exit/entry-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidEntryRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 1,
		},
		{
			name: "entry/single-exit/exit-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidEntryRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 2,
		},
		{
			name: "entry/multi-exit/entry-role",
			params: func() domaintest.RuleParams {
				params := domaintest.ValidEntryRuleParams(domaintest.WithBindIP("192.0.2.10"))
				params.ExitAgentID = 0
				params.ExitAgents = mustAgentWeights(t, map[uint]uint16{2: 60, 3: 40})
				return params
			},
			agentID: 1,
		},
		{
			name: "entry/multi-exit/exit-role",
			params: func() domaintest.RuleParams {
				params := domaintest.ValidEntryRuleParams(domaintest.WithBindIP("192.0.2.10"))
				params.ExitAgentID = 0
				params.ExitAgents = mustAgentWeights(t, map[uint]uint16{2: 60, 3: 40})
				return params
			},
			agentID: 2,
		},
		{
			name: "chain/full-tunnel/entry-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidChainRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 1,
		},
		{
			name: "chain/full-tunnel/relay-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidChainRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 2,
		},
		{
			name: "chain/full-tunnel/exit-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidChainRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 4,
		},
		{
			name: "chain/hybrid/tunnel-hop",
			params: func() domaintest.RuleParams {
				params := domaintest.ValidChainRuleParams(
					domaintest.WithBindIP("192.0.2.10"),
					domaintest.WithChainPortConfig(chainPorts),
				)
				params.TunnelHops = &hybridHops
				return params
			},
			agentID: 1,
		},
		{
			name: "chain/hybrid/boundary-hop",
			params: func() domaintest.RuleParams {
				params := domaintest.ValidChainRuleParams(
					domaintest.WithBindIP("192.0.2.10"),
					domaintest.WithChainPortConfig(chainPorts),
				)
				params.TunnelHops = &hybridHops
				return params
			},
			agentID: 2,
		},
		{
			name: "chain/hybrid/direct-hop",
			params: func() domaintest.RuleParams {
				params := domaintest.ValidChainRuleParams(
					domaintest.WithBindIP("192.0.2.10"),
					domaintest.WithChainPortConfig(chainPorts),
				)
				params.TunnelHops = &hybridHops
				return params
			},
			agentID: 3,
		},
		{
			name: "chain/hybrid/direct-exit",
			params: func() domaintest.RuleParams {
				params := domaintest.ValidChainRuleParams(
					domaintest.WithBindIP("192.0.2.10"),
					domaintest.WithChainPortConfig(chainPorts),
				)
				params.TunnelHops = &hybridHops
				return params
			},
			agentID: 4,
		},
		{
			name: "direct_chain/entry-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidDirectChainRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 1,
		},
		{
			name: "direct_chain/relay-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidDirectChainRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 2,
		},
		{
			name: "direct_chain/exit-role",
			params: func() domaintest.RuleParams {
				return domaintest.ValidDirectChainRuleParams(domaintest.WithBindIP("192.0.2.10"))
			},
			agentID: 4,
		},
	}

	tunnelTypes := []vo.TunnelType{
		"", // unset: must behave like "ws" on both paths
		vo.TunnelTypeWS,
		vo.TunnelTypeTLS,
		vo.TunnelTypeWSSmux,
		vo.TunnelTypeTLSSmux,
	}

	for _, tc := range cases {
		for _, tunnelType := range tunnelTypes {
			label := fmt.Sprintf("%s/tunnel=%s", tc.name, tunnelTypeLabel(tunnelType))
			t.Run(label, func(t *testing.T) {
				params := tc.params()
				params.TunnelType = tunnelType
				rule, err := domaintest.NewTestForwardRule(params)
				if err != nil {
					t.Fatalf("NewTestForwardRule() error = %v", err)
				}
				if err := rule.UpdateListenIP("10.10.0.2"); err != nil {
					t.Fatalf("UpdateListenIP() error = %v", err)
				}

				pushed, err := pushConverter.Convert(ctx, rule, tc.agentID)
				if err != nil {
					t.Fatalf("push Convert() error = %v", err)
				}
				pulled, err := pullConverter.ConvertForAgent(ctx, rule, tc.agentID)
				if err != nil {
					t.Fatalf("pull ConvertForAgent() error = %v", err)
				}

				pushView := agentRuleViewFromPush(pushed)
				pullView := agentRuleViewFromPull(pulled)

				// Empty tunnel_type defaults to "ws" on both paths.
				wantTunnelType := rule.TunnelType().String()
				if pushView.TunnelType != wantTunnelType {
					t.Fatalf("push TunnelType = %q, want %q", pushView.TunnelType, wantTunnelType)
				}
				if pullView.TunnelType != wantTunnelType {
					t.Fatalf("pull TunnelType = %q, want %q", pullView.TunnelType, wantTunnelType)
				}

				if !reflect.DeepEqual(pushView, pullView) {
					t.Fatalf("push/pull mismatch for agent %d (role %q)\n push: %+v\n pull: %+v",
						tc.agentID, pushed.Role, pushView, pullView)
				}
				// Role drives which forwarder the agent starts, so a
				// divergence there is a real behavioral difference even
				// though ruleConfigChanged does not compare it directly.
				if pushed.Role != pulled.Role {
					t.Fatalf("role mismatch: push %q, pull %q", pushed.Role, pulled.Role)
				}
			})
		}
	}
}
