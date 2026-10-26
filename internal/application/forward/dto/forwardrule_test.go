package dto

import (
	"testing"

	domaintest "github.com/orris-inc/orris/internal/domain/forward/testutil"
	vo "github.com/orris-inc/orris/internal/domain/forward/valueobjects"
)

// TestToForwardRuleDTOTunnelTypeEmptyForDirectTypes pins the admin/user listing
// contract: direct, direct_chain and external rules expose an empty tunnel_type
// in RulesToForwardRuleDTO output, even though the agent-facing conversion
// normalizes the same value to "ws".
func TestToForwardRuleDTOTunnelTypeEmptyForDirectTypes(t *testing.T) {
	cases := []struct {
		name   string
		params domaintest.RuleParams
	}{
		{
			name:   "direct",
			params: domaintest.ValidDirectRuleParams(),
		},
		{
			name:   "direct_chain",
			params: domaintest.ValidDirectChainRuleParams(),
		},
	}

	for _, tc := range cases {
		for _, tunnelType := range []vo.TunnelType{"", vo.TunnelTypeWS, vo.TunnelTypeTLS, vo.TunnelTypeWSSmux, vo.TunnelTypeTLSSmux} {
			t.Run(tc.name+"/tunnel="+string(tunnelType), func(t *testing.T) {
				params := tc.params
				params.TunnelType = tunnelType
				rule, err := domaintest.NewTestForwardRule(params)
				if err != nil {
					t.Fatalf("NewTestForwardRule() error = %v", err)
				}

				if got := ToForwardRuleDTO(rule).TunnelType; got != "" {
					t.Fatalf("ToForwardRuleDTO().TunnelType = %q, want empty for %s", got, tc.name)
				}
			})
		}
	}
}

// TestToForwardRuleDTOTunnelTypeCarriedForTunnelTypes is the counterpart: rules
// that actually use a tunnel keep their configured tunnel type, with an unset
// value normalized to "ws" by the value object.
func TestToForwardRuleDTOTunnelTypeCarriedForTunnelTypes(t *testing.T) {
	cases := []struct {
		name   string
		params domaintest.RuleParams
	}{
		{
			name:   "entry",
			params: domaintest.ValidEntryRuleParams(),
		},
		{
			name:   "chain",
			params: domaintest.ValidChainRuleParams(),
		},
	}

	for _, tc := range cases {
		for _, tunnelType := range []vo.TunnelType{"", vo.TunnelTypeWS, vo.TunnelTypeTLS, vo.TunnelTypeWSSmux, vo.TunnelTypeTLSSmux} {
			t.Run(tc.name+"/tunnel="+string(tunnelType), func(t *testing.T) {
				params := tc.params
				params.TunnelType = tunnelType
				rule, err := domaintest.NewTestForwardRule(params)
				if err != nil {
					t.Fatalf("NewTestForwardRule() error = %v", err)
				}

				if got, want := ToForwardRuleDTO(rule).TunnelType, rule.TunnelType().String(); got != want {
					t.Fatalf("ToForwardRuleDTO().TunnelType = %q, want %q", got, want)
				}
			})
		}
	}
}
