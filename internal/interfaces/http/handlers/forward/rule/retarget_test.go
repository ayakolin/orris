package rule

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/forward/usecases"
	"github.com/orris-inc/orris/internal/interfaces/http/handlers/testutil"
	"github.com/orris-inc/orris/internal/shared/errors"
)

// capturingRetargetUC records the command it received so the test can assert the
// handler forwarded every field exactly.
type capturingRetargetUC struct {
	cmd    *usecases.RetargetCommand
	calls  int
	result *usecases.RetargetResult
	err    error
}

func (m *capturingRetargetUC) Execute(ctx context.Context, cmd usecases.RetargetCommand) (*usecases.RetargetResult, error) {
	m.calls++
	m.cmd = &cmd
	if m.err != nil {
		return nil, m.err
	}
	if m.result != nil {
		return m.result, nil
	}
	return &usecases.RetargetResult{
		DryRun:  cmd.DryRun,
		From:    cmd.FromAddress,
		To:      cmd.ToAddress,
		ToPort:  cmd.ToPort,
		Matched: 0,
	}, nil
}

// newRetargetHandler wires the capturing use case into the shared handler
// constructor; every other dependency is unused by RetargetRules.
func newRetargetHandler(uc retargetRulesUseCase) *Handler {
	return NewHandler(
		nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		uc, nil, testutil.NewMockLogger(),
	)
}

func TestHandler_RetargetRules_Success(t *testing.T) {
	tests := []struct {
		name        string
		dryRun      bool
		wantMessage string
	}{
		{name: "apply", dryRun: false, wantMessage: "Retarget completed"},
		{name: "dry run", dryRun: true, wantMessage: "Retarget dry run"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := &capturingRetargetUC{}
			handler := newRetargetHandler(uc)

			port := uint16(8443)
			reqBody := RetargetForwardRulesRequest{
				FromAddress: "203.0.113.10",
				ToAddress:   "203.0.113.20",
				ToPort:      &port,
				RuleIDs:     []string{validRuleSID()},
				DryRun:      tt.dryRun,
			}
			c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", reqBody)

			handler.RetargetRules(c)

			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			require.Equal(t, 1, uc.calls)

			require.NotNil(t, uc.cmd)
			assert.Equal(t, "203.0.113.10", uc.cmd.FromAddress)
			assert.Equal(t, "203.0.113.20", uc.cmd.ToAddress)
			require.NotNil(t, uc.cmd.ToPort)
			assert.Equal(t, uint16(8443), *uc.cmd.ToPort)
			assert.Equal(t, []string{validRuleSID()}, uc.cmd.RuleSIDs)
			assert.Equal(t, tt.dryRun, uc.cmd.DryRun)

			var resp testutil.APIResponse
			require.NoError(t, testutil.ParseResponse(w, &resp))
			assert.True(t, resp.Success)
			assert.Equal(t, tt.wantMessage, resp.Message)

			var result usecases.RetargetResult
			require.NoError(t, json.Unmarshal(resp.Data, &result))
			assert.Equal(t, tt.dryRun, result.DryRun)
			assert.Equal(t, "203.0.113.10", result.From)
			assert.Equal(t, "203.0.113.20", result.To)
			require.NotNil(t, result.ToPort)
			assert.Equal(t, uint16(8443), *result.ToPort)
		})
	}
}

func TestHandler_RetargetRules_OmitsOptionalFields(t *testing.T) {
	uc := &capturingRetargetUC{}
	handler := newRetargetHandler(uc)

	reqBody := map[string]any{
		"from_address": "203.0.113.10",
		"to_address":   "203.0.113.20",
	}
	c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", reqBody)

	handler.RetargetRules(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.NotNil(t, uc.cmd)
	assert.Nil(t, uc.cmd.ToPort)
	assert.Empty(t, uc.cmd.RuleSIDs)
	assert.False(t, uc.cmd.DryRun)
}

func TestHandler_RetargetRules_MissingFromAddress(t *testing.T) {
	uc := &capturingRetargetUC{}
	handler := newRetargetHandler(uc)

	reqBody := map[string]any{
		"to_address": "203.0.113.20",
	}
	c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", reqBody)

	handler.RetargetRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, uc.calls, "validation must happen before the use case runs")

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	assert.False(t, resp.Success)
}

func TestHandler_RetargetRules_MissingToAddress(t *testing.T) {
	uc := &capturingRetargetUC{}
	handler := newRetargetHandler(uc)

	reqBody := map[string]any{
		"from_address": "203.0.113.10",
	}
	c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", reqBody)

	handler.RetargetRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, uc.calls, "validation must happen before the use case runs")

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	assert.False(t, resp.Success)
}

// A malformed rule ID is detected by the use case: the handler must pass it
// through and map the returned validation error to 400.
func TestHandler_RetargetRules_InvalidRuleIDMappedToBadRequest(t *testing.T) {
	uc := &capturingRetargetUC{err: errors.NewValidationError("invalid forward rule ID format, expected fr_xxxxx")}
	handler := newRetargetHandler(uc)

	reqBody := RetargetForwardRulesRequest{
		FromAddress: "203.0.113.10",
		ToAddress:   "203.0.113.20",
		RuleIDs:     []string{"not-a-rule-id"},
	}
	c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", reqBody)

	handler.RetargetRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	require.Equal(t, 1, uc.calls)
	require.NotNil(t, uc.cmd)
	assert.Equal(t, []string{"not-a-rule-id"}, uc.cmd.RuleSIDs)

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "invalid forward rule ID format")
}

func TestHandler_RetargetRules_UseCaseValidationError(t *testing.T) {
	uc := &capturingRetargetUC{err: errors.NewValidationError("from_address and to_address must differ")}
	handler := newRetargetHandler(uc)

	reqBody := RetargetForwardRulesRequest{
		FromAddress: "203.0.113.10",
		ToAddress:   "203.0.113.10",
	}
	c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", reqBody)

	handler.RetargetRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	assert.False(t, resp.Success)
	require.NotNil(t, resp.Error)
	assert.Equal(t, string(errors.ErrorTypeValidation), resp.Error.Type)
}

func TestHandler_RetargetRules_InvalidBody(t *testing.T) {
	uc := &capturingRetargetUC{}
	handler := newRetargetHandler(uc)

	// to_port=0 violates the min=1 binding constraint.
	c, w := testutil.NewTestContext(http.MethodPost, "/forward-rules/retarget", map[string]any{
		"from_address": "203.0.113.10",
		"to_address":   "203.0.113.20",
		"to_port":      0,
	})

	handler.RetargetRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, uc.calls)
}
