package rule

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/application/forward/usecases"
	"github.com/orris-inc/orris/internal/interfaces/http/handlers/testutil"
)

// capturingBatchRuleUC records the BatchUpdate command it receives so tests can
// assert how the HTTP layer mapped target_address/target_port onto the use case
// input.
type capturingBatchRuleUC struct {
	mu          sync.Mutex
	updateCalls []usecases.BatchUpdateCommand

	updateResult *dto.BatchOperationResult
	updateErr    error
}

func (m *capturingBatchRuleUC) BatchCreate(ctx context.Context, cmd usecases.BatchCreateCommand) (*dto.BatchCreateResponse, error) {
	return nil, nil
}

func (m *capturingBatchRuleUC) BatchDelete(ctx context.Context, cmd usecases.BatchDeleteCommand) (*dto.BatchOperationResult, error) {
	return nil, nil
}

func (m *capturingBatchRuleUC) BatchToggleStatus(ctx context.Context, cmd usecases.BatchToggleStatusCommand) (*dto.BatchOperationResult, error) {
	return nil, nil
}

func (m *capturingBatchRuleUC) BatchUpdate(ctx context.Context, cmd usecases.BatchUpdateCommand) (*dto.BatchOperationResult, error) {
	m.mu.Lock()
	m.updateCalls = append(m.updateCalls, cmd)
	m.mu.Unlock()
	return m.updateResult, m.updateErr
}

// UpdateCalls returns a copy of the captured BatchUpdate commands.
func (m *capturingBatchRuleUC) UpdateCalls() []usecases.BatchUpdateCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]usecases.BatchUpdateCommand(nil), m.updateCalls...)
}

func newBatchTargetTestHandler(batchUC batchRuleUseCase) *Handler {
	return newTestHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, batchUC, nil)
}

func TestBatchUpdateRules_ForwardsTargetFields(t *testing.T) {
	captured := &capturingBatchRuleUC{
		updateResult: &dto.BatchOperationResult{
			Succeeded: []string{validRuleSID(), validRuleSID()},
			Failed:    []dto.BatchOperationErr{},
		},
	}
	handler := newBatchTargetTestHandler(captured)

	firstSID := validRuleSID()
	secondSID := "fr_B7nQ4xW2pLmZ"
	body := map[string]any{
		"updates": []map[string]any{
			{
				"rule_id":        firstSID,
				"target_address": "10.0.0.9",
				"target_port":    8443,
				"name":           "x",
			},
			{
				"rule_id":        secondSID,
				"target_address": "10.0.0.10",
			},
		},
	}
	c, w := testutil.NewTestContext(http.MethodPatch, "/forward-rules/batch", body)

	handler.BatchUpdateRules(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	assert.True(t, resp.Success)

	calls := captured.UpdateCalls()
	require.Len(t, calls, 1)
	require.Len(t, calls[0].Updates, 2)

	first := calls[0].Updates[0]
	assert.Equal(t, firstSID, first.RuleSID)
	require.NotNil(t, first.TargetAddress)
	assert.Equal(t, "10.0.0.9", *first.TargetAddress)
	require.NotNil(t, first.TargetPort)
	assert.Equal(t, uint16(8443), *first.TargetPort)
	require.NotNil(t, first.Name)
	assert.Equal(t, "x", *first.Name)

	second := calls[0].Updates[1]
	assert.Equal(t, secondSID, second.RuleSID)
	require.NotNil(t, second.TargetAddress)
	assert.Equal(t, "10.0.0.10", *second.TargetAddress)
	assert.Nil(t, second.TargetPort, "omitted target_port must stay nil so the stored port is kept")
	assert.Nil(t, second.Name)
}

func TestBatchUpdateRules_TargetPortZeroIsRejected(t *testing.T) {
	captured := &capturingBatchRuleUC{
		updateResult: &dto.BatchOperationResult{},
	}
	handler := newBatchTargetTestHandler(captured)

	body := map[string]any{
		"updates": []map[string]any{
			{
				"rule_id":        validRuleSID(),
				"target_address": "10.0.0.11",
				"target_port":    0,
			},
		},
	}
	c, w := testutil.NewTestContext(http.MethodPatch, "/forward-rules/batch", body)

	handler.BatchUpdateRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	assert.False(t, resp.Success)
	assert.Empty(t, captured.UpdateCalls(), "validation must reject the request before the use case runs")
}
