package rule

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	forwarddto "github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/application/forward/usecases"
	"github.com/orris-inc/orris/internal/interfaces/http/handlers/testutil"
)

// capturingListRulesUC records the query it received. The shared
// mockListRulesUC in handler_test.go returns fixed results only, so it cannot
// prove which filters the handler forwarded.
type capturingListRulesUC struct {
	query  *usecases.ListForwardRulesQuery
	calls  int
	result *usecases.ListForwardRulesResult
	err    error
}

func (m *capturingListRulesUC) Execute(ctx context.Context, query usecases.ListForwardRulesQuery) (*usecases.ListForwardRulesResult, error) {
	m.calls++
	m.query = &query
	if m.err != nil {
		return nil, m.err
	}
	if m.result != nil {
		return m.result, nil
	}
	return &usecases.ListForwardRulesResult{
		Rules: []*forwarddto.ForwardRuleDTO{},
		Total: 0,
		Page:  query.Page,
		Pages: 0,
	}, nil
}

func newListFilterHandler(uc listRulesUseCase) *Handler {
	return NewHandler(
		nil, nil, nil, nil, uc,
		nil, nil, nil, nil, nil,
		nil, nil, testutil.NewMockLogger(),
	)
}

func TestHandler_ListRules_ForwardsAgentAndTargetAddressFilters(t *testing.T) {
	uc := &capturingListRulesUC{}
	handler := newListFilterHandler(uc)

	c, w := testutil.NewTestContext(http.MethodGet, "/forward-rules", nil)
	testutil.SetQueryParams(c, map[string]string{
		"agent_id":       validAgentSID(),
		"target_address": "1.2.3.4",
	})

	handler.ListRules(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.Equal(t, 1, uc.calls)
	require.NotNil(t, uc.query)
	assert.Equal(t, validAgentSID(), uc.query.AgentSID)
	assert.Equal(t, "1.2.3.4", uc.query.TargetAddress)
}

func TestHandler_ListRules_InvalidAgentIDRejectedBeforeUseCase(t *testing.T) {
	uc := &capturingListRulesUC{}
	handler := newListFilterHandler(uc)

	c, w := testutil.NewTestContext(http.MethodGet, "/forward-rules", nil)
	testutil.SetQueryParams(c, map[string]string{"agent_id": "nope"})

	handler.ListRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, uc.calls, "an invalid agent_id filter must fail before the use case runs")

	var resp testutil.APIResponse
	require.NoError(t, testutil.ParseResponse(w, &resp))
	assert.False(t, resp.Success)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "agent_id")
}

func TestHandler_ListRules_InvalidAgentIDPrefixRejected(t *testing.T) {
	uc := &capturingListRulesUC{}
	handler := newListFilterHandler(uc)

	// Correct shape but the wrong entity prefix.
	c, w := testutil.NewTestContext(http.MethodGet, "/forward-rules", nil)
	testutil.SetQueryParams(c, map[string]string{"agent_id": validRuleSID()})

	handler.ListRules(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Zero(t, uc.calls)
}

func TestHandler_ListRules_ForwardsExistingFiltersUnchanged(t *testing.T) {
	uc := &capturingListRulesUC{}
	handler := newListFilterHandler(uc)

	c, w := testutil.NewTestContext(http.MethodGet, "/forward-rules", nil)
	testutil.SetQueryParams(c, map[string]string{
		"name":      "mysql",
		"protocol":  "tcp",
		"status":    "enabled",
		"page":      "3",
		"page_size": "25",
	})

	handler.ListRules(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.Equal(t, 1, uc.calls)
	require.NotNil(t, uc.query)
	assert.Equal(t, "mysql", uc.query.Name)
	assert.Equal(t, "tcp", uc.query.Protocol)
	assert.Equal(t, "enabled", uc.query.Status)
	assert.Equal(t, 3, uc.query.Page)
	assert.Equal(t, 25, uc.query.PageSize)
	assert.Empty(t, uc.query.AgentSID)
	assert.Empty(t, uc.query.TargetAddress)
}

func TestHandler_ListRules_NoFiltersForwardedAsEmpty(t *testing.T) {
	uc := &capturingListRulesUC{}
	handler := newListFilterHandler(uc)

	c, w := testutil.NewTestContext(http.MethodGet, "/forward-rules", nil)

	handler.ListRules(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.NotNil(t, uc.query)
	assert.Empty(t, uc.query.AgentSID)
	assert.Empty(t, uc.query.TargetAddress)
}
