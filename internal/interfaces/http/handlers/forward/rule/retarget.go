package rule

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/application/forward/usecases"
	"github.com/orris-inc/orris/internal/shared/utils"
)

// RetargetForwardRulesRequest represents a request to move rules from one static
// landing address to another.
type RetargetForwardRulesRequest struct {
	FromAddress string   `json:"from_address" binding:"required" example:"203.0.113.10"`
	ToAddress   string   `json:"to_address" binding:"required" example:"203.0.113.20"`
	ToPort      *uint16  `json:"to_port,omitempty" binding:"omitempty,min=1" example:"443"`
	RuleIDs     []string `json:"rule_ids,omitempty" binding:"omitempty,max=100,dive,required" example:"[\"fr_xK9mP2vL3nQ\"]"`
	DryRun      bool     `json:"dry_run,omitempty" example:"false"`
}

// RetargetRules handles POST /forward-rules/retarget.
func (h *Handler) RetargetRules(c *gin.Context) {
	var req RetargetForwardRulesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warnw("invalid request body for retarget rules", "error", err, "ip", c.ClientIP())
		utils.ErrorResponseWithError(c, err)
		return
	}

	result, err := h.retargetRulesUC.Execute(c.Request.Context(), usecases.RetargetCommand{
		FromAddress: req.FromAddress,
		ToAddress:   req.ToAddress,
		ToPort:      req.ToPort,
		RuleSIDs:    req.RuleIDs,
		DryRun:      req.DryRun,
	})
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	message := "Retarget completed"
	if req.DryRun {
		message = "Retarget dry run"
	}
	utils.SuccessResponse(c, http.StatusOK, message, result)
}
