// Package tokens provides HTTP handlers for admin API token management.
package tokens

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/application/admintoken/dto"
	"github.com/orris-inc/orris/internal/application/admintoken/usecases"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
	"github.com/orris-inc/orris/internal/shared/utils"
)

// Handler handles admin API token management requests.
type Handler struct {
	createUC *usecases.CreateAdminAPITokenUseCase
	listUC   *usecases.ListAdminAPITokensUseCase
	getUC    *usecases.GetAdminAPITokenUseCase
	revokeUC *usecases.RevokeAdminAPITokenUseCase
	deleteUC *usecases.DeleteAdminAPITokenUseCase
	logger   logger.Interface
}

// NewHandler creates a new admin API token handler.
func NewHandler(
	createUC *usecases.CreateAdminAPITokenUseCase,
	listUC *usecases.ListAdminAPITokensUseCase,
	getUC *usecases.GetAdminAPITokenUseCase,
	revokeUC *usecases.RevokeAdminAPITokenUseCase,
	deleteUC *usecases.DeleteAdminAPITokenUseCase,
	logger logger.Interface,
) *Handler {
	return &Handler{
		createUC: createUC,
		listUC:   listUC,
		getUC:    getUC,
		revokeUC: revokeUC,
		deleteUC: deleteUC,
		logger:   logger,
	}
}

// CreateToken handles POST /admin/api-tokens.
// The plaintext token is returned exactly once in this response.
func (h *Handler) CreateToken(c *gin.Context) {
	var req dto.CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warnw("invalid request body for create admin API token", "error", err, "ip", c.ClientIP())
		utils.ErrorResponseWithError(c, err)
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	result, err := h.createUC.Execute(c.Request.Context(), usecases.CreateAdminAPITokenCommand{
		Name:      req.Name,
		CreatedBy: userID,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	utils.CreatedResponse(c, result, "Admin API token created. Copy the token now: it will not be shown again.")
}

// ListTokens handles GET /admin/api-tokens.
// The result is scoped to the caller; a token never allows reading another
// admin's tokens.
func (h *Handler) ListTokens(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	tokens, err := h.listUC.Execute(c.Request.Context(), usecases.ListAdminAPITokensQuery{CreatedBy: userID})
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "success", tokens)
}

// GetToken handles GET /admin/api-tokens/:id.
func (h *Handler) GetToken(c *gin.Context) {
	sid, err := utils.ParseSIDParam(c, "id", id.PrefixAdminAPIToken, "admin API token")
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	token, err := h.getUC.Execute(c.Request.Context(), usecases.GetAdminAPITokenQuery{SID: sid, OwnerID: userID})
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "success", token)
}

// RevokeToken handles POST /admin/api-tokens/:id/revoke.
func (h *Handler) RevokeToken(c *gin.Context) {
	sid, err := utils.ParseSIDParam(c, "id", id.PrefixAdminAPIToken, "admin API token")
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	if err := h.revokeUC.Execute(c.Request.Context(), usecases.RevokeAdminAPITokenCommand{SID: sid, OwnerID: userID}); err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin API token revoked successfully", nil)
}

// DeleteToken handles DELETE /admin/api-tokens/:id.
func (h *Handler) DeleteToken(c *gin.Context) {
	sid, err := utils.ParseSIDParam(c, "id", id.PrefixAdminAPIToken, "admin API token")
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	if err := h.deleteUC.Execute(c.Request.Context(), usecases.DeleteAdminAPITokenCommand{SID: sid, OwnerID: userID}); err != nil {
		utils.ErrorResponseWithError(c, err)
		return
	}

	utils.NoContentResponse(c)
}
