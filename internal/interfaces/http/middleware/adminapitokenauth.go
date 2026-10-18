package middleware

import (
	"context"

	"github.com/orris-inc/orris/internal/application/admintoken/usecases"
)

// AdminAPITokenAuthenticator validates an admin API token and returns the owning
// admin identity. Implemented by usecases.AuthenticateAdminAPITokenUseCase.
type AdminAPITokenAuthenticator interface {
	Execute(ctx context.Context, cmd usecases.AuthenticateAdminAPITokenCommand) (*usecases.AuthenticateAdminAPITokenResult, error)
}
