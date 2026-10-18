package mappers

import (
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/infrastructure/persistence/models"
)

// AdminAPITokenMapper handles conversion between the admin API token aggregate
// and its persistence model.
type AdminAPITokenMapper interface {
	ToModel(entity *admintoken.Token) *models.AdminAPITokenModel
	ToEntity(model *models.AdminAPITokenModel) (*admintoken.Token, error)
}

// AdminAPITokenMapperImpl is the concrete implementation.
type AdminAPITokenMapperImpl struct{}

// NewAdminAPITokenMapper creates a new AdminAPITokenMapper.
func NewAdminAPITokenMapper() AdminAPITokenMapper {
	return &AdminAPITokenMapperImpl{}
}

// ToModel converts a domain entity to a persistence model.
func (m *AdminAPITokenMapperImpl) ToModel(entity *admintoken.Token) *models.AdminAPITokenModel {
	if entity == nil {
		return nil
	}
	return &models.AdminAPITokenModel{
		ID:         entity.ID(),
		SID:        entity.SID(),
		Name:       entity.Name(),
		TokenHash:  entity.TokenHash(),
		TokenHint:  entity.TokenHint(),
		CreatedBy:  entity.CreatedBy(),
		LastUsedAt: entity.LastUsedAt(),
		ExpiresAt:  entity.ExpiresAt(),
		RevokedAt:  entity.RevokedAt(),
		CreatedAt:  entity.CreatedAt(),
		UpdatedAt:  entity.UpdatedAt(),
	}
}

// ToEntity converts a persistence model to a domain entity.
func (m *AdminAPITokenMapperImpl) ToEntity(model *models.AdminAPITokenModel) (*admintoken.Token, error) {
	if model == nil {
		return nil, nil
	}
	return admintoken.ReconstructToken(
		model.ID,
		model.SID,
		model.Name,
		model.TokenHash,
		model.TokenHint,
		model.CreatedBy,
		model.LastUsedAt,
		model.ExpiresAt,
		model.RevokedAt,
		model.CreatedAt,
		model.UpdatedAt,
	)
}
