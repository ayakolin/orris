package repository

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/infrastructure/persistence/mappers"
	"github.com/orris-inc/orris/internal/infrastructure/persistence/models"
)

// AdminAPITokenRepositoryImpl implements admintoken.Repository.
type AdminAPITokenRepositoryImpl struct {
	db     *gorm.DB
	mapper mappers.AdminAPITokenMapper
}

// NewAdminAPITokenRepository creates a new AdminAPITokenRepositoryImpl.
func NewAdminAPITokenRepository(db *gorm.DB) admintoken.Repository {
	return &AdminAPITokenRepositoryImpl{
		db:     db,
		mapper: mappers.NewAdminAPITokenMapper(),
	}
}

func (r *AdminAPITokenRepositoryImpl) Create(ctx context.Context, token *admintoken.Token) error {
	model := r.mapper.ToModel(token)
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return fmt.Errorf("failed to create admin API token: %w", err)
	}
	if err := token.SetID(model.ID); err != nil {
		return fmt.Errorf("failed to set admin API token ID: %w", err)
	}
	return nil
}

func (r *AdminAPITokenRepositoryImpl) GetByID(ctx context.Context, id uint) (*admintoken.Token, error) {
	var model models.AdminAPITokenModel
	if err := r.db.WithContext(ctx).First(&model, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get admin API token by ID: %w", err)
	}
	return r.mapper.ToEntity(&model)
}

func (r *AdminAPITokenRepositoryImpl) GetBySID(ctx context.Context, sid string) (*admintoken.Token, error) {
	var model models.AdminAPITokenModel
	if err := r.db.WithContext(ctx).Where("sid = ?", sid).First(&model).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get admin API token by SID: %w", err)
	}
	return r.mapper.ToEntity(&model)
}

func (r *AdminAPITokenRepositoryImpl) GetByTokenHash(ctx context.Context, tokenHash string) (*admintoken.Token, error) {
	var model models.AdminAPITokenModel
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&model).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get admin API token by hash: %w", err)
	}
	return r.mapper.ToEntity(&model)
}

func (r *AdminAPITokenRepositoryImpl) List(ctx context.Context, createdBy uint) ([]*admintoken.Token, error) {
	query := r.db.WithContext(ctx).Model(&models.AdminAPITokenModel{})
	if createdBy != 0 {
		query = query.Where("created_by = ?", createdBy)
	}

	var tokenModels []*models.AdminAPITokenModel
	if err := query.Order("created_at DESC, id DESC").Find(&tokenModels).Error; err != nil {
		return nil, fmt.Errorf("failed to list admin API tokens: %w", err)
	}

	tokens := make([]*admintoken.Token, 0, len(tokenModels))
	for _, model := range tokenModels {
		entity, err := r.mapper.ToEntity(model)
		if err != nil {
			return nil, fmt.Errorf("failed to map admin API token: %w", err)
		}
		tokens = append(tokens, entity)
	}
	return tokens, nil
}

func (r *AdminAPITokenRepositoryImpl) Revoke(ctx context.Context, id uint, revokedAt time.Time) (bool, error) {
	// Only the first revocation is recorded; re-revoking keeps the original timestamp.
	result := r.db.WithContext(ctx).Model(&models.AdminAPITokenModel{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Updates(map[string]any{
			"revoked_at": revokedAt,
			"updated_at": revokedAt,
		})
	if result.Error != nil {
		return false, fmt.Errorf("failed to revoke admin API token: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		return true, nil
	}

	// Distinguish "already revoked" (success, idempotent) from "not found".
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.AdminAPITokenModel{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check admin API token existence: %w", err)
	}
	return count > 0, nil
}

// RevokeByUserID revokes every active token owned by userID.
func (r *AdminAPITokenRepositoryImpl) RevokeByUserID(ctx context.Context, userID uint, revokedAt time.Time) (int64, error) {
	result := r.db.WithContext(ctx).Model(&models.AdminAPITokenModel{}).
		Where("created_by = ? AND revoked_at IS NULL", userID).
		Updates(map[string]any{
			"revoked_at": revokedAt,
			"updated_at": revokedAt,
		})
	if result.Error != nil {
		return 0, fmt.Errorf("failed to revoke admin API tokens for user: %w", result.Error)
	}
	return result.RowsAffected, nil
}

func (r *AdminAPITokenRepositoryImpl) UpdateLastUsed(ctx context.Context, id uint, lastUsedAt time.Time) (bool, error) {
	result := r.db.WithContext(ctx).Model(&models.AdminAPITokenModel{}).
		Where("id = ?", id).
		UpdateColumn("last_used_at", lastUsedAt)
	if result.Error != nil {
		return false, fmt.Errorf("failed to update admin API token last used at: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

func (r *AdminAPITokenRepositoryImpl) Delete(ctx context.Context, id uint) (bool, error) {
	result := r.db.WithContext(ctx).Delete(&models.AdminAPITokenModel{}, id)
	if result.Error != nil {
		return false, fmt.Errorf("failed to delete admin API token: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}
