package repository

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by stubbed repository methods pending database queries.
var ErrNotImplemented = errors.New("method not implemented")

// Insert stores a new refresh token hash for the given subject.
// TODO(token-migration): Implement database query for inserting a refresh token.
func (r *repository) Insert(ctx context.Context, sub string, tokenHash string, expiresAt time.Time) error {
	return ErrNotImplemented
}

// Refresh rotates an old refresh token hash with a new one and updates the expiration time.
// TODO(token-migration): Implement database query for rotating a refresh token.
func (r *repository) Refresh(ctx context.Context, oldTokenHash, newTokenHash string, expiresAt time.Time) error {
	return ErrNotImplemented
}

// Revoke revokes a single refresh token by its hash.
// TODO(token-migration): Implement database query for revoking a refresh token.
func (r *repository) Revoke(ctx context.Context, tokenHash string) error {
	return ErrNotImplemented
}

// RevokeAll revokes all refresh tokens for the given subject.
// TODO(token-migration): Implement database query for revoking all refresh tokens for a user.
func (r *repository) RevokeAll(ctx context.Context, sub string) error {
	return ErrNotImplemented
}
