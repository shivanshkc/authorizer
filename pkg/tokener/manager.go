package tokener

import (
	"context"
)

// Manager encapsulates methods required to create and manage access-refresh token pairs.
type Manager struct {
	repo Repository
}

// NewManager returns a new instance of the manager.
func NewManager(repo Repository) *Manager {
	return &Manager{repo: repo}
}

// Login returns a new access-refresh token pair for the given claims.
func (m *Manager) Login(ctx context.Context, claims Claims) (string, string, error) {
	panic("implement me")
}

// Refresh checks if the given refreshToken is valid (not revoked + not expired). If valid, a new access-refresh token
// pair is issued, otherwise all refresh tokens for the user are revoked.
func (m *Manager) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	panic("implement me")
}

// Logout revokes the given refresh token.
func (m *Manager) Logout(ctx context.Context, refreshToken string) (string, string, error) {
	panic("implement me")
}
