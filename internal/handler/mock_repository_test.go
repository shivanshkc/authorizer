package handler

import (
	"context"
	"time"

	"github.com/shivanshkc/authorizer/internal/repository"

	"github.com/stretchr/testify/mock"
)

// mockRepository is a mock implementation of repository.Repository.
type mockRepository struct {
	mock.Mock
}

func (m *mockRepository) UpsertUser(ctx context.Context, user repository.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockRepository) Insert(ctx context.Context, sub string, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, sub, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *mockRepository) Refresh(ctx context.Context, oldTokenHash, newTokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, oldTokenHash, newTokenHash, expiresAt)
	return args.Error(0)
}

func (m *mockRepository) RevokeAll(ctx context.Context, sub string) error {
	args := m.Called(ctx, sub)
	return args.Error(0)
}

func (m *mockRepository) Revoke(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}
