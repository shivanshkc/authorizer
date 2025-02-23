package handler

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/shivanshkc/authorizer/internal/repository"
)

// mockRepository is a mock implementation of repository.Repository.
type mockRepository struct {
	mock.Mock
}

func (m *mockRepository) UpsertUser(ctx context.Context, user repository.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
