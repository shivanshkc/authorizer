package handler

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// mockProvider is a mock implementation of the oauth.Provider interface.
type mockProvider struct {
	mock.Mock
}

func (m *mockProvider) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockProvider) Issuers() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *mockProvider) GetAuthURL(c context.Context, state, codeChallenge string) string {
	args := m.Called(c, state, codeChallenge)
	return args.String(0)
}

func (m *mockProvider) TokenFromCode(c context.Context, code, codeVerifier string) (string, error) {
	args := m.Called(c, code, codeVerifier)
	return args.String(0), args.Error(1)
}

func (m *mockProvider) DecodeToken(c context.Context, s string) (oauth.Claims, error) {
	args := m.Called(c, s)
	return args.Get(0).(oauth.Claims), args.Error(1)
}
