package handler

import (
	"context"

	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// mockProvider is a mock implementation of the oauth.Provider interface.
type mockProvider struct {
	// To mock the Name method.
	name string
	// To mock the GetAuthURL method.
	authURL string
	// To mock the TokenFromCode method.
	errTokenFromCode error
	token            string
	// To mock the DecodeToken method.
	errDecodeToken error
	claims         oauth.Claims
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) GetAuthURL(context.Context, string) string {
	return m.authURL
}

func (m *mockProvider) TokenFromCode(context.Context, string) (string, error) {
	if m.errTokenFromCode != nil {
		return "", m.errTokenFromCode
	}
	return m.token, nil
}

func (m *mockProvider) DecodeToken(context.Context, string) (oauth.Claims, error) {
	if m.errDecodeToken != nil {
		return oauth.Claims{}, m.errDecodeToken
	}
	return m.claims, nil
}

// Clone is a utility method to quickly create a copy.
func (m *mockProvider) Clone() *mockProvider {
	clone := &mockProvider{}
	*clone = *m
	return clone
}
