package handler

import (
	"context"

	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// mockProvider is a mock implementation of the oauth.Provider interface.
type mockProvider struct {
	// To mock the Name method.
	name string
	// To mock the Issuers method.
	issuers []string
	// To mock the GetAuthURL method.
	argState         string
	argCodeChallenge string
	authURL          string
	// To mock the TokenFromCode method.
	argCode          string
	argCodeVerifier  string
	errTokenFromCode error
	token            string
	// To mock the DecodeToken method.
	argDecodeToken string
	errDecodeToken error
	claims         oauth.Claims
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Issuers() []string {
	return m.issuers
}

func (m *mockProvider) GetAuthURL(c context.Context, state, codeChallenge string) string {
	m.argState = state
	m.argCodeChallenge = codeChallenge
	return m.authURL
}

func (m *mockProvider) TokenFromCode(c context.Context, code, codeVerifier string) (string, error) {
	m.argCode = code
	m.argCodeVerifier = codeVerifier
	if m.errTokenFromCode != nil {
		return "", m.errTokenFromCode
	}
	return m.token, nil
}

func (m *mockProvider) DecodeToken(c context.Context, s string) (oauth.Claims, error) {
	m.argDecodeToken = s
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
