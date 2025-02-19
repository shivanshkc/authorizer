package handler

import (
	"context"
	"fmt"

	"github.com/shivanshkc/authorizer/pkg/oauth"
)

// mockProvider is a mock implementation of the oauth.Provider interface.
type mockProvider struct {
	// To mock the Name method.
	name string
	// To mock the GetAuthURL method.
	authURL string
	// To mock the TokenFromCode method.
	argTokenFromCode string
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

func (m *mockProvider) GetAuthURL(context.Context, string) string {
	return m.authURL
}

func (m *mockProvider) TokenFromCode(c context.Context, s string) (string, error) {
	fmt.Println("INVOKED:", s)
	m.argTokenFromCode = s
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
