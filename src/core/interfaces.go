package core

import (
	"context"
)

// Dependencies of the core.
var (
	// ClientCallbackURL is where the frontend will receive the OAuth result.
	ClientCallbackURL string

	// ProviderMap maps provider names to their OAuthProvider implementation.
	ProviderMap = map[string]OAuthProvider{}

	// UserDB is required to get user data from the database.
	UserDB UserDatabase
)

// OAuthProvider represents a generic OAuth provider.
type OAuthProvider interface {
	// Name provides the name of the provider.
	Name() string

	// GetRedirectURL returns the URL to the auth page of the provider.
	GetRedirectURL(ctx context.Context) string

	// Code2Token converts the auth code to identity token.
	Code2Token(ctx context.Context, code string) (string, error)

	// Token2UserInfo converts the identity token into the user's info.
	Token2UserInfo(ctx context.Context, token string) (*UserDoc, error)
}

// UserDatabase represents the database layer for user information.
type UserDatabase interface {
	// SetUser upserts the user's info in the database.
	SetUser(ctx context.Context, doc *UserDoc) error

	// GetUserInfo fetches the user info for the provided userID.
	GetUser(ctx context.Context, userID string) (*UserDoc, error)
}
