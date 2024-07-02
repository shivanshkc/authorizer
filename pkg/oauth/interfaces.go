package oauth

import (
	"context"
)

// Provider represents an OAuth provider.
type Provider interface {
	// Name provides the name of the provider.
	Name() string

	// GetRedirectURL returns the URL to the auth page of the provider.
	//
	// The "state" parameter is returned as is in the provider's callback
	// and can be used to correlate it with the original redirect.
	GetRedirectURL(ctx context.Context, state string) string

	// TokenFromCode converts the auth code to identity token.
	TokenFromCode(ctx context.Context, code string) (string, error)

	// ValidateToken validates the token claims and signature and returns the claims.
	ValidateToken(ctx context.Context, token string) (GoogleClaims, error)
}
