package oauth

import (
	"context"
	"time"
)

// Provider represents an OAuth provider.
type Provider interface {
	// Name provides the name of the provider.
	Name() string

	// Issuers returns the list of valid "iss" claim values for the tokens of this Provider.
	Issuers() []string

	// GetAuthURL returns the URL to the auth page of the provider.
	//
	// The "state" parameter is returned as is in the provider's callback
	// and can be used to correlate it with the original redirect.
	//
	// The "codeChallenge" parameter is for PKCE (Proof Key for Code Exchange).
	// This method only supports the "S256" code challenge method.
	GetAuthURL(ctx context.Context, state, codeChallenge string) string

	// TokenFromCode converts the auth code to the identity token.
	//
	// The "codeVerifier" parameter is for PKCE (Proof Key for Code Exchange).
	TokenFromCode(ctx context.Context, code, codeVerifier string) (string, error)

	// DecodeToken validates the token claims and signature, and returns the claims.
	DecodeToken(ctx context.Context, token string) (Claims, error)
}

// Claims contain the user data retrieved from an OAuth provider.
type Claims struct {
	Iss string    `json:"iss"`
	Exp time.Time `json:"exp"`

	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
}
