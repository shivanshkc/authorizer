package oauth

import (
	"errors"
	"slices"

	"github.com/lestrrat-go/jwx/jwt"
)

var (
	// ErrCannotDeduceProvider is returned when the provider cannot be deduced from the token.
	// It is mostly due to malformed token.
	ErrCannotDeduceProvider = errors.New("cannot deduce token provider")
	// ErrUnknownProvider is returned when the token issuer is unknown.
	ErrUnknownProvider = errors.New("unknown token provider")
)

// ProviderFromToken infers the provider name from the given token.
func ProviderFromToken(token string) (string, error) {
	// Parse the token without any verifications.
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false))
	if err != nil {
		return "", errors.Join(ErrCannotDeduceProvider, err)
	}

	// Issuer can be used to identify the provider.
	iss := parsed.Issuer()

	// Check if issuer is Google.
	if slices.Contains(googleIssuers, iss) {
		return googleProviderName, nil
	}

	// Provider couldn't be determined.
	return "", ErrUnknownProvider
}
