package oauth

import (
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/jwt"

	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
)

// ProviderFromToken infers the provider name from the given token.
func ProviderFromToken(token string) (string, error) {
	// Parse the token without any verifications.
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false))
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	// Issuer can be used to identify the provider.
	iss := parsed.Issuer()

	// Check if issuer is Google.
	if slices.Contains(googleIssuers, iss) {
		return googleProviderName, nil
	}

	// Provider couldn't be determined.
	return "", errutils.Unauthorized().WithReasonStr("unknown provider")
}
