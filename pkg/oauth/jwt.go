package oauth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// jwtParser is used by the JWT functions in this file.
var jwtParser = jwt.NewParser()

// JWTDecodeUnsafe decodes the JWT without validating it and without verifying the sign.
func JWTDecodeUnsafe(token string, target jwt.Claims) error {
	// Parse the token to get the claims.
	if _, _, err := jwtParser.ParseUnverified(token, target); err != nil {
		return fmt.Errorf("error in jwtParser.ParseUnverified call: %w", err)
	}

	return nil
}
