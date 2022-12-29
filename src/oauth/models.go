package oauth

import (
	"fmt"
)

// googleIDTokenResponse is the schema of the response from Google's ID token endpoint.
type googleIDTokenResponse struct {
	IDToken string `json:"id_token"`
}

// GoogleClaims is the models of the claims present in a Google ID token.
type GoogleClaims struct {
	Email       string `json:"email"`
	GivenName   string `json:"given_name"`
	FamilyName  string `json:"family_name"`
	PictureLink string `json:"picture"`
}

func (g *GoogleClaims) Valid() error {
	// All claims should be non-empty.
	allPresent := g.Email != "" && g.GivenName != "" && g.FamilyName != "" && g.PictureLink != ""
	if !allPresent {
		return fmt.Errorf("insufficient data in claims")
	}

	return nil
}
