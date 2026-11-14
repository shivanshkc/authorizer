package handler

import (
	"github.com/shivanshkc/authorizer/pkg/oauth"
	"github.com/shivanshkc/authorizer/pkg/tokener"
)

// makeClaims prepares the "tokener.Claims" type by copying user's details from the "oauth.Claims" type.
//
// All members that are not set here are set by the tokener package itself.
func makeClaims(claims oauth.Claims) tokener.Claims {
	return tokener.Claims{
		Sub:        claims.Email,
		Email:      claims.Email,
		GivenName:  claims.GivenName,
		FamilyName: claims.FamilyName,
		Picture:    claims.Picture,
	}
}
