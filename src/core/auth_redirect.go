package core

import (
	"context"
	"encoding/base64"
)

// GetProviderRedirectURI returns the redirect URI for the given provider.
func GetProviderRedirectURI(ctx context.Context, provider, clientRedirectURI string) (string, error) {
	// Fetch the required provider from the map.
	oAuthProvider, exists := ProviderMap[provider]
	if !exists {
		return "", ErrProviderNotFound
	}

	// Encode the client redirect URI to base64 to make it a suitable query parameter.
	cruB64 := base64.StdEncoding.EncodeToString([]byte(clientRedirectURI))

	// Location header is required for redirection in the browser.
	return oAuthProvider.GetRedirectURL(ctx, cruB64), nil
}
