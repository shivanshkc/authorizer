package core

import (
	"context"
	"net/http"

	"github.com/shivanshkc/authorizer/src/utils/httputils"
)

// OAuthRedirect redirects the caller to the specified provider's auth page.
func OAuthRedirect(ctx context.Context, provider string, writer http.ResponseWriter) error {
	// Fetch the required provider from the map.
	oAuthProvider, exists := ProviderMap[provider]
	if !exists {
		return ErrProviderNotFound
	}

	// Location header is required for redirection in the browser.
	headers := map[string]string{"Location": oAuthProvider.GetRedirectURL(ctx)}
	// Write response.
	httputils.Write(writer, http.StatusFound, headers, nil)

	return nil
}
