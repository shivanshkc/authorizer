package core

import (
	"context"
	"net/http"
)

// OAuthRedirect redirects the caller to the specified provider's auth page.
func OAuthRedirect(ctx context.Context, provider string, writer http.ResponseWriter) error {
	return nil
}
