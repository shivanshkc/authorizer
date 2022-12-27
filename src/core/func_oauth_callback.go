package core

import (
	"context"
	"net/http"
)

// OAuthCallback handles the callback received from the provider.
func OAuthCallback(ctx context.Context, provider string, code string, writer http.ResponseWriter) error {
	return nil
}
