package oauth

import (
	"context"
	"fmt"
	"net/url"
)

// Google implements the Provider interface for Google.
type Google struct {
	// ClientID of your application.
	ClientID string
	// ClientSecret for your application.
	ClientSecret string
	// CallbackURL is URL that Google will hit after the user has authenticated.
	CallbackURL string
	// Scopes for the request. Most basic scope:
	// https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile
	Scopes string
}

func (g *Google) Name() string {
	return "google"
}

func (g *Google) GetRedirectURL(ctx context.Context, state string) (string, error) {
	// Convert to Go's URL type to conveniently build the query string.
	u, err := url.Parse(`https://accounts.google.com/o/oauth2/v2/auth`)
	if err != nil {
		return "", fmt.Errorf("error in url.Parse call: %w", err)
	}

	// Add all query parameters.
	q := u.Query()
	q.Set("client_id", g.ClientID)
	q.Set("scope", g.Scopes)
	q.Set("response_type", "code")
	q.Set("redirect_uri", g.CallbackURL)
	q.Set("include_granted_scopes", "true")
	q.Set("state", state)
	//q.Set("prompt", "none")

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (g *Google) TokenFromCode(ctx context.Context, code string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (g *Google) ValidateToken(ctx context.Context, token string) (Claims, error) {
	//TODO implement me
	panic("implement me")
}
