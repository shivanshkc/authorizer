package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

// Google implements the Provider interface for Google.
//
// Read documentation here: https://developers.google.com/identity/protocols/oauth2/web-server
type Google struct {
	// clientID of your application.
	clientID string
	// clientSecret for your application.
	clientSecret string
	// callbackURL is URL that Google will hit after the user has authenticated.
	callbackURL string
	// scopes for the request. Most basic scope:
	// https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile
	scopes string

	httpClient *http.Client
}

// googleTokenResponse is the body schema of the response returned by Google's code-to-token endpoint.
//
// See this: https://developers.google.com/identity/protocols/oauth2/web-server#exchange-authorization-code
type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// NewGoogle instantiates a new Google provider instance.
func NewGoogle(clientID, clientSecret, callbackURL, scopes string) *Google {
	return &Google{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		scopes:       scopes,
		httpClient:   &http.Client{},
	}
}

func (g *Google) Name() string {
	return "google"
}

func (g *Google) GetAuthURL(ctx context.Context, state string) (string, error) {
	// Convert to Go's URL type to conveniently build the query string.
	// This auth endpoint URL is documented here:
	// https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
	u, err := url.Parse(`https://accounts.google.com/o/oauth2/v2/auth`)
	if err != nil {
		return "", fmt.Errorf("error in url.Parse call: %w", err)
	}

	// Add all query parameters.
	q := u.Query()
	q.Set("client_id", g.clientID)
	q.Set("scope", g.scopes)
	q.Set("response_type", "code")
	q.Set("redirect_uri", g.callbackURL)
	q.Set("include_granted_scopes", "true")
	q.Set("state", state)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (g *Google) TokenFromCode(ctx context.Context, code string) (string, error) {
	// Endpoint to obtain token as per:
	// https://developers.google.com/identity/protocols/oauth2/web-server#exchange-authorization-code
	endpoint := `https://oauth2.googleapis.com/token`

	// Request body.
	body := map[string]any{
		"code":          code,
		"client_id":     g.clientID,
		"client_secret": g.clientSecret,
		"redirect_uri":  g.callbackURL,
		"grant_type":    "authorization_code",
	}

	// Marshal body to use as an io.Reader.
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("error in json.Marshal call: %w", err)
	}

	// Form the HTTP request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("error in http.NewRequestWithContext call: %w", err)
	}

	// Execute request.
	res, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error in httpClient.Do call: %w", err)
	}
	// Close response body upon return.
	defer func() { _ = res.Body.Close() }()

	// Check if the request failed.
	if !httputils.Is2xx(res.StatusCode) {
		// Decode response body only for logging.
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			resBody = []byte("error in io.ReadAll call: " + err.Error())
		}
		slog.ErrorContext(ctx, "request failed", "code", res.StatusCode, "body", string(resBody))
		return "", fmt.Errorf("request failed with status code: %d", res.StatusCode)
	}

	// Decode the success response.
	tokenResponse := &googleTokenResponse{}
	if err := json.NewDecoder(res.Body).Decode(tokenResponse); err != nil {
		return "", fmt.Errorf("error in json Decode call: %w", err)
	}

	return tokenResponse.IDToken, nil
}

func (g *Google) DecodeToken(ctx context.Context, token string) (Claims, error) {
	jwkEndpoint := `https://www.googleapis.com/oauth2/v3/certs`
	_ = jwkEndpoint
	return Claims{}, nil
}
