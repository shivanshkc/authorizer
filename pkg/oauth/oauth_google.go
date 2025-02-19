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
	"slices"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/shivanshkc/authorizer/internal/utils/httputils"
	"github.com/shivanshkc/authorizer/internal/utils/miscutils"
)

const (
	// Source: https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
	googleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	// Source: https://developers.google.com/identity/protocols/oauth2/web-server#exchange-authorization-code
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleJWKURL   = "https://www.googleapis.com/oauth2/v3/certs"
)

var (
	// parsedGoogleAuthURL removes the need to repeatedly parse the auth URL.
	parsedGoogleAuthURL = miscutils.MustParseURL(googleAuthURL)
	// googleIssuers is the list of valid values for the "iss" (issuer) claim in a Google ID token.
	googleIssuers = []string{"accounts.google.com", "https://accounts.google.com"}
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
	jwkCache   *jwk.Cache
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
//
// It accepts a context because it periodically fetches Google's JSON Web Keys and the context can be used to cancel
// the underlying fetching goroutine.
func NewGoogle(ctx context.Context, clientID, clientSecret, callbackURL, scopes string) (*Google, error) {
	// This allows auto-refresh of the JWK as Google keeps rotating them.
	// See the documentation here:
	// https://github.com/lestrrat-go/jwx/tree/develop/v3/jwk#auto-refresh-a-key-during-a-long-running-process
	jwkCache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("error in jwk.NewCache call: %w", err)
	}

	// Register Google's JWK fetch URL.
	if err := jwkCache.Register(ctx, googleJWKURL); err != nil {
		return nil, fmt.Errorf("error in jwkCache.Register call: %w", err)
	}

	return &Google{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		scopes:       scopes,
		httpClient:   &http.Client{},
		jwkCache:     jwkCache,
	}, nil
}

func (g *Google) Name() string {
	return "google"
}

func (g *Google) GetAuthURL(ctx context.Context, state string) string {
	var u = &url.URL{}
	// Copy the auth URL value into local pointer. This must not modify the original URL variable.
	*u = *parsedGoogleAuthURL

	// Add all query parameters.
	q := u.Query()
	q.Set("client_id", g.clientID)
	q.Set("scope", g.scopes)
	q.Set("response_type", "code")
	q.Set("redirect_uri", g.callbackURL)
	q.Set("include_granted_scopes", "true")
	q.Set("state", state)

	u.RawQuery = q.Encode()
	return u.String()
}

func (g *Google) TokenFromCode(ctx context.Context, code string) (string, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, bytes.NewReader(bodyBytes))
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
	// Google's documentation for ID token verification:
	// https://developers.google.com/identity/gsi/web/guides/verify-google-id-token

	// Obtain Google's key set.
	set, err := g.jwkCache.Lookup(ctx, googleJWKURL)
	if err != nil {
		return Claims{}, fmt.Errorf("error in jwkCache.Lookup call: %w", err)
	}

	// Parse and validate the token with the obtained key set.
	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(set), jwt.WithValidate(true), jwt.WithAudience(g.clientID))
	if err != nil {
		return Claims{}, fmt.Errorf("error in jwt.Parse call: %w", err)
	}

	// Validate issuer. This could not be done with jwt.WithIssuer because there are two allowed values.
	if iss, _ := parsed.Issuer(); !slices.Contains(googleIssuers, iss) {
		return Claims{}, fmt.Errorf("jwt has unknown issuer: %s", iss)
	}

	// Claims to return.
	var claims Claims

	// Attach the ExpiresAt claim.
	expiry, found := parsed.Expiration()
	if !found {
		return Claims{}, fmt.Errorf("exp field is empty in JWT")
	}
	claims.ExpiresAt = expiry

	if err := parsed.Get("email", &claims.Email); err != nil {
		return Claims{}, fmt.Errorf("failed to decode email claim: %w", err)
	}
	if err := parsed.Get("given_name", &claims.GivenName); err != nil {
		return Claims{}, fmt.Errorf("failed to decode given_name claim: %w", err)
	}
	if err := parsed.Get("family_name", &claims.FamilyName); err != nil {
		return Claims{}, fmt.Errorf("failed to decode family_name claim: %w", err)
	}
	if err := parsed.Get("picture", &claims.PictureURL); err != nil {
		return Claims{}, fmt.Errorf("failed to decode picture claim: %w", err)
	}

	return claims, nil
}
