package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/shivanshkc/authorizer/pkg/config"
	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
)

// googleProviderName uniquely identifies the GoogleProvider OAuth implementation from other implementations.
const googleProviderName = "google"

// googleIssuers is the allowed list of issuers for a Google access token.
var googleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

// GoogleProvider implements the Provider interface for Google.
type GoogleProvider struct {
	Config       config.Config
	httpClient   *http.Client
	jwkRefresher *jwk.AutoRefresh
}

// NewGoogleProvider returns a new Google OAuth Provider instance.
func NewGoogleProvider(conf config.Config) *GoogleProvider {
	httpClient := &http.Client{}
	// Create the JWK refresher.
	refresher := jwk.NewAutoRefresh(context.Background())
	refresher.Configure(conf.OAuthGoogle.JwkUri, jwk.WithHTTPClient(httpClient))

	return &GoogleProvider{Config: conf, httpClient: httpClient, jwkRefresher: refresher}
}

func (g *GoogleProvider) Name() string {
	return googleProviderName
}

func (g *GoogleProvider) GetRedirectURL(ctx context.Context, state string) string {
	conf := g.Config.OAuthGoogle
	serverRedirectURI := g.Config.OAuthGeneral.ServerRedirectURI

	return fmt.Sprintf(
		"%s?scope=%s&include_granted_scopes=true&response_type=code&redirect_uri=%s&client_id=%s&state=%s",
		conf.RedirectURI,
		conf.Scopes,
		fmt.Sprintf("%s/api/auth/%s/callback", serverRedirectURI, g.Name()),
		conf.ClientID,
		state,
	)
}

func (g *GoogleProvider) TokenFromCode(ctx context.Context, code string) (string, error) {
	conf := g.Config.OAuthGoogle
	serverRedirectURI := g.Config.OAuthGeneral.ServerRedirectURI

	// Request body to obtain OAuth code.
	body, err := json.Marshal(map[string]interface{}{
		"code":          code,
		"client_id":     conf.ClientID,
		"client_secret": conf.ClientSecret,
		"redirect_uri":  fmt.Sprintf("%s/api/auth/%s/callback", serverRedirectURI, g.Name()),
		"grant_type":    "authorization_code",
	})
	if err != nil {
		return "", fmt.Errorf("error in json.Marshal call: %w", err)
	}

	// Form the HTTP request.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, conf.TokenEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("error in http.NewRequestWithContext call: %w", err)
	}

	// HTTP request to obtain OAuth code.
	resp, err := g.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("error in httpClient.Do call: %w", err)
	}
	// Close response body upon return.
	defer func() { _ = resp.Body.Close() }()

	// Check if the request failed.
	if !httputils.Is2xx(resp.StatusCode) {
		return "", fmt.Errorf("endpoint returned unsuccessful status code: %d", resp.StatusCode)
	}

	// Decode the success response.
	responseBody := &googleIDTokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return "", fmt.Errorf("failed to decode access token response body: %w", err)
	}

	// Success.
	return responseBody.IDToken, nil
}

func (g *GoogleProvider) ValidateToken(ctx context.Context, token string) (GoogleClaims, error) {
	// This call will try to get the JWK from the cache first.
	// If not found, it will make a call to the provided JWK URL.
	keySet, err := g.jwkRefresher.Fetch(ctx, g.Config.OAuthGoogle.JwkUri)
	if err != nil {
		return GoogleClaims{}, fmt.Errorf("failed to fetch JWK: %w", err)
	}

	// Various setting for token decode.
	parseOptions := []jwt.ParseOption{jwt.WithKeySet(keySet), jwt.WithValidate(true),
		jwt.WithAudience(g.Config.OAuthGoogle.ClientID)}

	// Decode with validation.
	decoded, err := jwt.Parse([]byte(token), parseOptions...)
	if err != nil {
		return GoogleClaims{}, errutils.Unauthorized().WithReasonErr(err)
	}

	// Verify issuer. There are two correct values that's why it can't be validated with parseOptions.
	iss := decoded.Issuer()
	if !slices.Contains(googleIssuers, iss) {
		slog.ErrorContext(ctx, "unknown issuer found in token. This could be an attack", "iss", iss)
		return GoogleClaims{}, errutils.Unauthorized().WithReasonStr("unknown issuer")
	}

	// Convert decoded token to map.
	claimsMap, err := decoded.AsMap(ctx)
	if err != nil {
		return GoogleClaims{}, fmt.Errorf("failed to convert decoded token to map: %w", err)
	}

	// Marshal to bytes to unmarshal into GoogleClaims.
	claimsBytes, err := json.Marshal(claimsMap)
	if err != nil {
		return GoogleClaims{}, fmt.Errorf("failed to marshal claims map: %w", err)
	}

	// Finally unmarshal into the required type.
	var claims GoogleClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return GoogleClaims{}, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

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
