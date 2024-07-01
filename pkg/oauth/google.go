package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"github.com/shivanshkc/authorizer/internal/database"
	"github.com/shivanshkc/authorizer/pkg/config"
	"github.com/shivanshkc/authorizer/pkg/utils/httputils"
)

// GoogleProvider implements the Provider interface for Google.
type GoogleProvider struct {
	Config     config.Config
	httpClient *http.Client
}

// NewGoogleProvider returns a new Google OAuth Provider instance.
func NewGoogleProvider(conf config.Config) *GoogleProvider {
	return &GoogleProvider{Config: conf, httpClient: &http.Client{}}
}

func (g *GoogleProvider) Name() string {
	return "google"
}

func (g *GoogleProvider) GetRedirectURL(ctx context.Context, state string) string {
	conf := g.Config.OAuthGoogle
	publicAddr := g.Config.Application.PublicAddr

	return fmt.Sprintf(
		"%s?scope=%s&include_granted_scopes=true&response_type=code&redirect_uri=%s&client_id=%s&state=%s",
		conf.RedirectURI,
		conf.Scopes,
		fmt.Sprintf("%s/api/auth/%s/callback", publicAddr, g.Name()),
		conf.ClientID,
		state,
	)
}

func (g *GoogleProvider) TokenFromCode(ctx context.Context, code string) (string, error) {
	conf := g.Config.OAuthGoogle
	publicAddr := g.Config.Application.PublicAddr

	// Request body to obtain OAuth code.
	body, err := json.Marshal(map[string]interface{}{
		"code":          code,
		"client_id":     conf.ClientID,
		"client_secret": conf.ClientSecret,
		"redirect_uri":  fmt.Sprintf("%s/api/auth/%s/callback", publicAddr, g.Name()),
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

func (g *GoogleProvider) UserFromToken(ctx context.Context, token string) (database.UserDoc, error) {
	// Decode claims.
	claims := &GoogleClaims{}
	if err := JWTDecodeUnsafe(token, claims); err != nil {
		return database.UserDoc{}, fmt.Errorf("error in jwtDecodeUnsafe call: %w", err)
	}

	// Convert claims structure to user document.
	return database.UserDoc{
		Email:       claims.Email,
		FirstName:   claims.GivenName,
		LastName:    claims.FamilyName,
		PictureLink: claims.PictureLink,
	}, nil
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

	jwt.Claims
}
