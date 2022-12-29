package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/shivanshkc/authorizer/src/configs"
	"github.com/shivanshkc/authorizer/src/core"
	"github.com/shivanshkc/authorizer/src/logger"
	"github.com/shivanshkc/authorizer/src/utils/httputils"
)

// GoogleOAuthProvider implements core.OAuthProvider for google.
type GoogleOAuthProvider struct {
	httpClient *http.Client
}

// NewGoogleOAuthProvider is the constructor for GoogleOAuthProvider.
func NewGoogleOAuthProvider() core.OAuthProvider {
	return &GoogleOAuthProvider{httpClient: &http.Client{}}
}

func (g *GoogleOAuthProvider) Name() string {
	return "google"
}

func (g *GoogleOAuthProvider) GetRedirectURL(ctx context.Context) string {
	// Prerequisites.
	conf := configs.Get()

	return fmt.Sprintf(
		"%s?scope=%s&include_granted_scopes=true&response_type=code&redirect_uri=%s&client_id=%s",
		conf.OAuthGoogle.RedirectURL,
		conf.OAuthGoogle.Scopes,
		fmt.Sprintf("%s/api/auth/%s/callback", conf.OAuthGeneral.ServerCallbackURL, g.Name()),
		conf.OAuthGoogle.ClientID,
	)
}

func (g *GoogleOAuthProvider) Code2Token(ctx context.Context, code string) (string, error) {
	// Prerequisites.
	conf := configs.Get()

	// Request body to obtain OAuth code.
	body, err := json.Marshal(map[string]interface{}{
		"code":          code,
		"client_id":     conf.OAuthGoogle.ClientID,
		"client_secret": conf.OAuthGoogle.ClientSecret,
		"redirect_uri":  fmt.Sprintf("%s/api/auth/%s/callback", conf.OAuthGeneral.ServerCallbackURL, g.Name()),
		"grant_type":    "authorization_code",
	})
	if err != nil {
		err = fmt.Errorf("error in json.Marshal call: %w", err)
		logger.Error(ctx, err.Error())
		return "", err
	}

	// Form the HTTP request.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, conf.OAuthGoogle.TokenEndpoint, bytes.NewReader(body))
	if err != nil {
		err = fmt.Errorf("error in http.NewRequestWithContext call: %w", err)
		logger.Error(ctx, err.Error())
		return "", err
	}

	// HTTP request to obtain OAuth code.
	resp, err := g.httpClient.Do(request)
	if err != nil {
		err = fmt.Errorf("error in httpClient.Do call: %w", err)
		logger.Error(ctx, err.Error())
		return "", err
	}
	// Close response body upon return.
	defer func() { _ = resp.Body.Close() }()

	// Check if the request failed.
	if !httputils.Is2xx(resp.StatusCode) {
		err = fmt.Errorf("endpoint returned unsuccessful status code: %d", resp.StatusCode)
		logger.Error(ctx, err.Error())
		return "", err
	}

	// Decode the success response.
	responseBody := &googleIDTokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		err = fmt.Errorf("error in httpClient.Do call: %w", err)
		logger.Error(ctx, err.Error())
		return "", err
	}

	// Success.
	return responseBody.IDToken, nil
}

func (g *GoogleOAuthProvider) Token2UserInfo(ctx context.Context, token string) (*core.UserDoc, error) {
	// Decode claims.
	claims := &GoogleClaims{}
	if err := JWTDecodeUnsafe(token, claims); err != nil {
		return nil, fmt.Errorf("error in jwtDecodeUnsafe call: %w", err)
	}

	// Convert claims structure to user document.
	return &core.UserDoc{
		Email:       claims.Email,
		FirstName:   claims.GivenName,
		LastName:    claims.FamilyName,
		PictureLink: claims.PictureLink,
	}, nil
}
