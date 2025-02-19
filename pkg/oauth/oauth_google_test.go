package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/utils/httputils"

	_ "embed"
)

// customKeySet is an actual JWK for testing.
//
//go:embed testdata/key-set.json
var customKeySet string

func TestNewGoogle(t *testing.T) {
	// Use cancellable context to clean up JWK fetching goroutine upon return.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	google, err := NewGoogle(ctx, "mockClientID", "mockClientSecret",
		"mockCallbackURL", "mockScope1 mockScope2")

	require.NoError(t, err, "Expected no error in NewGoogle")
	require.NotNil(t, google, "Expected Google instance to be non-nil")
}

func TestGoogle_Name(t *testing.T) {
	require.Equal(t, "google", (&Google{}).Name())
}

func TestGoogle_GetAuthURL(t *testing.T) {
	// Use cancellable context to clean up JWK fetching goroutine upon return.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// Mock inputs.
	mockState := "mockState"

	// Mock client.
	google, err := newMockGoogle(ctx, nil)
	require.NoError(t, err, "Failed to create Google instance")

	// Method to test.
	authURL := google.GetAuthURL(ctx, mockState)

	// Verify that the returned URL is valid.
	parsed, err := url.Parse(authURL)
	require.NoError(t, err, "Expected URL parsing to succeed")

	// Returned URL must be the Google Auth URL.
	require.Equal(t, googleAuthURL, parsed.Scheme+"://"+parsed.Host+parsed.Path)

	// Match query params.
	require.Equal(t, google.clientID, parsed.Query().Get("client_id"),
		"Incorrect Client ID")
	require.Equal(t, google.scopes, parsed.Query().Get("scope"),
		"Incorrect Scope")
	require.Equal(t, "code", parsed.Query().Get("response_type"),
		"Incorrect Response Type")
	require.Equal(t, google.callbackURL, parsed.Query().Get("redirect_uri"),
		"Incorrect Redirect URI")
	require.Equal(t, "true", parsed.Query().Get("include_granted_scopes"),
		"Incorrect 'Include Granted Scopes'")
	require.Equal(t, mockState, parsed.Query().Get("state"),
		"Incorrect state")
}

func TestGoogle_TokenFromCode(t *testing.T) {
	// Use cancellable context to clean up JWK fetching goroutine upon return.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// Mock inputs.
	mockCode := "mockCode"

	// Mock client.
	google, err := newMockGoogle(ctx, nil)
	require.NoError(t, err, "Failed to create Google instance")

	// Mock success response.
	validGoogleTokenResponse := googleTokenResponse{
		AccessToken:  "mockAccessToken",
		IDToken:      "mockIDToken",
		ExpiresIn:    100,
		RefreshToken: "mockRefreshToken",
		Scope:        google.scopes,
		TokenType:    "mockTokenType",
	}

	validResponseJSON, err := json.Marshal(validGoogleTokenResponse)
	require.NoError(t, err, "Failed to marshal success response")

	for _, tc := range []struct {
		name         string
		mockResponse *http.Response
		errExpected  bool
	}{
		{
			name: "Everything good, no errors",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(validResponseJSON)),
			},
			errExpected: false,
		},
		{
			name:         "Request returns non 2xx status code, error expected",
			mockResponse: &http.Response{StatusCode: http.StatusBadRequest},
			errExpected:  true,
		},
		{
			name:         "Response body fails to unmarshal, error expected",
			mockResponse: &http.Response{StatusCode: http.StatusOK},
			errExpected:  true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// The method being tested must send the request with this body.
			expectedRequestBody := map[string]any{
				"code":          mockCode,
				"client_id":     google.clientID,
				"client_secret": google.clientSecret,
				"redirect_uri":  google.callbackURL,
				"grant_type":    "authorization_code",
			}

			// Transport to mock the HTTP request.
			transport := httputils.RoundTripFunc(func(req *http.Request) *http.Response {
				// Verify request details.
				require.Equal(t, googleTokenURL, req.URL.String())
				require.Equal(t, http.MethodPost, req.Method)

				// Unmarshal request body to verify it.
				var body map[string]any
				err := json.NewDecoder(req.Body).Decode(&body)
				require.NoError(t, err, "Expected body to be valid JSON")

				// Verify request body.
				require.Equal(t, expectedRequestBody, body, "Request body is not as expected")
				return tc.mockResponse
			})

			// Attach mock HTTP client.
			google.httpClient = &http.Client{Transport: transport}
			token, err := google.TokenFromCode(ctx, mockCode)

			// Verify based on error expectation.
			if tc.errExpected {
				require.Error(t, err, "Expected error but got none")
				require.Equal(t, "", token, "Expected ID token to be empty")
			} else {
				require.NoError(t, err, "Expected no error but got one")
				require.Equal(t, validGoogleTokenResponse.IDToken, token, "ID token does not match")
			}
		})
	}
}

func TestGoogle_DecodeToken(t *testing.T) {
	// Use cancellable context to clean up JWK fetching goroutine upon return.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// Mock Google client.
	google, err := newMockGoogle(ctx, nil)
	require.NoError(t, err, "Failed to create Google instance")

	// Get the key set to generate tokens for testing.
	keySet, err := google.jwkCache.Lookup(ctx, googleJWKURL)
	require.NoError(t, err, "Failed to lookup JWK")

	nowTime := time.Now().UTC()
	expiresAt := time.Date(nowTime.Year(), nowTime.Month(), nowTime.Day(),
		// Expires after an hour.
		nowTime.Hour()+1, nowTime.Minute(), 0, 0, time.UTC)

	// Inputs required to create a valid token.
	tokenInput := generateTokenInput{
		keySet:   keySet,
		audience: google.clientID,
		issuer:   googleIssuers[0],
		expiry:   expiresAt,
		claims: Claims{
			Iss:        googleIssuers[0],
			Exp:        expiresAt,
			Email:      "mockEmail",
			GivenName:  "mockGivenName",
			FamilyName: "mockFamilyName",
			Picture:    "mockPictureURL",
		},
	}

	// Valid token for the happy path.
	validToken, err := generateToken(tokenInput)
	require.NoError(t, err, "Failed to generate valid token")

	// Expired token.
	var expiredTokenInput = tokenInput
	expiredTokenInput.expiry = time.Now().Add(-time.Hour)
	expiredToken, err := generateToken(expiredTokenInput)
	require.NoError(t, err, "Failed to generate expired token")

	// Bad audience token.
	var badAudienceInput = tokenInput
	badAudienceInput.audience = google.clientID + "Random"
	badAudienceToken, err := generateToken(badAudienceInput)
	require.NoError(t, err, "Failed to generate bad audience token")

	// Bad issuer token.
	var badIssuerInput = tokenInput
	badIssuerInput.issuer = googleIssuers[0] + "Random"
	badIssuerToken, err := generateToken(badIssuerInput)
	require.NoError(t, err, "Failed to generate bad issuer token")

	for _, tc := range []struct {
		name           string
		token          string
		expectedClaims Claims
		errSubstring   string
	}{
		{
			name:           "Valid token, no errors",
			token:          validToken,
			expectedClaims: tokenInput.claims,
			errSubstring:   "",
		},
		{
			name:           "Expired token, error expected",
			token:          expiredToken,
			expectedClaims: Claims{},
			errSubstring:   `"exp" not satisfied`,
		},
		{
			name:           "Bad audience token, error expected",
			token:          badAudienceToken,
			expectedClaims: Claims{},
			errSubstring:   `"aud" not satisfied`,
		},
		{
			name:           "Bad issuer token, error expected",
			token:          badIssuerToken,
			expectedClaims: Claims{},
			errSubstring:   `jwt has unknown issuer`,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			claims, err := google.DecodeToken(ctx, tc.token)
			if tc.errSubstring != "" {
				require.Error(t, err, "Expected error but got none")
				require.Contains(t, err.Error(), tc.errSubstring)
			} else {
				require.NoError(t, err, "Expected no error but got one")
				require.Equal(t, tc.expectedClaims, claims, "Claims are not as expected")
			}
		})
	}

}

// generateTokenInput specifies all inputs to generate a signed token for testing.
type generateTokenInput struct {
	keySet   jwk.Set
	audience string
	issuer   string
	expiry   time.Time
	claims   Claims
}

func generateToken(input generateTokenInput) (string, error) {
	// Add basic claims to the token.
	builder := jwt.NewBuilder().Expiration(input.expiry).Audience([]string{input.audience}).Issuer(input.issuer)
	// Add custom claims.
	builder.Claim("email", input.claims.Email)
	builder.Claim("given_name", input.claims.GivenName)
	builder.Claim("family_name", input.claims.FamilyName)
	builder.Claim("picture", input.claims.Picture)

	// Build the token. Note that this is not the JWT string yet, it requires signing.
	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("error in builder.Build call: %w", err)
	}

	// Get the key to sign the JWT with.
	key, found := input.keySet.Key(0)
	if !found {
		return "", fmt.Errorf("key not found at index 0")
	}

	// Get the algorithm of the key.
	algo, _ := key.Algorithm()

	// Sign token.
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(algo, key))
	if err != nil {
		return "", fmt.Errorf("error in jwt.Sign call: %w", err)
	}

	return string(tokenBytes), nil
}

// newMockGoogle returns a new mock Google instance.
//
// It mocks all parameters including the JWK cache (with a mock HTTP RC client).
func newMockGoogle(ctx context.Context, httpClient *http.Client) (*Google, error) {
	// Transport for the mock HTTP client that will be passed to the HTTP RC client.
	transport := httputils.RoundTripFunc(func(_ *http.Request) *http.Response {
		body := io.NopCloser(strings.NewReader(customKeySet))
		return &http.Response{StatusCode: http.StatusOK, Body: body}
	})

	// Mock HTTP RC client.
	httpRCClient := httprc.NewClient(httprc.WithHTTPClient(&http.Client{Transport: transport}))

	// Create JWK cache object with mock HTTP client.
	cache, err := jwk.NewCache(ctx, httpRCClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK cache: %w", err)
	}

	// Register Google's JWK URL.
	if err := cache.Register(ctx, googleJWKURL); err != nil {
		return nil, fmt.Errorf("failed to register Google JWK URL: %w", err)
	}

	// If an HTTP client is not provided, use a basic one.
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &Google{
		clientID:     "mockClientID",
		clientSecret: "mockClientSecret",
		callbackURL:  "mockCallbackURL",
		scopes:       "mockScope1 mockScope2",
		httpClient:   httpClient,
		jwkCache:     cache,
	}, nil
}
