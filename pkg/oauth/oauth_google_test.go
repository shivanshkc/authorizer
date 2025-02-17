package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

func TestGoogle_Name(t *testing.T) {
	require.Equal(t, "google", (&Google{}).Name())
}

func TestGoogle_GetAuthURL(t *testing.T) {
	// Mock inputs.
	mockState := "mockState"

	// Mock client.
	google, err := NewGoogle(context.Background(), "mockClientID", "mockClientSecret",
		"mockCallbackURL", "mockScope1 mockScope2")
	require.NoError(t, err, "Failed to create Google instance")

	// Method to test.
	authURL := google.GetAuthURL(context.Background(), mockState)

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
	// Mock inputs.
	mockCode := "mockCode"

	// Mock client.
	google, err := NewGoogle(context.Background(), "mockClientID", "mockClientSecret",
		"mockCallbackURL", "mockScope1 mockScope2")
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
			token, err := google.TokenFromCode(context.Background(), mockCode)

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

func TestGoogle_DecodeToken(t *testing.T) {}
