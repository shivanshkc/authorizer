package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/config"
)

func TestHandler_Auth_Validations(t *testing.T) {
	// Requests carrying this provider name will pass the provider check.
	const correctProviderName = "google"
	// Requests carrying this redirect URL will pass the redirect URL check.
	const allowedRedirectURL = "https://allowed.com"
	// For brevity.
	mConfig := config.Config{AllowedRedirectURLs: []string{allowedRedirectURL}}

	for _, tc := range []struct {
		name string
		// Request inputs.
		inputProviderName string
		inputRedirectURL  string
		// Expectations.
		expectProviderCall bool
		errSubstring       string
	}{
		{
			name:              "Too long provider length",
			inputProviderName: strings.Repeat("a", 21),
			errSubstring:      errInvalidProvider.Error(),
		},
		{
			name:              "Invalid provider character",
			inputProviderName: correctProviderName + "$$",
			errSubstring:      errInvalidProvider.Error(),
		},
		{
			name:              "Absent redirect_url",
			inputProviderName: correctProviderName,
			inputRedirectURL:  "",
			errSubstring:      errInvalidCCU.Error(),
		},
		{
			name:              "Too long redirect_url",
			inputProviderName: correctProviderName,
			inputRedirectURL:  strings.Repeat("a", 201),
			errSubstring:      errInvalidCCU.Error(),
		},
		{
			name:              "redirect_url is not a valid URL",
			inputProviderName: correctProviderName,
			inputRedirectURL:  "invalid-url@@",
			errSubstring:      errInvalidCCU.Error(),
		},
		{
			name:              "Allow list does not contain the redirect_url",
			inputProviderName: correctProviderName,
			inputRedirectURL:  allowedRedirectURL + "-random",
			errSubstring:      errUnknownRedirectURL.Error(),
		},
		{
			name:               "Unknown provider",
			inputProviderName:  correctProviderName + "-random",
			inputRedirectURL:   allowedRedirectURL,
			expectProviderCall: true,
			errSubstring:       errUnsupportedProvider.Error(),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create mock response writer and request.
			rr, req, err := createMockAuthWR(tc.inputProviderName, tc.inputRedirectURL)
			require.NoError(t, err, "Failed to create mock response writer and request")

			// Prepare the mock provider instance.
			mProvider := &mockProvider{}
			if tc.expectProviderCall {
				mProvider.On("Name").Return(correctProviderName).Once()
			}

			// Prepare and call the method to test.
			mHandler := &Handler{config: mConfig, googleProvider: mProvider}
			mHandler.Auth(rr, req)

			// Verifications.
			require.Equal(t, http.StatusBadRequest, rr.Code, "Expected 400 status code")
			require.Contains(t, rr.Body.String(), tc.errSubstring)
			mProvider.AssertExpectations(t)
		})
	}
}

func TestHandler_Auth(t *testing.T) {
	// Mock quantities for test.
	mProviderName := "google"
	mRedirectURL := "https://allowed.com"
	mProviderAuthURL := "https://auth.google.com"

	// Setup mock provider.
	mProvider := &mockProvider{}
	mProvider.On("Name").Return(mProviderName).Once()
	mProvider.On("GetAuthURL", mock.Anything, mock.Anything, mock.Anything).Return(mProviderAuthURL).Once()

	// Create the mock handler.
	mHandler := NewHandler(config.Config{AllowedRedirectURLs: []string{mRedirectURL}}, mProvider, nil, nil)

	// Changing the state key expiry time to a shorter time so the test doesn't take too long.
	stateKeyExpiry = time.Second

	// Create mock response writer and request.
	rr, req, err := createMockAuthWR(mProviderName, mRedirectURL)
	require.NoError(t, err, "Failed to create mock response writer and request")

	// Invoke the method to test.
	mHandler.Auth(rr, req)

	// Testable quantities about the state map.
	var insertedStateKeyAny, insertedStateValueAny any
	var mapSize int
	// Loop over the state map to populate the testable quantities.
	mHandler.stateMap.Range(func(key, value any) bool {
		mapSize++
		insertedStateKeyAny, insertedStateValueAny = key, value
		return true
	})

	// The state map must have only one entry.
	require.Equal(t, 1, mapSize, "State map has more than 1 entries")

	// The state key must be a string.
	insertedStateKey, ok := insertedStateKeyAny.(string)
	require.True(t, ok, "State key inserted in the State Map is not a string")

	// The state value must be of correct type.
	insertedStateValue, ok := insertedStateValueAny.(stateValue)
	require.True(t, ok, "State value inserted in the State Map is of unexpected type")

	// State key must be a UUID.
	_, errUUID := uuid.Parse(insertedStateKey)
	require.NoError(t, errUUID, "State key is not a valid UUID")

	// State value verification.
	require.NotEmpty(t, insertedStateValue.CodeVerifier, "Code verifier is empty")
	require.Equal(t, mRedirectURL, insertedStateValue.ClientCallbackURL, "CCU does not match")

	// State key must be deleted after expiry.
	time.Sleep(stateKeyExpiry + 500*time.Millisecond)
	_, found := mHandler.stateMap.Load(insertedStateKeyAny)
	require.False(t, found, "State key was not deleted after expiry")

	// Verify response.
	require.Equal(t, http.StatusFound, rr.Code)
	require.Equal(t, mProviderAuthURL, rr.Header().Get("Location"))
	mProvider.AssertExpectations(t)
}

// createMockAuthWR creates a mock ResponseWriter and Request to test the Auth handler.
func createMockAuthWR(provider, redirectURL string) (*httptest.ResponseRecorder, *http.Request, error) {
	// Mock HTTP request.
	req, err := http.NewRequest(http.MethodGet, "/mock", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP request")
	}

	// Set path params.
	req = mux.SetURLVars(req, map[string]string{"provider": provider})
	// Set query params.
	q := req.URL.Query()
	q.Set("redirect_url", redirectURL)
	req.URL.RawQuery = q.Encode()

	return httptest.NewRecorder(), req, nil
}
