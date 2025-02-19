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
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

func TestHandler_Auth_Validations(t *testing.T) {
	mProvider := &mockProvider{name: "google"}
	mHandler := &Handler{config: config.Config{AllowedRedirectURLs: []string{"https://allowed.com"}}}

	for _, tc := range []struct {
		name             string
		mockProvider     oauth.Provider
		inputProvider    string
		inputRedirectURL string
		errSubstring     string
	}{
		{
			name:          "Too long provider length",
			inputProvider: strings.Repeat("a", 21),
			errSubstring:  errInvalidProvider.Error(),
		},
		{
			name:          "Invalid provider character",
			inputProvider: mProvider.name + "$$",
			errSubstring:  errInvalidProvider.Error(),
		},
		{
			name:             "Absent redirect_url",
			inputProvider:    mProvider.name,
			inputRedirectURL: "",
			errSubstring:     errInvalidCCU.Error(),
		},
		{
			name:             "Too long redirect_url",
			inputProvider:    mProvider.name,
			inputRedirectURL: strings.Repeat("a", 201),
			errSubstring:     errInvalidCCU.Error(),
		},
		{
			name:             "redirect_url not present in allow list",
			inputProvider:    mProvider.name,
			inputRedirectURL: mHandler.config.AllowedRedirectURLs[0] + "-random",
			errSubstring:     errUnknownRedirectURL.Error(),
		},
		{
			name:             "unknown provider",
			mockProvider:     mProvider,
			inputProvider:    mProvider.name + "-random",
			inputRedirectURL: mHandler.config.AllowedRedirectURLs[0],
			errSubstring:     errUnsupportedProvider.Error(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock response writer and request.
			rr, req, err := createMockAuthWR(tc.inputProvider, tc.inputRedirectURL)
			require.NoError(t, err, "Failed to create mock response writer and request")

			// Prepare and call the method to test.
			mHandler.googleProvider = tc.mockProvider
			mHandler.Auth(rr, req)

			// Verifications.
			require.Equal(t, http.StatusBadRequest, rr.Code, "Expected 400 status code")
			require.Contains(t, rr.Body.String(), tc.errSubstring)
		})
	}
}

func TestHandler_Auth(t *testing.T) {
	// Mock quantities for test.
	mProvider := "google"
	mRedirectURL := "https://allowed.com"
	mProviderAuthURL := "https://auth.google.com"

	// Create the mock handler.
	mHandler := NewHandler(
		config.Config{AllowedRedirectURLs: []string{mRedirectURL}},
		&mockProvider{name: mProvider, authURL: mProviderAuthURL}, nil)

	// Changing the state ID expiry to a shorter time so the test doesn't take too long.
	stateIDExpiry = time.Second

	// Create mock response writer and request.
	rr, req, err := createMockAuthWR(mProvider, mRedirectURL)
	require.NoError(t, err, "Failed to create mock response writer and request")

	// Invoke the method to test.
	mHandler.Auth(rr, req)

	// Testable quantities about the State ID Map.
	var insertedStateIDAny any
	var mapSize int
	// Loop over the State ID Map to populate the testable quantities.
	mHandler.stateIDMap.Range(func(key, value any) bool {
		mapSize++
		insertedStateIDAny = key
		return true
	})

	// The State ID Map must have only one entry.
	require.Equal(t, 1, mapSize, "State ID Map has more than 1 entries")

	// State ID must be a string.
	insertedStateID, ok := insertedStateIDAny.(string)
	require.True(t, ok, "State ID inserted in State ID Map is not a string")

	// State ID must be a UUID.
	_, errUUID := uuid.Parse(insertedStateID)
	require.NoError(t, errUUID, "State ID is not a valid UUID")

	// State ID must be deleted after expiry.
	time.Sleep(stateIDExpiry + 500*time.Millisecond)
	_, found := mHandler.stateIDMap.Load(insertedStateIDAny)
	require.False(t, found, "State ID was not deleted after expiry")

	// Verify response.
	require.Equal(t, http.StatusFound, rr.Code)
	require.Equal(t, mProviderAuthURL, rr.Header().Get("Location"))
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
