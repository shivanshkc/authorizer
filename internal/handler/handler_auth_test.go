package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
			// Mock HTTP response.
			rr := httptest.NewRecorder()

			// Mock HTTP request.
			req, err := http.NewRequest(http.MethodGet, "/mock", nil)
			require.NoError(t, err, "Failed to create HTTP request")

			// Set path params.
			req = mux.SetURLVars(req, map[string]string{"provider": tc.inputProvider})
			// Set query params.
			q := req.URL.Query()
			q.Set("redirect_url", tc.inputRedirectURL)
			req.URL.RawQuery = q.Encode()

			// Prepare and call the method to test.
			mHandler.googleProvider = tc.mockProvider
			mHandler.Auth(rr, req)

			// Verifications.
			require.Equal(t, http.StatusBadRequest, rr.Code, "Expected 400 status code")
			require.Contains(t, rr.Body.String(), tc.errSubstring)
		})
	}
}
