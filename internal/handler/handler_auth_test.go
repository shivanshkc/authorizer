package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestHandler_Auth_Validations(t *testing.T) {
	for _, tc := range []struct {
		name             string
		inputProvider    string
		inputRedirectURL string
		errSubstring     string
	}{
		{
			name:          "Too long provider length",
			inputProvider: strings.Repeat("a", 100),
			errSubstring:  errInvalidProvider.Error(),
		},
		{
			name:          "Invalid provider character",
			inputProvider: "google$$",
			errSubstring:  errInvalidProvider.Error(),
		},
		{
			name:             "Absent redirect_url",
			inputProvider:    "google",
			inputRedirectURL: "",
			errSubstring:     errInvalidCCU.Error(),
		},
		{
			name:             "Too long redirect_url",
			inputProvider:    "google",
			inputRedirectURL: strings.Repeat("a", 300),
			errSubstring:     errInvalidCCU.Error(),
		},
		{
			name:             "redirect_url not present in allow list",
			inputProvider:    "google",
			inputRedirectURL: "https://my-random-url.com",
			errSubstring:     errUnknownRedirectURL.Error(),
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

			// Method to test.
			(&Handler{}).Auth(rr, req)

			// Verifications.
			require.Equal(t, http.StatusBadRequest, rr.Code, "Expected 400 status code")
			require.Contains(t, rr.Body.String(), tc.errSubstring)
		})
	}
}
