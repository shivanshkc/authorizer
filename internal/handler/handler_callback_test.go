package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
)

func TestHandler_Callback_StateValidation(t *testing.T) {
	mStateID := uuid.NewString()
	mAllowedURLs := []string{"https://allowed.com", "https://wow.com"}
	mHandler := &Handler{config: config.Config{AllowedRedirectURLs: mAllowedURLs}, stateIDMap: &sync.Map{}}

	for _, tc := range []struct {
		name string
		// Request inputs.
		inputState string
		// Expectations.
		expectedLocation string
		errSubstring     string
	}{
		{
			name:             "State absent",
			inputState:       "",
			expectedLocation: mAllowedURLs[0],
			errSubstring:     errInvalidState.Error(),
		},
		{
			name:             "State too long",
			inputState:       strings.Repeat("z", 401),
			expectedLocation: mAllowedURLs[0],
			errSubstring:     errInvalidState.Error(),
		},
		{
			name:             "State not a valid base64",
			inputState:       "Just some gibberish",
			expectedLocation: mAllowedURLs[0],
			errSubstring:     errMalformedState.Error(),
		},
		{
			name: "State not present in the State ID Map",
			inputState: base64.StdEncoding.EncodeToString(
				[]byte(`{"ID":"` + mStateID + `","ClientCallbackURL":"` + mAllowedURLs[1] + `"}`)),
			expectedLocation: mAllowedURLs[1],
			errSubstring:     errutils.RequestTimeout().Error(),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create mock response writer and request.
			w, r, err := createMockCallbackWR("anything", tc.inputState, "anything", "")
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Verify response code and headers.
			require.Equal(t, http.StatusFound, w.Code)
			// Verify redirect URL and error message.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")
			require.Equal(t, tc.expectedLocation, parsed.Scheme+"://"+parsed.Host)
			require.Contains(t, tc.errSubstring, parsed.Query().Get("error"))
		})
	}
}

// createMockCallbackWR creates a mock ResponseWriter and Request to test the Callback handler.
func createMockCallbackWR(provider, state, code, e string) (*httptest.ResponseRecorder, *http.Request, error) {
	// Mock HTTP request.
	req, err := http.NewRequest(http.MethodGet, "/mock", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP request")
	}

	// Set path params.
	req = mux.SetURLVars(req, map[string]string{"provider": provider})
	// Set query params.
	q := req.URL.Query()
	q.Set("state", state)
	q.Set("code", code)
	q.Set("error", e)
	req.URL.RawQuery = q.Encode()

	return httptest.NewRecorder(), req, nil
}
