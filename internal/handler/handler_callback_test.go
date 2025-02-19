package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
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
			require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
		})
	}
}

func TestHandler_Callback_Validations(t *testing.T) {
	// Common mock inputs and implementations.
	mStateID, mCCU := uuid.NewString(), "https://allowed.com"
	mState := base64.StdEncoding.EncodeToString([]byte(`{"ID":"` + mStateID + `","ClientCallbackURL":"` + mCCU + `"}`))
	mHandler := &Handler{config: config.Config{AllowedRedirectURLs: []string{mCCU}}, stateIDMap: &sync.Map{}}

	for _, tc := range []struct {
		name string
		// Mock inputs.
		inputProvider string
		inputCode     string
		inputError    string
		// Expectations.
		expectedLocation string
		errSubstring     string
	}{
		{
			name:             "Too long provider length",
			inputProvider:    strings.Repeat("a", 21),
			expectedLocation: mCCU,
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Invalid provider character",
			inputProvider:    "google$$",
			expectedLocation: mCCU,
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Absent auth code",
			inputProvider:    "google",
			inputCode:        "",
			expectedLocation: mCCU,
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Too long auth code",
			inputProvider:    strings.Repeat("a", 401),
			inputCode:        "",
			expectedLocation: mCCU,
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Invalid characters in auth code",
			inputProvider:    "google",
			inputCode:        "code$$",
			expectedLocation: mCCU,
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Error received from provider",
			inputProvider:    "google",
			inputCode:        "valid-code",
			inputError:       "access_denied",
			expectedLocation: mCCU,
			errSubstring:     "access_denied",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Populate the State ID Map. This must be empty by the end.
			mHandler.stateIDMap.Store(mStateID, struct{}{})

			// Create mock response writer and request.
			w, r, err := createMockCallbackWR(tc.inputProvider, mState, tc.inputCode, tc.inputError)
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state ID was deleted from the State ID Map.
			_, found := mHandler.stateIDMap.LoadAndDelete(mStateID)
			require.False(t, found, "Expected state ID to be deleted but it was not")

			// Verify response code and headers.
			require.Equal(t, http.StatusFound, w.Code)
			// Verify the redirection URL.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")
			require.Equal(t, tc.expectedLocation, parsed.Scheme+"://"+parsed.Host)
			// Check the error query parameter.
			require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
		})
	}
}

func TestHandler_Callback(t *testing.T) {
	// Common mock inputs.
	errMock := errors.New("mock error")
	mStateID, mCCU := uuid.NewString(), "https://allowed.com"
	mockCode := "4/0ASVgi3Iwlq42Bl8wh6-XUEpdSNFremRaxzXPWpRZxqYWW-xGo54-DAV94ZbLKx033sG5qA"
	mState := base64.StdEncoding.EncodeToString([]byte(`{"ID":"` + mStateID + `","ClientCallbackURL":"` + mCCU + `"}`))

	// Common mock implementations.
	mProvider := &mockProvider{
		name:             "google",
		errTokenFromCode: nil,
		token:            "mockToken.Darth.Vader",
		errDecodeToken:   nil,
		claims:           oauth.Claims{ExpiresAt: time.Now().Add(time.Hour)},
	}

	mHandler := &Handler{
		config:         config.Config{AllowedRedirectURLs: []string{mCCU}},
		stateIDMap:     &sync.Map{},
		googleProvider: mProvider,
	}

	for _, tc := range []struct {
		name string
		// Mock inputs.
		providerFunc func() *mockProvider
		isHTTPS      bool
		// Expectations.
		expectTokenFromCodeCall bool
		expectDecodeTokenCall   bool
		errSubstring            string
	}{
		{
			name:                    "Everything good, application on HTTPS domain, no errors",
			providerFunc:            func() *mockProvider { return mProvider.Clone() },
			isHTTPS:                 true,
			expectTokenFromCodeCall: true,
			expectDecodeTokenCall:   true,
			errSubstring:            "",
		},
		{
			name:                    "Everything good, application on HTTP domain, no errors",
			providerFunc:            func() *mockProvider { return mProvider.Clone() },
			expectTokenFromCodeCall: true,
			expectDecodeTokenCall:   true,
			errSubstring:            "",
		},
		{
			name: "Unknown provider",
			providerFunc: func() *mockProvider {
				p := mProvider.Clone()
				p.name += "-unknown"
				return p
			},
			expectTokenFromCodeCall: false,
			expectDecodeTokenCall:   false,
			errSubstring:            errutils.InternalServerError().Error(),
		},
		{
			name: "TokenFromCode method returns error",
			providerFunc: func() *mockProvider {
				p := mProvider.Clone()
				p.errTokenFromCode = errMock
				return p
			},
			expectTokenFromCodeCall: true,
			expectDecodeTokenCall:   false,
			errSubstring:            errutils.InternalServerError().Error(),
		},
		{
			name: "DecodeToken method returns error",
			providerFunc: func() *mockProvider {
				p := mProvider.Clone()
				p.errDecodeToken = errMock
				return p
			},
			expectTokenFromCodeCall: true,
			expectDecodeTokenCall:   true,
			errSubstring:            errutils.InternalServerError().Error(),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Set application base URL as per HTTPS status.
			// This is required to test the "Secure" field of the cookie.
			if tc.isHTTPS {
				mHandler.config.Application.BaseURL = "https://application.com"
			} else {
				mHandler.config.Application.BaseURL = "http://application.com"
			}

			// Populate the State ID Map. This must be empty by the end.
			mHandler.stateIDMap.Store(mStateID, struct{}{})
			// Provider to use for this test.
			thisProvider := tc.providerFunc()
			mHandler.googleProvider = thisProvider

			// Create mock response writer and request.
			w, r, err := createMockCallbackWR(mProvider.name, mState, mockCode, "")
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state ID was deleted from the State ID Map.
			_, found := mHandler.stateIDMap.LoadAndDelete(mStateID)
			require.False(t, found, "Expected state ID to be deleted but it was not")

			// Verify if the provider methods were invoked and with correct arguments.
			if tc.expectTokenFromCodeCall {
				require.Equal(t, mockCode, thisProvider.argTokenFromCode,
					"TokenFromCode was not called with correct arguments")
			} else {
				require.Equal(t, "", thisProvider.argTokenFromCode,
					"TokenFromCode unexpectedly called, was the mockProvider instance correctly reset?")
			}

			if tc.expectDecodeTokenCall {
				require.Equal(t, thisProvider.token, thisProvider.argDecodeToken,
					"DecodeToken was not called with correct arguments")
			} else {
				require.Equal(t, "", thisProvider.argDecodeToken,
					"DecodeToken unexpectedly called, was the mockProvider instance correctly reset?")
			}

			// Verify response code.
			require.Equal(t, http.StatusFound, w.Code)
			// Verify redirection URL.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")
			require.Equal(t, mCCU, parsed.Scheme+"://"+parsed.Host)

			// Verify in case of error.
			if tc.errSubstring != "" {
				require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
				return
			}

			// Verify success behaviour.
			require.Equal(t, parsed.Query().Get("provider"), mProvider.name)
			// Get the cookie from the response.
			cookie := w.Result().Cookies()[0]
			// Verify cookie fields.
			require.Equal(t, thisProvider.token, cookie.Value, "Cookie value does not match")
			require.Equal(t, "/", cookie.Path, "Cookie path does not match")
			require.NotEqual(t, 0, cookie.MaxAge, "Cookie max age does not match")
			require.Equal(t, tc.isHTTPS, cookie.Secure, "Cookie secure does not match")
			require.True(t, cookie.HttpOnly, "Cookie httpOnly is not true")
			require.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "Cookie SameSite does not match")
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
