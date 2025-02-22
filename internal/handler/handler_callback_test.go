package handler

import (
	"context"
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/internal/config"
	"github.com/shivanshkc/authorizer/internal/repository"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

func TestHandler_Callback_StateValidation(t *testing.T) {
	mAllowedURLs := []string{"https://allowed.com", "https://wow.com"}
	mHandler := &Handler{config: config.Config{AllowedRedirectURLs: mAllowedURLs}, stateMap: &sync.Map{}}

	for _, tc := range []struct {
		name string
		// Request inputs.
		inputStateKey string
		errSubstring  string
	}{
		{
			name:          "State key absent",
			inputStateKey: "",
			errSubstring:  errInvalidState.Error(),
		},
		{
			name:          "State key invalid",
			inputStateKey: "not-a-valid-uuid",
			errSubstring:  errInvalidState.Error(),
		},
		{
			name:          "State key not present in the state map",
			inputStateKey: uuid.NewString(),
			errSubstring:  errutils.RequestTimeout().Error(),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create mock response writer and request.
			w, r, err := createMockCallbackWR("anything", tc.inputStateKey, "anything", "")
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Verify response code and headers.
			require.Equal(t, http.StatusFound, w.Code)
			// Verify redirect URL and error message.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")
			require.Equal(t, mAllowedURLs[0], parsed.Scheme+"://"+parsed.Host)
			require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
		})
	}
}

func TestHandler_Callback_Validations(t *testing.T) {
	// Common mock inputs and implementations.
	mStateKey, mCCU := uuid.NewString(), "https://allowed.com"
	mHandler := &Handler{config: config.Config{AllowedRedirectURLs: []string{mCCU}}, stateMap: &sync.Map{}}

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
			// Populate the state map. This must be empty by the end.
			mHandler.stateMap.Store(mStateKey, stateValue{CodeVerifier: "anything", ClientCallbackURL: mCCU})

			// Create mock response writer and request.
			w, r, err := createMockCallbackWR(tc.inputProvider, mStateKey, tc.inputCode, tc.inputError)
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state key was deleted from the state map.
			_, found := mHandler.stateMap.LoadAndDelete(mStateKey)
			require.False(t, found, "Expected state key to have been deleted but it was not")

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
	mStateKey, mCCU := uuid.NewString(), "https://allowed.com"
	mockCode := "4/0ASVgi3Iwlq42Bl8wh6-XUEpdSNFremRaxzXPWpRZxqYWW-xGo54-DAV94ZbLKx033sG5qA"
	mStateValue := stateValue{CodeVerifier: "anything", ClientCallbackURL: mCCU}

	// Common mock implementations.
	mProvider := &mockProvider{
		name:             "google",
		errTokenFromCode: nil,
		token:            "mockToken.Darth.Vader",
		errDecodeToken:   nil,
		claims: oauth.Claims{
			Iss:        "mockIssuer",
			Exp:        time.Now().Add(time.Hour),
			Email:      "mock@mock.com",
			GivenName:  "mockGivenName",
			FamilyName: "mockFamilyName",
			Picture:    "mockPicture",
		},
	}

	mHandler := &Handler{
		config:         config.Config{AllowedRedirectURLs: []string{mCCU}},
		stateMap:       &sync.Map{},
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
		expectDatabaseCall      bool
		errSubstring            string
	}{
		{
			name:                    "Everything good, application on HTTPS domain, no errors",
			providerFunc:            func() *mockProvider { return mProvider.Clone() },
			isHTTPS:                 true,
			expectTokenFromCodeCall: true,
			expectDecodeTokenCall:   true,
			expectDatabaseCall:      true,
			errSubstring:            "",
		},
		{
			name:                    "Everything good, application on HTTP domain, no errors",
			providerFunc:            func() *mockProvider { return mProvider.Clone() },
			isHTTPS:                 false,
			expectTokenFromCodeCall: true,
			expectDecodeTokenCall:   true,
			expectDatabaseCall:      true,
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

			// Populate the state map. This must be empty by the end.
			mHandler.stateMap.Store(mStateKey, mStateValue)
			// Provider to use for this test.
			thisProvider := tc.providerFunc()
			mHandler.googleProvider = thisProvider
			// Attach new mock repository instance for each run.
			mRepo := &mockRepository{}
			mHandler.repo = mRepo

			// Create mock response writer and request.
			w, r, err := createMockCallbackWR(mProvider.name, mStateKey, mockCode, "")
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state key was deleted from the state map
			_, found := mHandler.stateMap.LoadAndDelete(mStateKey)
			require.False(t, found, "Expected state key to be deleted but it was not")

			// Verify if the provider methods were invoked and with correct arguments.
			if tc.expectTokenFromCodeCall {
				require.Equal(t, mockCode, thisProvider.argCode,
					"TokenFromCode was not called with the correct auth code")
				require.Equal(t, mStateValue.CodeVerifier, thisProvider.argCodeVerifier,
					"TokenFromCode was not called with the correct code verifier")
			} else {
				require.Equal(t, "", thisProvider.argCode,
					"TokenFromCode unexpectedly called, was the mockProvider instance correctly reset?")
				require.Equal(t, "", thisProvider.argCodeVerifier,
					"TokenFromCode unexpectedly called, was the mockProvider instance correctly reset?")
			}

			if tc.expectDecodeTokenCall {
				require.Equal(t, thisProvider.token, thisProvider.argDecodeToken,
					"DecodeToken was not called with correct arguments")
			} else {
				require.Equal(t, "", thisProvider.argDecodeToken,
					"DecodeToken unexpectedly called, was the mockProvider instance correctly reset?")
			}

			// Verify if the database operation was invoked and with correct arguments.
			if tc.expectDatabaseCall {
				mRepo.On("UpsertUser", context.Background(), repository.User{
					Email:      thisProvider.claims.Email,
					GivenName:  thisProvider.claims.GivenName,
					FamilyName: thisProvider.claims.FamilyName,
					PictureURL: thisProvider.claims.Picture,
				}).Return(nil)

				// Sleep for some time for the database operation to complete.
				time.Sleep(time.Millisecond * 100)
				mRepo.AssertExpectations(t)
			} else {
				// Sleep for some time for the database operation to complete.
				time.Sleep(time.Millisecond * 100)
				mRepo.AssertNotCalled(t, "UpsertUser", mock.Anything, mock.Anything)
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
func createMockCallbackWR(provider, stateKey, code, e string) (*httptest.ResponseRecorder, *http.Request, error) {
	// Mock HTTP request.
	req, err := http.NewRequest(http.MethodGet, "/mock", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP request")
	}

	// Set path params.
	req = mux.SetURLVars(req, map[string]string{"provider": provider})
	// Set query params.
	q := req.URL.Query()
	q.Set("state", stateKey)
	q.Set("code", code)
	q.Set("error", e)
	req.URL.RawQuery = q.Encode()

	return httptest.NewRecorder(), req, nil
}
