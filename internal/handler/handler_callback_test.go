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
	mProviderName, mStateKey := "google", uuid.NewString()
	mCode := "4/0ASVgi3Iwlq42Bl8wh6-XUEpdSNFremRaxzXPWpRZxqYWW-xGo54-DAV94ZbLKx033sG5qA"
	mToken := "header.payload.signature"
	mStateValue := stateValue{CodeVerifier: "anything", ClientCallbackURL: "https://allowed.com"}
	mClaims := oauth.Claims{
		Iss:        "mockIssuer",
		Exp:        time.Now().Add(time.Hour),
		Email:      "mock@mock.com",
		GivenName:  "mockGivenName",
		FamilyName: "mockFamilyName",
		Picture:    "mockPicture",
	}
	errMock := errors.New("mock error")

	mHandler := &Handler{
		config:   config.Config{AllowedRedirectURLs: []string{mStateValue.ClientCallbackURL}},
		stateMap: &sync.Map{},
	}

	for _, tc := range []struct {
		name string
		// Mock inputs.
		providerFunc func() *mockProvider
		isHTTPS      bool
		// Expectations.
		expectDatabaseCall bool
		errSubstring       string
	}{
		{
			name: "Everything good, application on HTTPS domain, no errors",
			providerFunc: func() *mockProvider {
				mProvider := &mockProvider{}
				mProvider.On("Name").Return(mProviderName).Once()
				mProvider.On("TokenFromCode", mock.Anything, mCode, mock.Anything).
					Return(mToken, nil).Once()
				mProvider.On("DecodeToken", mock.Anything, mToken).
					Return(mClaims, nil).Once()
				return mProvider
			},
			isHTTPS:            true,
			expectDatabaseCall: true,
			errSubstring:       "",
		},
		{
			name: "Everything good, application on HTTP domain, no errors",
			providerFunc: func() *mockProvider {
				mProvider := &mockProvider{}
				mProvider.On("Name").Return(mProviderName).Once()
				mProvider.On("TokenFromCode", mock.Anything, mCode, mock.Anything).
					Return(mToken, nil).Once()
				mProvider.On("DecodeToken", mock.Anything, mToken).
					Return(mClaims, nil).Once()
				return mProvider
			},
			isHTTPS:            false,
			expectDatabaseCall: true,
			errSubstring:       "",
		},
		{
			name: "Unknown provider",
			providerFunc: func() *mockProvider {
				mProvider := &mockProvider{}
				mProvider.On("Name").Return(mProviderName + "$$").Once()
				return mProvider
			},
			errSubstring: errutils.InternalServerError().Error(),
		},
		{
			name: "TokenFromCode method returns error",
			providerFunc: func() *mockProvider {
				mProvider := &mockProvider{}
				mProvider.On("Name").Return(mProviderName).Once()
				mProvider.On("TokenFromCode", mock.Anything, mCode, mock.Anything).
					Return("", errMock).Once()
				return mProvider
			},
			errSubstring: errutils.InternalServerError().Error(),
		},
		{
			name: "DecodeToken method returns error",
			providerFunc: func() *mockProvider {
				mProvider := &mockProvider{}
				mProvider.On("Name").Return(mProviderName).Once()
				mProvider.On("TokenFromCode", mock.Anything, mCode, mock.Anything).
					Return(mToken, nil).Once()
				mProvider.On("DecodeToken", mock.Anything, mToken).
					Return(oauth.Claims{}, errMock).Once()
				return mProvider
			},
			errSubstring: errutils.InternalServerError().Error(),
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
			w, r, err := createMockCallbackWR(mProviderName, mStateKey, mCode, "")
			require.NoError(t, err, "Failed to create mock callback response writer and request")

			// Setup databae call expectations.
			if tc.expectDatabaseCall {
				mRepo.On("UpsertUser", context.Background(), repository.User{
					Email:      mClaims.Email,
					GivenName:  mClaims.GivenName,
					FamilyName: mClaims.FamilyName,
					PictureURL: mClaims.Picture,
				}).Return(nil).Once()
			}

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state key was deleted from the state map
			_, found := mHandler.stateMap.LoadAndDelete(mStateKey)
			require.False(t, found, "Expected state key to be deleted but it was not")

			// Sleep for some time for the database operation to complete.
			time.Sleep(time.Millisecond * 100)
			mRepo.AssertExpectations(t)

			// Verify provider calls.
			thisProvider.AssertExpectations(t)

			// Verify response code.
			require.Equal(t, http.StatusFound, w.Code)
			// Verify redirection URL.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")
			require.Equal(t, mStateValue.ClientCallbackURL, parsed.Scheme+"://"+parsed.Host)

			// Verify in case of error.
			if tc.errSubstring != "" {
				require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
				return
			}

			// Verify success behaviour.
			require.Equal(t, parsed.Query().Get("provider"), mProviderName)
			// Get the cookie from the response.
			cookie := w.Result().Cookies()[0]
			// Verify cookie fields.
			require.Equal(t, mToken, cookie.Value, "Cookie value does not match")
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
