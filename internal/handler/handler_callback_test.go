package handler

import (
	"context"
	"errors"
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
	"github.com/shivanshkc/authorizer/internal/repository"
	"github.com/shivanshkc/authorizer/internal/utils/errutils"
	"github.com/shivanshkc/authorizer/pkg/oauth"
)

func TestHandler_Callback_StateValidation(t *testing.T) {
	// List of allowed redirect URLs.
	// If the state fails to parse, the handler must default to using the first URL in this list.
	allowedURLs := []string{"https://first.com", "https://second.com"}
	// For brevity.
	mConfig := config.Config{AllowedRedirectURLs: allowedURLs}

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
			w, r := createMockCallbackWR("anything", tc.inputStateKey, "anything", "")

			// Invoke the method to test.
			mHandler := &Handler{config: mConfig, stateMap: &sync.Map{}}
			mHandler.Callback(w, r)

			// Verify response code and headers.
			require.Equal(t, http.StatusFound, w.Code)

			// Verify redirect URL and error message.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")

			// Should default to the first URL in the allow list.
			require.Equal(t, allowedURLs[0], parsed.Scheme+"://"+parsed.Host)

			// Should include the expected error as a query parameter.
			require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
		})
	}
}

func TestHandler_Callback_Validations(t *testing.T) {
	// State key to use in all tests.
	var stateKey = uuid.NewString()
	// List of allowed redirect URLs.
	// In case of a valid state key, the handler should retrieve the redirect URL from the state map.
	var allowedURLs = []string{"https://first.com", "https://second.com"}
	// Requests with provider should pass the provider validation step.
	const correctProvider = "google"
	// Requests with this code should pass the code validation step.
	const correctCode = "4/0ASVgi3Iwlq42Bl8wh6-XUEpdSNFremRaxzXPWpRZxqYWW-xGo54-DAV94ZbLKx033sG5qA"

	// For brevity.
	mConfig := config.Config{AllowedRedirectURLs: allowedURLs}

	for _, tc := range []struct {
		name string
		// Mock inputs.
		inputProvider   string
		inputCode       string
		inputError      string
		inputStateValue any // It is not received through the HTTP request but still is effectively an input.
		// Expectations.
		expectedLocation string
		errSubstring     string
	}{
		{
			name:             "State value of unknown type, Location should be first allowed redirect URL",
			inputProvider:    correctProvider,
			inputCode:        correctCode,
			inputStateValue:  "incompatible type",
			expectedLocation: allowedURLs[0],
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Too long provider length, Location should be as specified in the stateValue",
			inputProvider:    strings.Repeat("a", 21),
			inputCode:        correctCode,
			inputStateValue:  stateValue{ClientCallbackURL: allowedURLs[1]},
			expectedLocation: allowedURLs[1],
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Invalid provider character",
			inputProvider:    correctProvider + "$$",
			inputCode:        correctCode,
			inputStateValue:  stateValue{ClientCallbackURL: allowedURLs[1]},
			expectedLocation: allowedURLs[1],
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Absent auth code",
			inputProvider:    correctProvider,
			inputCode:        "",
			inputStateValue:  stateValue{ClientCallbackURL: allowedURLs[1]},
			expectedLocation: allowedURLs[1],
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Too long auth code",
			inputProvider:    correctProvider,
			inputCode:        strings.Repeat("a", 401),
			inputStateValue:  stateValue{ClientCallbackURL: allowedURLs[1]},
			expectedLocation: allowedURLs[1],
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Invalid characters in auth code",
			inputProvider:    correctProvider,
			inputCode:        correctCode + "$$",
			inputStateValue:  stateValue{ClientCallbackURL: allowedURLs[1]},
			expectedLocation: allowedURLs[1],
			errSubstring:     errutils.InternalServerError().Error(),
		},
		{
			name:             "Error received from provider",
			inputProvider:    correctProvider,
			inputCode:        correctCode,
			inputError:       "access_denied",
			inputStateValue:  stateValue{ClientCallbackURL: allowedURLs[1]},
			expectedLocation: allowedURLs[1],
			errSubstring:     "access_denied",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Populate the state map. This must be empty by the end.
			mHandler := &Handler{config: mConfig, stateMap: &sync.Map{}}
			mHandler.stateMap.Store(stateKey, tc.inputStateValue)

			// Create mock response writer and request.
			w, r := createMockCallbackWR(tc.inputProvider, stateKey, tc.inputCode, tc.inputError)

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state key was deleted from the state map.
			_, found := mHandler.stateMap.LoadAndDelete(stateKey)
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
	// Requests with this provider name will pass the provider recognition check.
	const knownProviderName = "google"
	// List of allowed redirect URLs.
	// In case of a valid state key, the handler should retrieve the redirect URL from the state map.
	var allowedURLs = []string{"https://first.com", "https://second.com"}

	// State key and value for all requests.
	var stateKey = uuid.NewString()
	var stateVal = stateValue{CodeVerifier: "anything", ClientCallbackURL: allowedURLs[1]}

	// Code for all requests.
	const code = "4/0ASVgi3Iwlq42Bl8wh6-XUEpdSNFremRaxzXPWpRZxqYWW-xGo54-DAV94ZbLKx033sG5qA"
	// Token returned by the TokenFromCode method in case of no errors.
	const token = "header.payload.signature"
	// Claims returned by the DecodeToken method in case of no errors.
	var claims = oauth.Claims{
		Iss:        "mockIssuer",
		Exp:        time.Now().Add(time.Hour),
		Email:      "mock@mock.com",
		GivenName:  "mockGivenName",
		FamilyName: "mockFamilyName",
		Picture:    "mockPicture",
	}

	// Common error for reuse.
	errMock := errors.New("mock error")
	// For brevity.
	mConfig := config.Config{AllowedRedirectURLs: allowedURLs}

	for _, tc := range []struct {
		name string
		// Mock inputs.
		inputProviderName string
		inputHTTPS        bool  // Flag to control the protocol of the request. This affects the returned cookie.
		errTokenFromCode  error // Parameter to control if the TokenFromCode method should fail.
		errDecodeToken    error // Parameter to control if the DecodeToken method should fail.
		// Expectations.
		errSubstring string
	}{
		{
			name:              "Everything good, application on HTTPS domain, no errors",
			inputProviderName: knownProviderName,
			inputHTTPS:        true,
			errTokenFromCode:  nil,
			errDecodeToken:    nil,
			errSubstring:      "",
		},
		{
			name:              "Everything good, application on HTTP domain, no errors",
			inputProviderName: knownProviderName,
			inputHTTPS:        false,
			errTokenFromCode:  nil,
			errDecodeToken:    nil,
			errSubstring:      "",
		},
		{
			name:              "Unknown provider",
			inputProviderName: knownProviderName + "-random",
			inputHTTPS:        false,
			errTokenFromCode:  nil,
			errDecodeToken:    nil,
			errSubstring:      errutils.InternalServerError().Error(),
		},
		{
			name:              "TokenFromCode method returns error",
			inputProviderName: knownProviderName,
			inputHTTPS:        false,
			errTokenFromCode:  errMock,
			errDecodeToken:    nil,
			errSubstring:      errutils.InternalServerError().Error(),
		},
		{
			name:              "DecodeToken method returns error",
			inputProviderName: knownProviderName,
			inputHTTPS:        false,
			errTokenFromCode:  nil,
			errDecodeToken:    errMock,
			errSubstring:      errutils.InternalServerError().Error(),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create mock handler for each test.
			mHandler := &Handler{config: mConfig, stateMap: &sync.Map{}}

			// Create mock response writer and request.
			w, r := createMockCallbackWR(tc.inputProviderName, stateKey, code, "")

			// Set application base URL as per HTTPS status.
			// This is required to test the "Secure" field of the cookie.
			if tc.inputHTTPS {
				mHandler.config.Application.BaseURL = "https://application.com"
			} else {
				mHandler.config.Application.BaseURL = "http://application.com"
			}

			// Populate the state map. This must be empty by the end.
			mHandler.stateMap.Store(stateKey, stateVal)

			// Attach new mock repository instance for each run.
			mRepo := &mockRepository{}
			mHandler.repo = mRepo

			// Setup provider call expectations.
			mProvider := &mockProvider{}
			mHandler.googleProvider = mProvider

			// Always expect the Name call.
			mProvider.On("Name").Return(knownProviderName).Once()

			// If provider name id correct, expect a TokenFromCode call.
			expectTokenFromCode := tc.inputProviderName == knownProviderName
			// If TokenFromCode is supposed to succeed, expect a DecodeToken call.
			expectDecodeToken := expectTokenFromCode && tc.errTokenFromCode == nil
			// If DecodeToken is supposed to succeed, expect an UpsertUser call.
			expectUpsertUser := expectDecodeToken && tc.errDecodeToken == nil

			// Set call expectations.
			if expectTokenFromCode {
				mProvider.On("TokenFromCode", r.Context(), code, stateVal.CodeVerifier).
					Return(token, tc.errTokenFromCode).Once()
			}
			if expectDecodeToken {
				mProvider.On("DecodeToken", r.Context(), token).
					Return(claims, tc.errDecodeToken).Once()
			}
			if expectUpsertUser {
				mRepo.On("UpsertUser", context.Background(), repository.User{
					Email:      claims.Email,
					GivenName:  claims.GivenName,
					FamilyName: claims.FamilyName,
					PictureURL: claims.Picture,
				}).Return(nil).Once()
			}

			// Invoke the method to test.
			mHandler.Callback(w, r)

			// Check if the state key was deleted from the state map
			_, found := mHandler.stateMap.LoadAndDelete(stateKey)
			require.False(t, found, "Expected state key to be deleted but it was not")

			// Verify provider calls.
			mProvider.AssertExpectations(t)

			// Sleep for some time for the database operation to complete.
			time.Sleep(time.Millisecond * 100)
			mRepo.AssertExpectations(t)

			// Verify response code.
			require.Equal(t, http.StatusFound, w.Code)

			// Verify redirection URL.
			parsed, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err, "Expected Location header to be a valid URL")
			require.Equal(t, stateVal.ClientCallbackURL, parsed.Scheme+"://"+parsed.Host)

			// Verify in case of error.
			if tc.errSubstring != "" {
				require.Contains(t, parsed.Query().Get("error"), tc.errSubstring)
				return
			}

			// Verify success behaviour.
			require.Equal(t, parsed.Query().Get("provider"), knownProviderName)
			// Get the cookie from the response.
			cookie := w.Result().Cookies()[0]
			// Verify cookie fields.
			require.Equal(t, token, cookie.Value, "Cookie value does not match")
			require.Equal(t, "/", cookie.Path, "Cookie path does not match")
			require.NotEqual(t, 0, cookie.MaxAge, "Cookie max age does not match")
			require.Equal(t, tc.inputHTTPS, cookie.Secure, "Cookie secure does not match")
			require.True(t, cookie.HttpOnly, "Cookie httpOnly is not true")
			require.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "Cookie SameSite does not match")
		})
	}
}

// createMockCallbackWR creates a mock ResponseWriter and Request to test the Callback handler.
func createMockCallbackWR(provider, stateKey, code, e string) (*httptest.ResponseRecorder, *http.Request) {
	// Mock HTTP request.
	req := httptest.NewRequest(http.MethodGet, "/mock", nil)
	// Set path params.
	req = mux.SetURLVars(req, map[string]string{"provider": provider})

	// Set query params.
	query := req.URL.Query()
	query.Set("state", stateKey)
	query.Set("code", code)
	query.Set("error", e)
	req.URL.RawQuery = query.Encode()

	return httptest.NewRecorder(), req
}
