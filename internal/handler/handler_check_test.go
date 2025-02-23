package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/pkg/oauth"
)

func TestHandler_Check(t *testing.T) {
	// Requests containing the token with this issuer will pass the issuer recognition check.
	const correctIssuer = "accounts.google.com"

	// Correct claims to be returned by the DecodeToken call in case of no errors.
	claims := oauth.Claims{
		Iss:        correctIssuer,
		Exp:        time.Now().Add(time.Hour),
		Email:      "hey@hey.com",
		GivenName:  "Gi",
		FamilyName: "Hun",
		Picture:    "mockPicture",
	}

	// Marshal claims to embed into mock token.
	claimBytes, err := json.Marshal(claims)
	require.NoError(t, err, "Failed to marshal claims")

	// Common error for reuse.
	errMock := errors.New("mock error")

	// Base64 encoded token payloads for various cases.
	badJSONPayload := base64.RawURLEncoding.EncodeToString([]byte(`invalidJSON`))
	badIssuerPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + correctIssuer + `-random"}`))
	correctPayload := base64.RawURLEncoding.EncodeToString(claimBytes)

	for _, tc := range []struct {
		name string
		// Mock inputs.
		inCookieName   string
		inCookieValue  string
		errDecodeToken error // Parameter to control if the DecodeToken method should fail.
		// Expectations
		expectIssuersCall     bool
		expectDecodeTokenCall bool
		expectedResponseCode  int
		expectedHeaders       map[string]string
	}{
		{
			name:                  "Cookie absent, error expected",
			inCookieName:          accessTokenCookieName + "-random",
			inCookieValue:         "",
			errDecodeToken:        nil,
			expectIssuersCall:     false,
			expectDecodeTokenCall: false,
			expectedResponseCode:  http.StatusUnauthorized,
			expectedHeaders:       map[string]string{},
		},
		{
			name:                  "Token does not contain three dot separated parts, error expected",
			inCookieName:          accessTokenCookieName,
			inCookieValue:         "headers.payload",
			errDecodeToken:        nil,
			expectIssuersCall:     false,
			expectDecodeTokenCall: false,
			expectedResponseCode:  http.StatusUnauthorized,
			expectedHeaders:       map[string]string{},
		},
		{
			name:                  "Token payload is not valid base64, error expected",
			inCookieName:          accessTokenCookieName,
			inCookieValue:         "headers.invalidBase64.signature",
			errDecodeToken:        nil,
			expectIssuersCall:     false,
			expectDecodeTokenCall: false,
			expectedResponseCode:  http.StatusUnauthorized,
			expectedHeaders:       map[string]string{},
		},
		{
			name:                  "Token payload is valid base64 but not valid JSON when decoded, error expected",
			inCookieName:          accessTokenCookieName,
			inCookieValue:         "headers." + badJSONPayload + ".signature",
			errDecodeToken:        nil,
			expectIssuersCall:     false,
			expectDecodeTokenCall: false,
			expectedResponseCode:  http.StatusUnauthorized,
			expectedHeaders:       map[string]string{},
		},
		{
			name:                  "Token issuer does not correspond to any provider, error expected",
			inCookieName:          accessTokenCookieName,
			inCookieValue:         "headers." + badIssuerPayload + ".signature",
			errDecodeToken:        errMock,
			expectIssuersCall:     true,
			expectDecodeTokenCall: false,
			expectedResponseCode:  http.StatusUnauthorized,
			expectedHeaders:       map[string]string{},
		},
		{
			name:                  "Token verification fails, error expected",
			inCookieName:          accessTokenCookieName,
			inCookieValue:         "headers." + correctPayload + ".signature",
			errDecodeToken:        errMock,
			expectIssuersCall:     true,
			expectDecodeTokenCall: true,
			expectedResponseCode:  http.StatusUnauthorized,
			expectedHeaders:       map[string]string{},
		},
		{
			name:                  "Everything good",
			inCookieName:          accessTokenCookieName,
			inCookieValue:         "headers." + correctPayload + ".signature",
			errDecodeToken:        nil,
			expectIssuersCall:     true,
			expectDecodeTokenCall: true,
			expectedResponseCode:  http.StatusOK,
			expectedHeaders: map[string]string{
				xAuthEmailHeader:   claims.Email,
				xAuthNameHeader:    claims.GivenName + " " + claims.FamilyName,
				xAuthPictureHeader: claims.Picture,
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mHandler := &Handler{}
			// Create the cookie that's supposed to hold the access token.
			cookie := &http.Cookie{Name: tc.inCookieName, Value: tc.inCookieValue}
			// Create mock response writer and request.
			w, r := createMockCheckWR(cookie)

			// Setup provider call expectations.
			mProvider := &mockProvider{}
			mHandler.googleProvider = mProvider

			if tc.expectIssuersCall {
				mProvider.On("Issuers").Return([]string{correctIssuer}).Once()
			}
			if tc.expectDecodeTokenCall {
				mProvider.On("DecodeToken", r.Context(), tc.inCookieValue).
					Return(claims, tc.errDecodeToken).Once()
			}

			// Invoke the method to be tested.
			mHandler.Check(w, r)
			// Verify response.
			require.Equal(t, tc.expectedResponseCode, w.Code, "Wrong response code")

			// Form the actual headers to compare against the expected ones.
			actualHeaders := map[string]string{}
			if email := w.Header().Get(xAuthEmailHeader); email != "" {
				actualHeaders[xAuthEmailHeader] = email
			}
			if name := w.Header().Get(xAuthNameHeader); name != "" {
				actualHeaders[xAuthNameHeader] = name
			}
			if picture := w.Header().Get(xAuthPictureHeader); picture != "" {
				actualHeaders[xAuthPictureHeader] = picture
			}

			// Verify headers.
			require.Equal(t, tc.expectedHeaders, actualHeaders, "Wrong response headers")
			// Verify provider calls.
			mProvider.AssertExpectations(t)
		})
	}
}

// createMockCheckWR creates a mock ResponseWriter and Request to test the Check handler.
func createMockCheckWR(cookie *http.Cookie) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(http.MethodGet, "/mock", nil)
	req.AddCookie(cookie)
	return httptest.NewRecorder(), req
}
