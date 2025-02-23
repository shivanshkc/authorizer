package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/shivanshkc/authorizer/pkg/oauth"
)

func TestHandler_Check(t *testing.T) {
	// Common mock inputs.
	mClaims := oauth.Claims{
		Email:      "example@example.com",
		GivenName:  "mockGivenName",
		FamilyName: "mockFamilyName",
		Picture:    "mockPicture",
	}

	mIssuer := "mockIssuer"
	errMock := errors.New("mock error")

	// Base64 encoded token payloads for various cases.
	badJSONPayload := base64.RawURLEncoding.EncodeToString([]byte(`invalidJSON`))
	badIssuerPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + mIssuer + `-random"}`))
	correctIssuerPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + mIssuer + `"}`))

	for _, tc := range []struct {
		name string
		// Mock inputs.
		inCookieName  string
		inCookieValue string
		// Mock implementations.
		providerFunc func() *mockProvider
		// Expectations
		expectDecodeCall     bool
		expectedResponseCode int
		expectedHeaders      map[string]string
	}{
		{
			name:                 "Cookie absent, error expected",
			inCookieName:         accessTokenCookieName + "-random",
			providerFunc:         func() *mockProvider { return nil },
			expectedResponseCode: http.StatusUnauthorized,
			expectedHeaders:      map[string]string{},
		},
		{
			name:                 "Token does not contain three dot separated parts, error expected",
			inCookieName:         accessTokenCookieName,
			inCookieValue:        "headers.payload",
			providerFunc:         func() *mockProvider { return nil },
			expectedResponseCode: http.StatusUnauthorized,
			expectedHeaders:      map[string]string{},
		},
		{
			name:                 "Token payload is not valid base64, error expected",
			inCookieName:         accessTokenCookieName,
			inCookieValue:        "headers.invalidBase64.signature",
			providerFunc:         func() *mockProvider { return nil },
			expectedResponseCode: http.StatusUnauthorized,
			expectedHeaders:      map[string]string{},
		},
		{
			name:                 "Token payload is valid base64 but not valid JSON when decoded, error expected",
			inCookieName:         accessTokenCookieName,
			inCookieValue:        "headers." + badJSONPayload + ".signature",
			providerFunc:         func() *mockProvider { return nil },
			expectedResponseCode: http.StatusUnauthorized,
			expectedHeaders:      map[string]string{},
		},
		{
			name:          "Token issuer does not correspond to any provider, error expected",
			inCookieName:  accessTokenCookieName,
			inCookieValue: "headers." + badIssuerPayload + ".signature",
			providerFunc: func() *mockProvider {
				provider := &mockProvider{}
				provider.On("Issuers").Return([]string{mIssuer + "$$"}).Once()
				return provider
			},
			expectedResponseCode: http.StatusUnauthorized,
			expectedHeaders:      map[string]string{},
		},
		{
			name:          "Token verification fails, error expected",
			inCookieName:  accessTokenCookieName,
			inCookieValue: "headers." + correctIssuerPayload + ".signature",
			providerFunc: func() *mockProvider {
				provider := &mockProvider{}
				provider.On("Issuers").Return([]string{mIssuer}).Once()
				provider.On("DecodeToken", mock.Anything, "headers."+correctIssuerPayload+".signature").
					Return(oauth.Claims{}, errMock).Once()
				return provider
			},
			expectDecodeCall:     true,
			expectedResponseCode: http.StatusUnauthorized,
			expectedHeaders:      map[string]string{},
		},
		{
			name:          "Everything good",
			inCookieName:  accessTokenCookieName,
			inCookieValue: "headers." + correctIssuerPayload + ".signature",
			providerFunc: func() *mockProvider {
				provider := &mockProvider{}
				provider.On("Issuers").Return([]string{mIssuer}).Once()
				provider.On("DecodeToken", mock.Anything, "headers."+correctIssuerPayload+".signature").
					Return(mClaims, nil).Once()
				return provider
			},
			expectDecodeCall:     true,
			expectedResponseCode: http.StatusOK,
			expectedHeaders: map[string]string{
				xAuthEmailHeader:   mClaims.Email,
				xAuthNameHeader:    mClaims.GivenName + " " + mClaims.FamilyName,
				xAuthPictureHeader: mClaims.Picture,
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create the cookie that's supposed to hold the access token.
			cookie := &http.Cookie{Name: tc.inCookieName, Value: tc.inCookieValue}
			// Create mock response writer and request.
			w, r, err := createMockCheckWR(cookie)
			require.NoError(t, err, "Failed to create mock response writer and request")

			mProvider := tc.providerFunc()
			mHandler := &Handler{googleProvider: mProvider}
			// Invoke the method to be tested.
			mHandler.Check(w, r)

			// Verify response.
			require.Equal(t, tc.expectedResponseCode, w.Code, "Wrong response code")
			// Nothing to check further in case of failure.
			if tc.expectedResponseCode/100 != 2 {
				return
			}

			mProvider.AssertExpectations(t)

			// Verify headers.
			require.Equal(t, tc.expectedHeaders, map[string]string{
				xAuthEmailHeader:   w.Header().Get(xAuthEmailHeader),
				xAuthNameHeader:    w.Header().Get(xAuthNameHeader),
				xAuthPictureHeader: w.Header().Get(xAuthPictureHeader),
			}, "Wrong response headers")
		})
	}
}

// createMockCheckWR creates a mock ResponseWriter and Request to test the Check handler.
func createMockCheckWR(cookie *http.Cookie) (*httptest.ResponseRecorder, *http.Request, error) {
	// Mock HTTP request.
	req, err := http.NewRequest(http.MethodGet, "/mock", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP request")
	}

	req.AddCookie(cookie)
	return httptest.NewRecorder(), req, nil
}
