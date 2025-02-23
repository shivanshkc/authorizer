package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurity(t *testing.T) {
	// Common mock parameters.
	mockCustomHeader, mockCustomHeaderValue := "X-Custom-Header", "mockHeaderValue"
	mockStatusCode := http.StatusOK

	// Mock handler to which the middleware will be attached.
	mHandlerFunc := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(mockCustomHeader, mockCustomHeaderValue)
		w.WriteHeader(mockStatusCode)
	}

	// Attach the middleware to the handler.
	handler := Middleware{}.Security(http.HandlerFunc(mHandlerFunc))

	// Create mock request and response writer.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/mock", nil)

	// Invoke the middleware.
	handler.ServeHTTP(w, r)

	// Verify correct response code and headers set by the handler.
	// This makes sure that the middleware is passing control to the underlying handler correctly.
	require.Equal(t, mockStatusCode, w.Code, "Unexpected status code")
	// Test for Cache-Control header
	custom := w.Header().Get(mockCustomHeader)
	require.Equal(t, mockCustomHeaderValue, custom, "Wrong value for custom header")

	// Test for X-Content-Type-Options header
	contentTypeOptions := w.Header().Get(xContentTypeOptions)
	require.Equal(t, "nosniff", contentTypeOptions, "Wrong value for X-Content-Type-Options")

	// Test for Cache-Control header
	cc := w.Header().Get(cacheControl)
	require.Equal(t, "no-store, max-age=0", cc, "Wrong value for Cache-Control")
}
