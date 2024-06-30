package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shivanshkc/authorizer/pkg/config"
	"github.com/shivanshkc/authorizer/pkg/logger"
	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
)

func TestMiddleware_Recovery(t *testing.T) {
	t.Parallel()

	// Create a middleware instance with a mock logger.
	writer := &bytes.Buffer{}
	mockMW := middlewareWithMockLogger(writer)

	// This error should be present in the response.
	expectedResponse := errutils.InternalServerError().WithReasonStr("test panic")
	// Create mock request and response.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api", nil)

	// Create an instance of the recovery MW that passes control to a mock handler.
	recoveryMW := mockMW.Recovery(hFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(expectedResponse)
	}))

	recoveryMW.ServeHTTP(recorder, request)

	// Expect the correct status code.
	if recorder.Code != expectedResponse.StatusCode {
		t.Errorf("expected status code: %d but got: %d", expectedResponse.StatusCode, recorder.Code)
		return
	}

	// Decode the response body for verification.
	responseBody := map[string]any{}
	if err := json.NewDecoder(recorder.Body).Decode(&responseBody); err != nil {
		t.Errorf("failed to decode response body: %v", err)
		return
	}

	// Expect the correct status.
	if responseBody["status"] != expectedResponse.Status {
		t.Errorf("expected status to be: %s but got: %s", expectedResponse.Status, responseBody["status"])
		return
	}

	// Expect the correct reason.
	if responseBody["reason"] != expectedResponse.Reason {
		t.Errorf("expected reason to be: %s but got: %s", expectedResponse.Reason, responseBody["reason"])
		return
	}
}

func TestMiddleware_CORS(t *testing.T) {
	t.Parallel()

	// Create a middleware instance with a mock logger.
	mockMW := middlewareWithMockLogger(io.Discard)

	// HTTP request with the OPTIONS verb to test CORS.
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Add("origin", "example-origin")
	// Recorder for verifying the response.
	rec := httptest.NewRecorder()

	// Create an instance of the CORS MW that passes control to a mock handler.
	corsMW := mockMW.CORS(hFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	corsMW.ServeHTTP(rec, req)

	// Check the value of the allow-origin header.
	allowOriginHeader := rec.Header().Get("Access-Control-Allow-Origin")
	if allowOriginHeader != "*" {
		t.Errorf("expected the allow origin header to be * but got: %s", allowOriginHeader)
		return
	}
}

// middlewareWithMockLogger returns a middleware instance that uses a mock logger.
// The provided writer is used as the underlying io.Writer for the logger instance.
func middlewareWithMockLogger(writer io.Writer) *Middleware {
	// Setup basic dependencies.
	conf := config.LoadMock()
	logger.Init(writer, conf.Logger.Level, conf.Logger.Pretty)
	return &Middleware{}
}
