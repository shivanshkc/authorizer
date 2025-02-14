package http

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/shivanshkc/authorizer/internal/logger"
)

func TestAccessLogger(t *testing.T) {
	// This test cannot run in parallel because it relies on the global logger object.

	// Create a middleware instance with a mock logger.
	writer := &bytes.Buffer{}
	mockMW := middlewareWithMockLogger(writer)

	// Data to verify against.
	expectedResponseStatus := http.StatusBadRequest
	expectedLogCount := 2

	// Mock HTTP request and response-writer.
	req, res := httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder()

	// Create an instance of access-logger middleware that passes control to a mock handler.
	accessLoggerMW := mockMW.AccessLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(expectedResponseStatus)
	}))

	// Expect no error.
	accessLoggerMW.ServeHTTP(res, req)

	// Fetch context-info to verify if it was set correctly by the middleware.
	ctxInfo := logger.GetContextValues(req.Context())
	// Verify if the request ID was initialized.
	requestID, exists := ctxInfo["request_id"]
	if !exists {
		t.Errorf("expected request ID to be present but it's not")
		return
	}

	// Request ID must be initialized.
	if _, err := uuid.Parse(requestID.String()); err != nil {
		t.Errorf("expected request ID to be initialized but got empty")
		return
	}

	// Expect the correct response code.
	if res.Code != expectedResponseStatus {
		t.Errorf("expected response code to be %d but got: %d", http.StatusOK, res.Code)
		return
	}

	// Count number of log statements printed.
	var actualLogCount int
	for scanner := bufio.NewScanner(writer); scanner.Scan(); {
		actualLogCount++
	}

	// Expect the correct number of log statements.
	if actualLogCount != expectedLogCount {
		t.Errorf("expected log count to be %d but got: %d", expectedLogCount, actualLogCount)
		return
	}
}
