package ctxutils

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// contextKey can be used to put values in a context type.
type contextKey int

// ctxInfoKey is used to put a *RequestCtxInfo instance in the request context.
const ctxInfoKey contextKey = iota

// RequestCtxInfo contains the context info of a request.
type RequestCtxInfo struct {
	RequestID string
	TraceID   string
}

// SetRequestCtxInfo accepts a newly arrived request and attaches a *RequestCtxInfo instance to it.
func SetRequestCtxInfo(req *http.Request) {
	// Generate a new request ID.
	requestID := uuid.NewString()

	// Get existing trace ID or generate new.
	traceID := req.Header.Get("x-trace-id")
	if traceID == "" {
		traceID = uuid.NewString()
	}

	// Instantiate the context info.
	ctxInfo := &RequestCtxInfo{
		RequestID: requestID,
		TraceID:   traceID,
	}

	// Put the ctxInfo in the request context.
	newCtx := context.WithValue(req.Context(), ctxInfoKey, ctxInfo)
	// Update the request with the new context.
	*req = *req.WithContext(newCtx)
}

// GetRequestCtxInfo extracts a *RequestCtxInfo instance from the given context and returns it.
// If the context does not contain a *RequestCtxInfo instance, nil is returned.
func GetRequestCtxInfo(ctx context.Context) *RequestCtxInfo {
	ctxInfo, asserted := ctx.Value(ctxInfoKey).(*RequestCtxInfo)
	if !asserted || ctxInfo == nil {
		return nil
	}

	return ctxInfo
}
