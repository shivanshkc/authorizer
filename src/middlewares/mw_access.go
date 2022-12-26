package middlewares

import (
	"context"
	"net/http"
	"time"

	"github.com/shivanshkc/authorizer/src/logger"

	"github.com/google/uuid"
)

// AccessLogger middleware handles access logging.
func AccessLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// This will be used to calculate the total request execution time.
		start := time.Now()

		// Add a unique request ID to the request context.
		ctx := context.WithValue(request.Context(), logger.KeyRequestID, uuid.NewString())
		// Embedding the writer into the custom-writer to persist status-code for logging.
		cWriter := &responseWriterWithCode{ResponseWriter: writer}

		// Use the trace ID present in the request's context, if available. Otherwise, generate anew.
		traceID := request.Header.Get("x-trace-id")
		if traceID == "" {
			traceID = uuid.NewString()
		}
		// Put the traceID in the request context.
		ctx = context.WithValue(ctx, logger.KeyTraceID, traceID)
		// Update the request context.
		request = request.WithContext(ctx)

		// Request entry log.
		logger.Info(ctx, "request received: %s %s", request.Method, request.URL)
		// Releasing control to the next middleware or handler.
		next.ServeHTTP(cWriter, request)
		// Request exit log.
		logger.Info(ctx, "request completed: code: %d, took %+v", cWriter.statusCode, time.Since(start))
	})
}

// responseWriterWithCode is a wrapper for http.ResponseWriter for persisting statusCode.
type responseWriterWithCode struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseWriterWithCode) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
