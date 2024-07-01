package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/shivanshkc/authorizer/pkg/logger"
)

// AccessLogger middleware handles access logging.
func (m Middleware) AccessLogger(next http.Handler) http.Handler {
	return hFunc(func(w http.ResponseWriter, r *http.Request) {
		// This will be used to calculate the total request execution time.
		start := time.Now()

		newCtx := logger.AddContextValue(r.Context(), "request_id", uuid.NewString())
		// Update the request with the new context.
		*r = *r.WithContext(newCtx)

		// Embedding the writer into the custom-writer to persist status-code for logging.
		cw := &responseWriterWithCode{ResponseWriter: w}

		// Request entry log.
		slog.InfoContext(r.Context(), "request received", "url", r.URL.String())
		// Release control to the next middleware or handler.
		next.ServeHTTP(cw, r)
		// Request exit log.
		slog.InfoContext(r.Context(), "request completed",
			"latency", time.Since(start), "status", cw.statusCode)
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
