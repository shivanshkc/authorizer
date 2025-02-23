package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/shivanshkc/authorizer/internal/utils/httputils"
)

// Middleware implements all the REST middleware methods.
type Middleware struct{}

func (m Middleware) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// Recover the panic.
			errAny := recover()
			if errAny == nil {
				return
			}

			// Stack for debugging.
			stack := string(debug.Stack())
			// Log.
			slog.ErrorContext(r.Context(), "panic occurred during request execution",
				"err", errAny, "stack", stack)

			// Convert to error for handling.
			err, ok := errAny.(error)
			if !ok {
				err = fmt.Errorf("recover returned a non-error type value: %v", errAny)
			}

			// Response.
			httputils.WriteErr(w, err)
		}()

		// Next middleware or handler.
		next.ServeHTTP(w, r)
	})
}

// CORS middleware attaches the necessary CORS headers.
func (m Middleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This assumes that this service will sit behind a reverse proxy running on the same machine.
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost")
		// Allow credentials (cookies, HTTP authentication).
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		// Cache preflight requests for 1 hour
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Allow common HTTP methods.
		w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s %s %s %s %s %s", http.MethodGet,
			http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions))

		// Allow common headers.
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, "+
			"Accept-Encoding, Authorization, X-Requested-With")

		// Handle preflight requests.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Next middleware or handler.
		next.ServeHTTP(w, r)
	})
}
