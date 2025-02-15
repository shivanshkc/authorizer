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
//
// TODO: Make it secure.
func (m Middleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "*")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
