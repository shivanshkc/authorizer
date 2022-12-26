package middlewares

import (
	"net/http"

	"github.com/shivanshkc/authorizer/src/logger"
	"github.com/shivanshkc/authorizer/src/utils/errutils"
	"github.com/shivanshkc/authorizer/src/utils/httputils"
)

// Recovery recovers any panics that happen during request execution and returns a sanitized response.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer recoverRequestPanic(writer, request)
		next.ServeHTTP(writer, request)
	})
}

// recoverRequestPanic can be deferred inside a middleware/handler to handle any panics during request execution.
func recoverRequestPanic(writer http.ResponseWriter, request *http.Request) {
	// If panic occurred.
	if err := recover(); err != nil {
		errHTTP := errutils.ToHTTPError(err)
		// Logging the panic for debug purposes.
		logger.Error(request.Context(), "panic occurred during request execution: %+v", errHTTP)
		// Sending sanitized response to the user.
		httputils.Write(writer, errHTTP.Status, nil, errHTTP)
	}
}
