package errutils

import (
	"net/http"
)

// BadRequest is for logically incorrect requests.
func BadRequest() *HTTPError {
	return &HTTPError{Status: http.StatusBadRequest, Code: "BAD_REQUEST"}
}

// Unauthorized is for requests with invalid credentials.
func Unauthorized() *HTTPError {
	return &HTTPError{Status: http.StatusUnauthorized, Code: "UNAUTHORIZED"}
}

// PaymentRequired is for requests that require payment completion.
func PaymentRequired() *HTTPError {
	return &HTTPError{Status: http.StatusPaymentRequired, Code: "PAYMENT_REQUIRED"}
}

// Forbidden is for requests that do not have enough authority to execute the operation.
func Forbidden() *HTTPError {
	return &HTTPError{Status: http.StatusForbidden, Code: "FORBIDDEN"}
}

// NotFound is for requests that try to access a non-existent resource.
func NotFound() *HTTPError {
	return &HTTPError{Status: http.StatusNotFound, Code: "NOT_FOUND"}
}

// RequestTimeout is for requests that take longer than a certain time limit to execute.
func RequestTimeout() *HTTPError {
	return &HTTPError{Status: http.StatusRequestTimeout, Code: "REQUEST_TIMEOUT"}
}

// Conflict is for requests that attempt paradoxical operations, such as re-creating the same resource.
func Conflict() *HTTPError {
	return &HTTPError{Status: http.StatusConflict, Code: "CONFLICT"}
}

// PreconditionFailed is for requests that do not satisfy pre-business layers of the application.
func PreconditionFailed() *HTTPError {
	return &HTTPError{Status: http.StatusPreconditionFailed, Code: "PRECONDITION_FAILED"}
}

// InternalServerError is for requests that cause an unexpected misbehaviour.
func InternalServerError() *HTTPError {
	return &HTTPError{Status: http.StatusInternalServerError, Code: "INTERNAL_SERVER_ERROR"}
}

// ServiceUnavailable is returned when the system is not available enough to serve the request.
func ServiceUnavailable() *HTTPError {
	return &HTTPError{Status: http.StatusServiceUnavailable, Code: "SERVICE_UNAVAILABLE"}
}
