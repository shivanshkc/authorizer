package errutils

import (
	"net/http"
)

// BadRequest is for logically incorrect requests.
func BadRequest() *HTTPError {
	return &HTTPError{StatusCode: http.StatusBadRequest, Status: "BAD_REQUEST"}
}

// Unauthorized is for requests with invalid credentials.
func Unauthorized() *HTTPError {
	return &HTTPError{StatusCode: http.StatusUnauthorized, Status: "UNAUTHORIZED"}
}

// PaymentRequired is for requests that require payment completion.
func PaymentRequired() *HTTPError {
	return &HTTPError{StatusCode: http.StatusPaymentRequired, Status: "PAYMENT_REQUIRED"}
}

// Forbidden is for requests that do not have enough authority to execute the operation.
func Forbidden() *HTTPError {
	return &HTTPError{StatusCode: http.StatusForbidden, Status: "FORBIDDEN"}
}

// NotFound is for requests that try to access a non-existent resource.
func NotFound() *HTTPError {
	return &HTTPError{StatusCode: http.StatusNotFound, Status: "NOT_FOUND"}
}

// RequestTimeout is for requests that take longer than a certain time limit to execute.
func RequestTimeout() *HTTPError {
	return &HTTPError{StatusCode: http.StatusRequestTimeout, Status: "REQUEST_TIMEOUT"}
}

// Conflict is for requests that attempt paradoxical operations, such as re-creating the same resource.
func Conflict() *HTTPError {
	return &HTTPError{StatusCode: http.StatusConflict, Status: "CONFLICT"}
}

// PreconditionFailed is for requests that do not satisfy pre-business layers of the application.
func PreconditionFailed() *HTTPError {
	return &HTTPError{StatusCode: http.StatusPreconditionFailed, Status: "PRECONDITION_FAILED"}
}

// InternalServerError is for requests that cause an unexpected misbehaviour.
func InternalServerError() *HTTPError {
	return &HTTPError{StatusCode: http.StatusInternalServerError, Status: "INTERNAL_SERVER_ERROR"}
}

// ServiceUnavailable is returned when the system is not available enough to serve the request.
func ServiceUnavailable() *HTTPError {
	return &HTTPError{StatusCode: http.StatusServiceUnavailable, Status: "SERVICE_UNAVAILABLE"}
}
