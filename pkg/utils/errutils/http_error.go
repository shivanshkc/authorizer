package errutils

import (
	"errors"
)

// HTTPError is a custom error type that implements the error interface.
type HTTPError struct {
	StatusCode int    `json:"-"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
}

// Error provides the reason behind the error, which is usually human-readable.
// If the reason is absent, it provides the error code instead.
func (h *HTTPError) Error() string {
	if h.Reason != "" {
		return h.Reason
	}
	// Returning code if reason is empty.
	return h.Status
}

// WithReasonStr is a chainable method to set the reason of the HTTPError.
//
// This accepts the reason as a string.
func (h *HTTPError) WithReasonStr(reason string) *HTTPError {
	h.Reason = reason
	return h
}

// WithReasonErr is a chainable method to set the reason of the HTTPError.
//
// This accepts the reason as an error.
func (h *HTTPError) WithReasonErr(reason error) *HTTPError {
	h.Reason = reason.Error()
	return h
}

// ToHTTPError converts any value to an appropriate HTTPError.
func ToHTTPError(err any) *HTTPError {
	switch asserted := err.(type) {
	case *HTTPError:
		return asserted
	case HTTPError:
		return &asserted
	case error:
		var errHTTP *HTTPError
		if errors.As(asserted, &errHTTP) {
			return errHTTP
		}
		return InternalServerError().WithReasonErr(asserted)
	case string:
		return InternalServerError().WithReasonStr(asserted)
	default:
		return InternalServerError()
	}
}
