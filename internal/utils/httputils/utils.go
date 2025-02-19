package httputils

import (
	"net/http"
	"strings"
)

// RoundTripFunc is used to override the client transport if needed.
// This func implements http.RoundTripper interface.
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip will execute the round tripper func.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// TrimProtocol trims the http:// or https:// protocol from the given URL.
func TrimProtocol(url string) string {
	return strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
}
