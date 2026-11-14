package httputils

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
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

// DomainFromURL converts URLs like "https://google.com/search" to "google.com"
func DomainFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	host := u.Host

	// Remove port if present.
	host, _, err = net.SplitHostPort(host)
	if err != nil {
		// If there's no port, SplitHostPort fails. Return original host.
		return u.Host, nil
	}

	return host, nil
}
