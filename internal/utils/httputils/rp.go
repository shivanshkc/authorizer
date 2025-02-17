package httputils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// RoundTripFunc is used to override the client transport if needed.
// This func implements http.RoundTripper interface.
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip will execute the round tripper func.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// RoundTripperJSON returns a round tripper that delivers the given response as the response body.
func RoundTripperJSON(response any) (RoundTripFunc, error) {
	var marshalled []byte
	var err error

	switch asserted := response.(type) {
	case []byte:
		marshalled = asserted
	case string:
		marshalled = []byte(asserted)
	default:
		marshalled, err = json.Marshal(response)
		if err != nil {
			return nil, fmt.Errorf("error in json.Marshal call: %w", err)
		}
	}

	return func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(marshalled)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}
	}, nil
}
