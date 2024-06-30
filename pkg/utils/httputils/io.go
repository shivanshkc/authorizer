package httputils

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/shivanshkc/authorizer/pkg/utils/errutils"
)

// Write writes the provided data as the HTTP response using the provided writer.
func Write(writer http.ResponseWriter, status int, headers map[string]string, body interface{}) {
	// The content-type is application/json for all cases.
	writer.Header().Set("content-type", "application/json")
	// Setting the provided headers.
	for key, value := range headers {
		writer.Header().Set(key, value)
	}

	// Converting the provided body to a byte slice for writing.
	responseBytes, err := json.Marshal(body)
	if err != nil {
		slog.Error("failed to marshal body", "err", err)
	}

	// Setting the content-length header.
	writer.Header().Set("content-length", fmt.Sprintf("%d", len(responseBytes)))

	// Setting the status code. No more headers can be set after this.
	writer.WriteHeader(status)
	// Writing the body to the response.
	_, _ = writer.Write(responseBytes)
}

// WriteErr writes the provided error as the HTTP response using the provided writer.
func WriteErr(writer http.ResponseWriter, err error) {
	// Converting to HTTPError to get status-code.
	errHTTP := errutils.ToHTTPError(err)
	// Writing the response.
	Write(writer, errHTTP.StatusCode, nil, errHTTP)
}

// Is2xx returns true if the provided status belongs to the 2xx family.
func Is2xx(status int) bool {
	return status/100 == 2
}
