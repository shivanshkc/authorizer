package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// contextKey can be used to put values in a context type.
type contextKey int

const (
	// KeyRequestID should be used to put the request-id in a request's context.
	KeyRequestID contextKey = iota
	// KeyTraceID should be used to put the trace-id in a request's context.
	KeyTraceID

	// logFormat is the format in which the logs will be printed.
	logFormat = `{"level":"%s","timestamp":"%s","request_id":"%v","trace_id":"%v","caller":%s,"message":"%s"}`
)

// getFormattedCaller provides formatted caller details.
func getFormattedCaller(skip int) string {
	// Format of the string that will be returned.
	returnFormat := `{"package":"%s","file":"%s","line":"%d"}`

	// Adding 1 to skip because this function too is an additional caller.
	programCounter, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return fmt.Sprintf(returnFormat, "unknown", "unknown", 0)
	}

	// Trimming the file name to at most 2 path elements.
	pathElements := strings.Split(file, string(os.PathSeparator))
	if len(pathElements) > 0 {
		pathElements = pathElements[len(pathElements)-1:]
	}
	// Reassigning file with new path elements.
	file = strings.Join(pathElements, string(os.PathSeparator))

	// Fetching exact function details.
	details := runtime.FuncForPC(programCounter)
	// Final caller details.
	return fmt.Sprintf(returnFormat, details.Name(), file, line)
}
