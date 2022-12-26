package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// Debug logs at the debug level.
//
// Use it for logs that will be useful only in a debug session.
//
//nolint:goprintffuncname
func Debug(ctx context.Context, format string, values ...interface{}) {
	write(ctx, os.Stdout, "debug", format, values...)
}

// Info logs at the info level.
//
// Use it for logs that convey the basic functioning of the service.
//
//nolint:goprintffuncname
func Info(ctx context.Context, format string, values ...interface{}) {
	write(ctx, os.Stdout, "info", format, values...)
}

// Warn logs at the warn level.
//
// Use it for scenarios that are unwanted, yet expected.
//
//nolint:goprintffuncname
func Warn(ctx context.Context, format string, values ...interface{}) {
	write(ctx, os.Stderr, "warn", format, values...)
}

// Error logs at the error level.
//
// Use it for scenarios that are unwanted and unexpected.
//
//nolint:goprintffuncname
func Error(ctx context.Context, format string, values ...interface{}) {
	write(ctx, os.Stderr, "error", format, values...)
}

// Fatal logs at the fatal level. It panics after logging.
//
// Use it for scenarios that are absolutely catastrophic.
//
//nolint:goprintffuncname
func Fatal(ctx context.Context, format string, values ...interface{}) {
	<-write(ctx, os.Stderr, "fatal", format, values...)
	panic(fmt.Sprintf(format, values...))
}

// write is the centralized logging function.
//
// It logs without blocking but returns a read-only channel that can be used to await the operation's completion.
func write(ctx context.Context, dest io.Writer, level string, format string, values ...interface{}) <-chan struct{} {
	// Get the parameters required for logging.
	timestamp, requestID, traceID, caller, message := time.Now().Format(time.RFC3339Nano), ctx.Value(KeyRequestID),
		ctx.Value(KeyTraceID), getFormattedCaller(2), fmt.Sprintf(format, values...)

	// This channel can be used by the caller to know when the function is done logging.
	doneChan := make(chan struct{})
	// Print to the given destination without blocking.
	go func() {
		_, _ = fmt.Fprintf(dest, logFormat+"\n", level, timestamp, requestID, traceID, caller, message)
		close(doneChan)
	}()
	// The caller can listen to this channel if they want to await the IO operation's completion.
	return doneChan
}
