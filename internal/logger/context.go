package logger

import (
	"context"
	"log/slog"
)

type contextKey int

// ctxKey is used to put values into a context that are intended to be logged.
const ctxKey contextKey = iota

// ContextHandler is a custom slog.Handler implementation that logs the values present in the context.
type ContextHandler struct {
	slog.Handler
}

// Handle adds the context values as attributes before calling the underlying handler.
func (c *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs, ok := ctx.Value(ctxKey).([]slog.Attr); ok {
		for _, v := range attrs {
			r.AddAttrs(v)
		}
	}
	return c.Handler.Handle(ctx, r)
}

// WithAttrs makes sure that ContextHandler is compatible with `slog.With` usage.
func (c *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	underlyingHandler := c.Handler.WithAttrs(attrs)
	return &ContextHandler{Handler: underlyingHandler}
}

// AddContextValue returns a new context that includes the given value.
//
// Any slog statements logged using the returned context will log this value.
func AddContextValue(parent context.Context, key string, value any) context.Context {
	// Make slog.Attr from key-value.
	attr := slog.Attr{Key: key, Value: slog.AnyValue(value)}

	if parent == nil {
		parent = context.Background()
	}

	// The child context will have the parent's slog attributes too.
	if v, ok := parent.Value(ctxKey).([]slog.Attr); ok {
		v = append(v, attr)
		return context.WithValue(parent, ctxKey, v)
	}

	return context.WithValue(parent, ctxKey, []slog.Attr{attr})
}

// GetContextValues returns all the key-value pairs that were put in the given context by the AddContextValue function.
func GetContextValues(ctx context.Context) map[string]slog.Value {
	v, ok := ctx.Value(ctxKey).([]slog.Attr)
	if !ok {
		return nil
	}

	m := map[string]slog.Value{}
	for _, entry := range v {
		m[entry.Key] = entry.Value
	}

	return m
}
