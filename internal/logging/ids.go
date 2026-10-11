package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type ctxKey int

const (
	traceKey ctxKey = iota
	requestKey
)

// NewID returns a fresh random ID: 32 lower-case hex characters.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// The system source of randomness failing is not something a log
		// should hide behind a panic; an all-zero ID still sorts and greps.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// ValidID reports whether s is something this project accepts as a trace or
// request ID: 16 to 32 lower-case hex characters. IDs arrive from outside (a
// browser, the control service, the installer's environment); anything else is
// replaced rather than written into a log or a command line.
func ValidID(s string) bool {
	if len(s) < 16 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// WithTrace puts the trace ID of the operation in the context; the handler
// writes it as trace_id on every record logged with that context.
func WithTrace(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceKey, id)
}

// TraceID is the trace ID carried by ctx, or empty.
func TraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(traceKey).(string)
	return s
}

// WithRequestID puts the ID of one HTTP request in the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestKey, id)
}

// RequestID is the request ID carried by ctx, or empty.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(requestKey).(string)
	return s
}
