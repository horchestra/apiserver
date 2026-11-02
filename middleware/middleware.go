// Package middleware is the chain every request passes through before a handler sees it: recovery,
// the access log, authentication and authorization.
//
// Each is a bunrouter.MiddlewareFunc and each is separate, because the order is a decision a
// component makes and must be able to read back from its own wiring — Server assembles the usual
// one (see the module root), and a component that needs another writes it out.
//
// Refusals are RETURNED, never written. The chain hands the error to the Server, which renders it
// with the component's errors.Writer, so that a 403 from the authorizer and a 404 from a handler
// come out in one shape.
package middleware

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// logger is the one every middleware falls back to: the process-wide zerolog logger, so that a
// component that wired none still leaves a trail instead of dropping refusals silently.
func logger(l *zerolog.Logger) *zerolog.Logger {
	if l == nil {
		return &log.Logger
	}
	return l
}
