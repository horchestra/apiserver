package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/errors"
)

// Recover turns a panic anywhere below it into a 500 for that one request, logged with its stack.
//
// Without it net/http's own recovery aborts the connection with no line and no stack, so a
// reachable panic degrades into an unattributable stream of dropped requests. It goes OUTERMOST,
// so that a panic in the middleware chain itself is caught too.
//
// The caller is told nothing but "internal server error": the panic value and the stack name
// types, fields and paths from inside the process, and a client is not where those belong.
func Recover(l *zerolog.Logger) bunrouter.MiddlewareFunc {
	log := logger(l)
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) (err error) {
			defer func() {
				if v := recover(); v != nil {
					log.Error().Interface("panic", v).
						Str("verb", req.Method).Str("path", req.URL.Path).
						Bytes("stack", debug.Stack()).
						Msg("recovered from a panic serving a request")
					err = errors.New(http.StatusInternalServerError, "internal server error")
				}
			}()
			return next(w, req)
		}
	}
}
