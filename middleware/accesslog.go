package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/errors"
	"github.com/horchestra/apiserver/internal/respond"
)

// AccessLog writes one line per request, after it has been served.
//
// The status comes from whichever is true: the code the handler wrote, or the code the error it
// returned will be rendered as. A refusal never reaches the writer through this middleware — it is
// returned up to the Server — so a log that only watched the ResponseWriter would report 200 for
// every 403 in the fleet.
//
// It sits INSIDE Recover and OUTSIDE authentication: a panic is still a served request and must
// appear here. The identity is established further in, on a copy of the request this layer never
// holds, so it is read back through authn.Observe rather than from the request's own context.
//
// bytes is what the handler wrote. A refusal is returned and rendered once, at the top, after this
// line is written, so a refused request reports 0 here and in the metrics' body-size series.
func AccessLog(l *zerolog.Logger) bunrouter.MiddlewareFunc {
	log := logger(l)
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			started := time.Now()
			rec := respond.Wrap(w)
			ctx, caller := authn.Observe(req.Context())
			err := next(rec, req.WithContext(ctx))

			status := rec.Status()
			if err != nil {
				status = errors.StatusOf(err)
			}
			if status == 0 {
				status = http.StatusOK
			}

			ev := log.WithLevel(level(status)).
				Str("verb", req.Method).Str("path", req.URL.Path).
				Int("status", status).Dur("took", time.Since(started)).
				Int64("bytes", rec.Written()).Str("remote", req.RemoteAddr)

			if id := caller(); id != nil {
				ev = ev.Str("user", id.Name)
			}
			ev.Msg("request served")

			return err
		}
	}
}

// level keeps the ordinary traffic at DEBUG and lifts only what an operator would want to see: a
// server-side failure is an error, a refusal or a bad request is a warning. A fleet that logged
// every 200 at INFO buries both.
func level(status int) zerolog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return zerolog.ErrorLevel
	case status >= http.StatusBadRequest:
		return zerolog.WarnLevel
	default:
		return zerolog.DebugLevel
	}
}
