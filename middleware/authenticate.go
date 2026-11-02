package middleware

import (
	stderrors "errors"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/errors"
)

// Authenticate resolves the caller and puts them in the request context, or refuses with a 401.
//
// It prefers the response-driving form when the authenticator has one: a scheme that challenges
// writes its header here, and that header survives the 401 the error path emits afterwards,
// because the body is written once, at the very top, by the Server.
//
// Whatever the authenticator's own sentence was becomes the message. It is the caller's own
// credential that failed, so there is nothing to hide, and "invalid credentials" alone sends an
// operator to read logs for something the answer could have said.
func Authenticate(a authn.Authenticator, l *zerolog.Logger) bunrouter.MiddlewareFunc {
	log := logger(l)
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			id, err := Identify(w, a, req.Request)
			if err != nil {
				return AuthenticationFailed(log, req.Request, err)
			}
			return next(w, req.WithContext(authn.WithIdentity(req.Context(), id)))
		}
	}
}

// Identify asks the authenticator who the caller is, through the response-driving form when it has
// one, so a challenge reaches the 401 on every path that refuses. An authenticator that names nobody
// and reports nothing has found no credentials.
func Identify(w http.ResponseWriter, a authn.Authenticator, r *http.Request) (*authn.Identity, error) {
	if ra, ok := a.(authn.ResponseAuthenticator); ok {
		return ra.AuthenticateHTTP(w, r)
	}
	id, err := a.Authenticate(r)
	if err == nil && id == nil {
		return nil, authn.ErrNoCredentials
	}
	return id, err
}

// Refused writes the one line every refusal leaves, in every build: who was turned away from what,
// and why.
//
// It is written where the decision is made. An authenticator's refusal reaches no handler further
// in, and a middleware wrapped around this one holds the request as it was BEFORE the identity was
// attached and would name nobody — so an outer log would report every refusal as anonymous.
//
// WARN, because a refusal is something an operator may have to act on: an expired certificate, a
// role that lost a rule, somebody knocking. It is a log line and not an audit record — no id, no
// closed vocabulary — so a build with an audit trail writes that trail beside it, and a build
// without one still answers `journalctl | grep 'request refused'`.
func Refused(l *zerolog.Logger, r *http.Request, status int, who *authn.Identity, reason string) {
	ev := logger(l).Warn().Int("status", status).
		Str("verb", r.Method).Str("path", r.URL.Path).Str("remote", r.RemoteAddr)
	if who != nil {
		ev = ev.Str("user", who.Name).Strs("groups", who.Groups)
	}
	ev.Str("reason", reason).Msg("request refused")
}

// AuthenticationFailed answers what an authenticator returned instead of a caller. A credential
// that was refused is a 401. An authenticator that could not decide — its directory down, its
// review endpoint unreachable — says so with an error carrying its own status (errors.Unavailable,
// errors.Internal), and keeps it: answered as a 401, an outage reads as a bad credential and sends
// an operator to chase authentication instead of the store.
func AuthenticationFailed(l *zerolog.Logger, r *http.Request, err error) error {
	if se, ok := stderrors.AsType[errors.Error](err); ok && se.HTTPStatus() != http.StatusUnauthorized {
		logger(l).Error().Err(err).Str("verb", r.Method).Str("path", r.URL.Path).
			Msg("the authenticator could not decide")
		return se
	}
	Refused(l, r, http.StatusUnauthorized, nil, err.Error())
	return errors.Wrap(http.StatusUnauthorized, err)
}
