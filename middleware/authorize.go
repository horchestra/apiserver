package middleware

import (
	stderrors "errors"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/authz"
	"github.com/horchestra/apiserver/errors"
)

// Authorize decides whether the caller resolved by Authenticate may do what they asked.
//
// Only authz.Allow passes. NoOpinion refuses like Deny does, because "no rule mentions this" is
// not a grant — a request nobody wrote a rule about is one nobody permitted, and the opposite
// reading turns every gap in a policy into an open door.
//
// attrs decides what the request IS: authz.REST for a Kubernetes-shaped API, authz.Path for a
// surface whose paths name no resources, or a component's own.
//
// An authorizer that knows WHY it refuses returns its own *authz.Refusal as the error: that is a
// 403 in its words — a decision another server made and this one only carries — and not the 500
// every other error from an authorizer is.

func Authorize(az authz.Authorizer, attrs authz.AttributesFunc, l *zerolog.Logger) bunrouter.MiddlewareFunc {
	log := logger(l)
	if attrs == nil {
		attrs = authz.REST
	}
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			at := attrs(req.Request, authn.FromContext(req.Context()))
			decision, err := az.Authorize(req.Context(), at)
			if refusal, ok := stderrors.AsType[*authz.Refusal](err); ok {
				Refused(log, req.Request, http.StatusForbidden, at.User, refusal.Reason)
				return refusal
			}
			if err != nil {
				log.Error().Err(err).Str("verb", at.Verb).Str("path", at.Path).
					Msg("the authorizer could not decide")
				return errors.Internal(err)
			}
			if decision != authz.Allow {
				reason := "no rule grants " + at.Verb + " on " + Describe(at)
				Refused(log, req.Request, http.StatusForbidden, at.User, reason)
				return &authz.Refusal{Attributes: at, Reason: reason}
			}
			return next(w, req)
		}
	}
}

// Describe names what a caller asked for, the way a rule would: group/resource, the subresource if
// any, and the namespace and name when the request had them.
func Describe(at authz.Attributes) string {
	if !at.ResourceRequest {
		return at.Path
	}
	what := at.Resource
	if len(at.Group) > 0 {
		what = at.Group + "/" + what
	}
	if len(at.Subresource) > 0 {
		what += "/" + at.Subresource
	}
	if len(at.Namespace) > 0 {
		what += " in namespace " + at.Namespace
	}
	if len(at.Name) > 0 {
		what += " named " + at.Name
	}
	return what
}
