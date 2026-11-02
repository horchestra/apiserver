package apiserver

import (
	"github.com/rs/zerolog"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/authz"
	"github.com/horchestra/apiserver/errors"
	"github.com/horchestra/apiserver/metrics"
)

type config struct {
	errors           errors.Writer
	log              *zerolog.Logger
	authn            authn.Authenticator
	authz            authz.Authorizer
	instrument       []Middleware
	attrs            authz.AttributesFunc
	middleware       []Middleware
	notFound         Handler
	allowEncodedPath bool
}

// Option configures a Router at New. Everything a component decides about its HTTP surface that is
// not a route is decided here, in one call, so the wiring can be read in one place.
type Option func(*config)

// WithLogger names the logger the chain writes to. Unset is the process-wide zerolog logger, so a
// component that wires none still leaves a trail; a component with a logger of its own — one
// carrying the component name, as every binary in this platform builds — passes it here.
func WithLogger(l *zerolog.Logger) Option {
	return func(c *config) { c.log = l }
}

// WithErrorWriter decides what a refusal looks like on the wire. Unset is errors.JSON; a
// Kubernetes-shaped API passes errors/k8s.Writer.
func WithErrorWriter(w errors.Writer) Option {
	return func(c *config) { c.errors = w }
}

// WithAuthenticator names the credentials this server admits. Unset means the server does not
// authenticate at all — every request reaches the handlers as an unknown caller — which is a
// choice worth making out loud and never a default anything falls into.
func WithAuthenticator(a authn.Authenticator) Option {
	return func(c *config) { c.authn = a }
}

// WithAuthorizer names what decides whether a caller may do what they asked. Unset means no
// authorization step: use authz.AllowAll to say so explicitly when authentication alone is the
// gate.
func WithAuthorizer(az authz.Authorizer) Option {
	return func(c *config) { c.authz = az }
}

// WithAttributes decides how a request is turned into the attributes a rule is written about.
// Unset is authz.REST, the Kubernetes-shaped reading; a surface whose paths name no resources
// passes authz.Path or its own.
func WithAttributes(attrs authz.AttributesFunc) Option {
	return func(c *config) { c.attrs = attrs }
}

// WithMetrics measures every request this server serves, refusals included.
//
// The measurement sits outside authentication on purpose: a server whose 401s were invisible
// reports perfect health while nobody can reach it. Collectors are registered where the component
// says (metrics.New), and the exposition is a route the component binds — metrics.Handler — so a
// scraper goes through the same chain as any other caller.
func WithMetrics(m *metrics.Requests) Option {
	return WithInstrumentation(m.Middleware())
}

// WithInstrumentation puts a measurement where WithMetrics puts this module's own: OUTERMOST, around
// recovery, so a panic is counted as the 500 it becomes and a refusal as the 401 or 403 it is. It is
// for a component that keeps its measurements in a registry of its own; it sees the request and the
// error the chain below returned, and must not answer either.
func WithInstrumentation(mw ...Middleware) Option {
	return func(c *config) { c.instrument = append(c.instrument, mw...) }
}

// WithMiddleware adds a component's own middleware BETWEEN authentication and authorization: the
// caller is already resolved, and nothing it does can widen a decision the authorizer has not made
// yet. An audit trail goes here.
func WithMiddleware(mw ...Middleware) Option {
	return func(c *config) { c.middleware = append(c.middleware, mw...) }
}

// WithNotFound replaces the handler for a path no route serves. It runs OUTSIDE the middleware
// chain (see Server.notFound), so a replacement authenticates for itself or answers the same
// thing to everyone.
func WithNotFound(h Handler) Option {
	return func(c *config) { c.notFound = h }
}

// AllowEncodedPath lets through a request-URI whose path is not already its own canonical
// encoding. Do not use it on a server that authorizes by path.
//
// The default refusal closes a routing/authorization split-brain. bunrouter matches routes against
// RawPath when it is set and hands back raw, still-escaped parameters, while attributes are built
// from the percent-DECODED path — so a %2F inside one segment expands into extra segments for the
// authorizer while staying one opaque segment for the router. The permission that is checked and
// the object that is served then come from different namespaces, which is a cross-namespace
// authorization bypass reachable through any segment no handler reads.
//
// net/http sets RawPath exactly when the escaped form differs from the canonical encoding of Path,
// and an API whose names are RFC1123-shaped never needs one, so refusing it keeps the two views
// the same string by construction.
func AllowEncodedPath() Option {
	return func(c *config) { c.allowEncodedPath = true }
}
