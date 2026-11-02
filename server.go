// Package apiserver is the HTTP surface every component of the platform serves its API on: one
// router, one middleware chain, one shape for an error, one line per refusal.
//
// It exists because the alternative was measured: the control plane grew a router with
// authentication, authorization, panic recovery and a Kubernetes-shaped error body, and every
// other surface beside it — a node agent's metrics endpoint, a registry, a proxy's admin API —
// started from net/http again and arrived somewhere else. Nothing about "who may call this" is
// component-specific, and a second implementation of it is a second place for a hole.
//
// What a component brings is the parts that ARE its own: which credentials it admits (a chain of
// authn packages), what its rules say (an authz.Authorizer), what its errors look like on the wire
// (an errors.Writer), and its routes.
package apiserver

import (
	"net/http"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/errors"
	"github.com/horchestra/apiserver/middleware"
)

// The router's own vocabulary, re-exported so that a component writing handlers imports this
// module alone and the router underneath stays an implementation detail of it.
type (
	Handler    = bunrouter.HandlerFunc
	Request    = bunrouter.Request
	Middleware = bunrouter.MiddlewareFunc
)

// Router is the router and everything wrapped around it. Build it with New, register routes,
// then mount it: it is an http.Handler.
type Router struct {
	router *bunrouter.Router
	// paths is every path this server answers on, remembered as it is registered. It is filled by
	// the registration helpers rather than written out a second time, because an index kept by
	// hand is an index that drifts from the server it describes, and the drift shows up as a
	// client looking for something that is not there.
	paths            map[string]struct{}
	errors           errors.Writer
	log              *zerolog.Logger
	authn            authn.Authenticator
	allowEncodedPath bool
	// outside wraps what answers outside the chain in the measurement, recovery and access log the
	// chain begins with.
	outside func(Handler) Handler
}

// New assembles the chain and returns a server with no routes on it yet.
//
// The order of the chain is fixed here and it is the whole security argument: recovery outermost
// so a panic anywhere below becomes one 500; the measurement and the access log next, so a request
// that panicked or was refused still leaves a line and a series; authentication before anything
// that reads an identity; a component's own middleware after it, where the caller is known;
// authorization last, so nothing between it and the handler can widen what was decided.
func New(opts ...Option) *Router {
	cfg := config{errors: errors.JSON}
	for _, opt := range opts {
		opt(&cfg)
	}
	s := &Router{
		paths:            map[string]struct{}{},
		errors:           cfg.errors,
		log:              cfg.log,
		authn:            cfg.authn,
		allowEncodedPath: cfg.allowEncodedPath,
	}
	chain := append([]Middleware(nil), cfg.instrument...)
	chain = append(chain, middleware.Recover(cfg.log))
	chain = append(chain, middleware.AccessLog(cfg.log))
	if cfg.authn != nil {
		chain = append(chain, middleware.Authenticate(cfg.authn, cfg.log))
	}
	chain = append(chain, cfg.middleware...)
	if cfg.authz != nil {
		chain = append(chain, middleware.Authorize(cfg.authz, cfg.attrs, cfg.log))
	}

	// What answers outside the chain — a path no route serves, a percent-encoded path — is outside
	// AUTHORIZATION only: it is still measured, still recovered from, still logged. An unrouted
	// request with no metric and no line is a scanner hammering the server leaving nothing behind.
	outside := append(append([]Middleware(nil), cfg.instrument...), middleware.Recover(cfg.log), middleware.AccessLog(cfg.log))
	s.outside = func(h Handler) Handler {
		for i := len(outside) - 1; i >= 0; i-- {
			h = outside[i](h)
		}
		return h
	}

	notFound := cfg.notFound
	if notFound == nil {
		notFound = s.notFound
	}
	s.router = bunrouter.New(
		// Registered BEFORE the middleware, and the order is the whole point: bunrouter binds the
		// not-found handler to the stack that exists at that moment, so declaring it first leaves
		// it outside the chain. See notFound for why it must be.
		bunrouter.WithNotFoundHandler(s.outside(notFound)),
		bunrouter.Use(chain...),
	)
	return s
}

func (s *Router) GET(path string, h Handler)    { s.Handle(http.MethodGet, path, h) }
func (s *Router) POST(path string, h Handler)   { s.Handle(http.MethodPost, path, h) }
func (s *Router) PUT(path string, h Handler)    { s.Handle(http.MethodPut, path, h) }
func (s *Router) PATCH(path string, h Handler)  { s.Handle(http.MethodPatch, path, h) }
func (s *Router) DELETE(path string, h Handler) { s.Handle(http.MethodDelete, path, h) }
func (s *Router) HEAD(path string, h Handler)   { s.Handle(http.MethodHead, path, h) }

// Handle binds one method and path, and remembers the path for the index.
func (s *Router) Handle(method, path string, h Handler) {
	s.remember(path)
	s.router.Handle(method, path, h)
}

// NewGroup opens a set of routes under a shared prefix. The paths a group remembers are the FULL
// ones, so the index does not depend on where a route was declared.
func (s *Router) NewGroup(prefix string) *Group {
	return &Group{server: s, group: s.router.NewGroup(prefix), prefix: prefix}
}

// WithGroup is NewGroup with the routes declared in place, which keeps a prefix and everything
// under it in one block — the router's own spelling, kept so that code moving onto this module
// reads the same.
func (s *Router) WithGroup(prefix string, fn func(*Group)) {
	fn(s.NewGroup(prefix))
}

// Group is a prefix and the routes under it.
type Group struct {
	server *Router
	group  *bunrouter.Group
	prefix string
}

func (g *Group) GET(path string, h Handler)    { g.Handle(http.MethodGet, path, h) }
func (g *Group) POST(path string, h Handler)   { g.Handle(http.MethodPost, path, h) }
func (g *Group) PUT(path string, h Handler)    { g.Handle(http.MethodPut, path, h) }
func (g *Group) PATCH(path string, h Handler)  { g.Handle(http.MethodPatch, path, h) }
func (g *Group) DELETE(path string, h Handler) { g.Handle(http.MethodDelete, path, h) }
func (g *Group) HEAD(path string, h Handler)   { g.Handle(http.MethodHead, path, h) }

func (g *Group) Handle(method, path string, h Handler) {
	g.server.remember(g.prefix + path)
	g.group.Handle(method, path, h)
}

// NewGroup nests another prefix under this one.
func (g *Group) NewGroup(prefix string) *Group {
	return &Group{server: g.server, group: g.group.NewGroup(prefix), prefix: g.prefix + prefix}
}

// WithGroup nests a prefix with its routes declared in place.
func (g *Group) WithGroup(prefix string, fn func(*Group)) {
	fn(g.NewGroup(prefix))
}

// AlsoServes names paths this process answers on that this router never sees — the probes bound on
// a mux in front of it, a second handler mounted beside it. Without it the index omits exactly the
// paths an operator checks first, and an omitted path reads as one that is not there.
func (s *Router) AlsoServes(paths ...string) {
	for _, p := range paths {
		s.remember(p)
	}
}

// Paths is what this server serves, sorted.
//
// A registered path carrying a PARAMETER (/apis/:group) is left out: it is a pattern, not a path,
// and nothing can be fetched from it. A component that wants those concrete paths in the index —
// the ones its own discovery already knows — adds them with AlsoServes.
func (s *Router) Paths() []string {
	out := make([]string, 0, len(s.paths))
	for p := range s.paths {
		if strings.ContainsAny(p, ":*") {
			continue
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Routes is every path registered on this router, patterns included, sorted. Paths is what a
// client can fetch; this is what the router matches, for a test that has to walk every route.
func (s *Router) Routes() []string {
	out := make([]string, 0, len(s.paths))
	for p := range s.paths {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// ServePathIndex answers with the paths this server serves, which is where a client that knows
// nothing about it starts. Bind it at "/" if the component wants one; nothing binds it by itself.
func (s *Router) ServePathIndex(w http.ResponseWriter, _ Request) error {
	errors.WriteJSON(w, http.StatusOK, map[string]any{"paths": s.Paths()})
	return nil
}

func (s *Router) remember(path string) { s.paths[path] = struct{}{} }

// Logger is the logger the chain writes to, for a component that wants its handlers on the same
// one. It is the process-wide zerolog logger when New was given none.
func (s *Router) Logger() *zerolog.Logger {
	if s.log == nil {
		return &log.Logger
	}
	return s.log
}

// Error renders err into the response with this server's writer. Handlers return errors and do not
// call this; it is here for the code OUTSIDE the chain — a not-found handler, a wrapper mounted in
// front — so that those answer in the same shape as everything else.
func (s *Router) Error(w http.ResponseWriter, r *http.Request, err error) {
	s.errors.WriteError(w, r, err)
}

func (s *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !s.allowEncodedPath && len(req.URL.RawPath) > 0 {
		refuse := s.outside(func(w http.ResponseWriter, req Request) error {
			s.Error(w, req.Request, errors.BadRequest("request path must not contain percent-encoded characters"))
			return nil
		})
		if err := refuse(w, bunrouter.NewRequest(req)); err != nil {
			s.Error(w, req, err)
		}
		return
	}
	if err := s.router.ServeHTTPError(w, req); err != nil {
		s.Error(w, req, err)
	}
}

// notFound answers a path no route serves, and WRITES the answer rather than returning it: nothing
// renders an error on this path, because the chain that would have never runs for a request that
// matched no route.
//
// It is the ONE handler outside the chain, and it authenticates for itself instead. bunrouter
// resolves the route BEFORE the middleware runs, so a miss selected this handler and the chain
// then wrapped it — which sent every typo to an authorizer with nothing to authorize: no resource,
// no verb, no object, only a string. It refused, as it must for a path no rule can name, and every
// mistyped path came back 403. That is the wrong answer twice over: it says "you may not" where
// the truth is "there is nothing there", and it says it to an administrator as readily as to
// anyone else.
//
// What is left to check here is identity, because "no such path" is itself information about the
// server — which routes exist, which features are switched on — and must not be free to whoever
// can open a socket. With no authenticator wired, the answer is the 404.
func (s *Router) notFound(w http.ResponseWriter, req Request) error {
	if s.authn != nil {
		id, err := middleware.Identify(w, s.authn, req.Request)
		if err != nil {
			s.Error(w, req.Request, middleware.AuthenticationFailed(s.log, req.Request, err))
			return nil
		}
		// The context is dropped on purpose: nothing further in reads it. The call fills the slot
		// the access log's authn.Observe left, which names the caller the same way on every path.
		_ = authn.WithIdentity(req.Context(), id)
	}
	s.Error(w, req.Request, errors.NotFound("the server could not find the requested resource"))
	return nil
}
