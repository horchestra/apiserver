package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/horchestra/apiserver"
	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/authn/basic"
	"github.com/horchestra/apiserver/authn/bearer"
	"github.com/horchestra/apiserver/authz"
	"github.com/horchestra/apiserver/errors"
	"github.com/horchestra/apiserver/metrics"
)

const token = "the-operator's-token"

// serve builds a server wired the way a component wires one, registers a single route, and answers
// the request.
func serve(t *testing.T, req *http.Request, opts ...apiserver.Option) *httptest.ResponseRecorder {
	t.Helper()
	quiet := zerolog.Nop()
	opts = append([]apiserver.Option{apiserver.WithLogger(&quiet)}, opts...)
	srv := apiserver.New(opts...)
	srv.GET("/apis/horchestra.io/v1/namespaces/:namespace/applications/:name", func(w http.ResponseWriter, r apiserver.Request) error {
		errors.WriteJSON(w, http.StatusOK, map[string]string{"name": r.Param("name")})
		return nil
	})
	srv.GET("/panics", func(http.ResponseWriter, apiserver.Request) error {
		panic("a handler that was never going to work")
	})
	srv.AlsoServes("/healthz")

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func authenticated() apiserver.Option {
	return apiserver.WithAuthenticator(authn.Chain{
		bearer.Authenticator{Verifier: bearer.NewStatic(map[string]authn.Identity{
			token: {Name: "alice", Groups: []string{"operators"}},
		})},
	})
}

func request(path string, authorized bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if authorized {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// TestAuthenticatedAndAuthorizedRequestReachesTheHandler is the whole chain in one pass: the token
// names a caller, the authorizer admits them, and the handler's own body comes back.
func TestAuthenticatedAndAuthorizedRequestReachesTheHandler(t *testing.T) {
	rec := serve(t, request("/apis/horchestra.io/v1/namespaces/team-a/applications/web", true),
		authenticated(), apiserver.WithAuthorizer(authz.AllowAll))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"web"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

// TestUnidentifiedCallerIsRefused: no credentials, no route — the 401 comes from the chain and is
// rendered in the component's error shape, not in bunrouter's plain text.
func TestUnidentifiedCallerIsRefused(t *testing.T) {
	rec := serve(t, request("/apis/horchestra.io/v1/namespaces/team-a/applications/web", false),
		authenticated(), apiserver.WithAuthorizer(authz.AllowAll))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":401`) {
		t.Fatalf("body = %s, want the error writer's shape", rec.Body.String())
	}
}

// TestRefusalNamesWhatWasAskedFor: a 403 that says only "forbidden" sends an operator to read the
// server's logs for something the answer could have said — the verb and the object it was refused
// on are in the body.
func TestRefusalNamesWhatWasAskedFor(t *testing.T) {
	rec := serve(t, request("/apis/horchestra.io/v1/namespaces/team-a/applications/web", true),
		authenticated(), apiserver.WithAuthorizer(authz.DenyAll))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"get", "horchestra.io/applications", "team-a", "web"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s does not name %q", body, want)
		}
	}
}

// TestNoOpinionRefuses: an authorizer that has no rule about the request has not granted anything.
func TestNoOpinionRefuses(t *testing.T) {
	silent := authz.Func(func(context.Context, authz.Attributes) (authz.Decision, error) {
		return authz.NoOpinion, nil
	})
	rec := serve(t, request("/apis/horchestra.io/v1/namespaces/team-a/applications/web", true),
		authenticated(), apiserver.WithAuthorizer(silent))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestUnroutedPathIs404ForACallerAndA401ForAStranger: "no such path" is information about the
// server — which routes exist, which features are on — so it is not free to whoever can open a
// socket. A caller who authenticated gets the truth: there is nothing there.
func TestUnroutedPathIs404ForACallerAndA401ForAStranger(t *testing.T) {
	rec := serve(t, request("/apis/horchestra.io/v1/mistyped", true), authenticated(), apiserver.WithAuthorizer(authz.AllowAll))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "404 page not found") {
		t.Fatalf("the router's own plain-text answer reached the client: %s", rec.Body.String())
	}

	rec = serve(t, request("/apis/horchestra.io/v1/mistyped", false), authenticated(), apiserver.WithAuthorizer(authz.AllowAll))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestUnroutedPathStillSaysHowToAuthenticate: the 401 on a mistyped path is the same answer as on a
// routed one, challenge included, or a client that negotiates never learns which scheme to try.
func TestUnroutedPathStillSaysHowToAuthenticate(t *testing.T) {
	challenging := apiserver.WithAuthenticator(authn.Chain{basic.Authenticator{Realm: "ops"}})
	for _, path := range []string{"/apis/horchestra.io/v1/mistyped", "/apis/horchestra.io/v1/namespaces/team-a/applications/web"} {
		rec := serve(t, request(path, false), challenging, apiserver.WithAuthorizer(authz.AllowAll))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", path, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="ops"` {
			t.Fatalf("%s: challenge = %q", path, got)
		}
	}
}

// TestUnroutedPathIsNotAnAuthorizationQuestion: the not-found handler is outside the chain, so a
// typo must not reach an authorizer with no resource, no verb and no object to judge — which
// refused, as it must, and turned every mistyped path into a 403 for everyone including an
// administrator.
func TestUnroutedPathIsNotAnAuthorizationQuestion(t *testing.T) {
	rec := serve(t, request("/apis/horchestra.io/v1/mistyped", true), authenticated(), apiserver.WithAuthorizer(authz.DenyAll))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — an unrouted path was judged by the authorizer", rec.Code)
	}
}

// TestPercentEncodedPathIsRefused closes a routing/authorization split-brain: the router matches
// on the raw path and hands back still-escaped parameters, while the attributes are built from the
// decoded one, so a %2F expands into extra segments for the authorizer while staying one segment
// for the router — the permission checked and the object served then come from different
// namespaces.
func TestPercentEncodedPathIsRefused(t *testing.T) {
	rec := serve(t, request("/apis/horchestra.io/v1/namespaces/team-a%2fapplications/applications/web", true),
		authenticated(), apiserver.WithAuthorizer(authz.AllowAll))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body: %s", rec.Code, rec.Body.String())
	}
}

// TestPanicBecomesOneRequestsWorthOf500: the connection survives, and the caller is told nothing
// about the inside of the process.
func TestPanicBecomesOneRequestsWorthOf500(t *testing.T) {
	rec := serve(t, request("/panics", true), authenticated(), apiserver.WithAuthorizer(authz.AllowAll))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "never going to work") {
		t.Fatalf("the panic value reached the client: %s", rec.Body.String())
	}
}

// TestPathsAreWhatTheServerAnswersOn: registration fills the index, patterns are left out because
// nothing can be fetched from one, and a path served by something mounted in front is named
// explicitly.
func TestPathsAreWhatTheServerAnswersOn(t *testing.T) {
	quiet := zerolog.Nop()
	srv := apiserver.New(apiserver.WithLogger(&quiet))
	srv.GET("/version", func(http.ResponseWriter, apiserver.Request) error { return nil })
	srv.GET("/apis/:group/:version", func(http.ResponseWriter, apiserver.Request) error { return nil })
	srv.WithGroup("/apis/horchestra.io/v1", func(g *apiserver.Group) {
		g.GET("/nodes", func(http.ResponseWriter, apiserver.Request) error { return nil })
		g.WithGroup("/namespaces/:namespace", func(ns *apiserver.Group) {
			ns.GET("/applications", func(http.ResponseWriter, apiserver.Request) error { return nil })
		})
	})
	srv.AlsoServes("/healthz")

	got := strings.Join(srv.Paths(), " ")
	for _, want := range []string{"/version", "/apis/horchestra.io/v1/nodes", "/healthz"} {
		if !strings.Contains(got, want) {
			t.Fatalf("paths %s do not carry %s", got, want)
		}
	}
	if strings.Contains(got, ":group") {
		t.Fatalf("a pattern reached the index: %s", got)
	}
}

// TestWithoutAnAuthenticatorEveryRequestIsAnonymous: a server that wires none does not
// authenticate at all, which is a choice a component makes out loud — the handler still runs, and
// nothing in the context names a caller.
func TestWithoutAnAuthenticatorEveryRequestIsAnonymous(t *testing.T) {
	quiet := zerolog.Nop()
	srv := apiserver.New(apiserver.WithLogger(&quiet))
	var saw *authn.Identity
	srv.GET("/metrics", func(w http.ResponseWriter, r apiserver.Request) error {
		saw = authn.FromContext(r.Context())
		return nil
	})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if saw != nil {
		t.Fatalf("identity = %+v, want none", saw)
	}
}

// TestNestedGroupsServeTheirFullPath: a route declared two prefixes deep answers on the whole path,
// and the parameters of both prefixes reach the handler. The router's own group spelling —
// NewGroup and WithGroup — is kept, so a surface moving onto this module keeps its route tree.
func TestNestedGroupsServeTheirFullPath(t *testing.T) {
	quiet := zerolog.Nop()
	srv := apiserver.New(apiserver.WithLogger(&quiet))
	srv.WithGroup("/apis/horchestra.io/v1", func(g *apiserver.Group) {
		g.WithGroup("/namespaces/:namespace", func(ns *apiserver.Group) {
			ns.GET("/applications/:name", func(w http.ResponseWriter, r apiserver.Request) error {
				errors.WriteJSON(w, http.StatusOK, map[string]string{
					"namespace": r.Param("namespace"),
					"name":      r.Param("name"),
				})
				return nil
			})
		})
	})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apis/horchestra.io/v1/namespaces/team-a/applications/web", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"namespace":"team-a"`) || !strings.Contains(body, `"name":"web"`) {
		t.Fatalf("body = %s", body)
	}
}

// TestMetricsCountRefusalsAndServeTheirOwnExposition: the measurement sits outside authentication,
// so the 401 the chain returns is counted — a server whose refusals were invisible reports perfect
// health while nobody can reach it. The exposition is an ordinary route, through the same chain.
func TestMetricsCountRefusalsAndServeTheirOwnExposition(t *testing.T) {
	quiet := zerolog.Nop()
	reg := prometheus.NewRegistry()
	srv := apiserver.New(
		apiserver.WithLogger(&quiet),
		apiserver.WithMetrics(metrics.New(reg, metrics.Options{})),
		authenticated(),
		apiserver.WithAuthorizer(authz.AllowAll),
	)
	srv.GET("/apis/horchestra.io/v1/nodes/:name", func(w http.ResponseWriter, r apiserver.Request) error {
		errors.WriteJSON(w, http.StatusOK, map[string]string{"name": r.Param("name")})
		return nil
	})
	srv.GET("/metrics", metrics.Handler(reg))

	for _, r := range []*http.Request{
		request("/apis/horchestra.io/v1/nodes/node-1", true),
		request("/apis/horchestra.io/v1/nodes/node-1", false),
	} {
		srv.ServeHTTP(httptest.NewRecorder(), r)
	}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, request("/metrics", true))

	body := rec.Body.String()
	for _, want := range []string{
		`http_requests_total{method="GET",route="/apis/horchestra.io/v1/nodes/:name",status="200"} 1`,
		`http_requests_total{method="GET",route="/apis/horchestra.io/v1/nodes/:name",status="401"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the exposition does not carry %s:\n%s", want, body)
		}
	}
}
