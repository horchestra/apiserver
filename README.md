# apiserver

The HTTP surface a component of this platform serves its API on: one router, one middleware chain, one shape for an
error, one line per refusal. It is a module of its own (`github.com/horchestra/apiserver`) and depends on nothing in the
platform, so the control plane, a node agent's metrics endpoint, the registry and a proxy's admin API can all stand on
it.

The pressure is measured rather than imagined. The control plane grew a router with authentication, authorization,
panic recovery and a Kubernetes-shaped error body; every other surface beside it started from `net/http` again and
arrived somewhere else — no identity, no common refusal, a 404 in plain text where a client expected an object.
Nothing about "who is calling and may they" is component-specific, and a second implementation of it is a second place
for a hole.

What a component brings is what IS its own: which credentials it admits (a chain of `authn` packages), what its rules
say (an `authz.Authorizer`), what an error looks like on its wire (an `errors.Writer`), and its routes. What this
module brings is the order those run in and the answers nobody should have to write twice.

It holds no state, no policy and no storage. `bunrouter` is the router underneath, re-exported as `apiserver.Handler`,
`Request` and `Middleware` so a component writing handlers imports this module alone. `zerolog` is the logger, because
every binary in this platform already carries one and a second logging vocabulary in the request path would split the
fleet's journal in two. `prometheus/client_golang` is the measurement, wired only when a component asks for it.

## What it may decide

**A1 — the order of the chain.** Measurement outermost, so a panic is counted as the 500 it becomes; then recovery, then the access log, then authentication, then a component's own
middleware, then authorization, then the handler. `New` writes it out and nothing can reorder it from a call site: a
component adds middleware only where the caller is already resolved and the authorizer has not yet decided, so nothing
between the decision and the handler can widen it.

**A2 — a refusal is returned, never written.** Every layer returns an error and the Server renders it, once, with the
component's `errors.Writer`. A 401 from the chain, a 403 from the authorizer and a 404 from a handler therefore come
out in one shape, and a middleware cannot half-write a response another layer then adds to.

**A3 — a rejected credential stops the chain.** `authn` distinguishes "no credentials of my kind" (`ErrNoCredentials`,
the chain moves on) from "presented and refused" (the chain stops). Without the split, a revoked token falls through to
whatever stands behind it — with an anonymous authenticator last, that is a 200 for the holder of a dead credential.

**A4 — an unrouted path is not an authorization question.** The not-found handler is bound before the middleware and
runs outside authorization. It authenticates for itself and answers 404, because the router resolves a route BEFORE the
chain runs: a typo used to reach an authorizer with no resource, no verb and no object, which refused as it must and
turned every mistyped path into a 403 — for an administrator as readily as for anyone else. Outside authorization is
not outside everything: the not-found handler, and the refusal of a percent-encoded path, still pass the measurement,
the recovery and the access log the chain begins with, and a stranger's 401 there is a `request refused` line like any
other.

**A5 — a route label is a template, never a path.** The metrics middleware labels by `req.Route()`, the pattern a route
was registered as. A path carries object names, so labelling by it opens one series per object in the fleet and one more
per mistyped name anybody cares to send; a request that matched no route at all is counted under a single
`<unrouted>` label, for the same reason.

**A6 — a percent-encoded request path is refused.** The router matches on `RawPath` and hands back still-escaped
parameters, while attributes are built from the decoded path; a `%2F` inside one segment therefore expands into extra
segments for the authorizer while staying one segment for the router, and the permission checked and the object served
come from different namespaces. `AllowEncodedPath()` exists for a surface that authorizes no paths.

### What this is not

Not an authorizer and not a policy engine: `authz` defines the question and the shape of an answer, and a component
brings what decides. Not a credential library either — `authn/bearer` reads the header and hands the token to a
`Verifier`, and what mints or validates one lives with whoever issues it.

## Layout

| Package                | Purpose                                                                      |
|------------------------|------------------------------------------------------------------------------|
| `apiserver`            | the router, its options, the not-found handler and `ServeHTTP`               |
| `apiserver/middleware` | recovery, the access log, authentication and authorization, as a chain       |
| `apiserver/authn`      | the identity, the authenticator interfaces and the chain that asks them      |
| `authn/clientcert`     | a caller proven by the client certificate the TLS handshake verified         |
| `authn/bearer`         | a token in a header, checked by a verifier; a fixed table for service tokens |
| `authn/basic`          | a user name and a password, with the challenge that asks for one             |
| `authn/frontproxy`     | the caller a verified proxy asserts in `X-Remote-*` headers                  |
| `authn/anonymous`      | a name for the caller who presented nothing, so a rule can be written        |
| `apiserver/authz`      | the attributes a decision is made about, the authorizer, the union of them   |
| `apiserver/metrics`    | request count, latency, in-flight and body bytes, and the exposition handler |
| `apiserver/errors`     | an error that knows its status, and the writer that renders one              |
| `errors/k8s`           | the same, rendered as a Kubernetes `Status` — the only apimachinery import   |

## Build and test

```shell
cd apiserver && go test ./... -race
```

A component wires it in one call:

```go
reg := prometheus.NewRegistry()

srv := apiserver.Router(
apiserver.WithLogger(&logger),
apiserver.WithErrorWriter(k8s.Writer),
apiserver.WithAuthenticator(authn.Chain{clientcert.Authenticator{}, bearerAuth}),
apiserver.WithAuthorizer(rbac),
apiserver.WithMetrics(metrics.New(reg, metrics.Options{Namespace: "horchestra", Subsystem: "apiserver"})),
)

srv.WithGroup("/apis/horchestra.io/v1", func (g *apiserver.Group) {
    g.WithGroup("/namespaces/:namespace", func (ns *apiserver.Group) {
      ns.GET("/applications", list)
  })
})

srv.GET("/metrics", metrics.Handler(reg))
```

## When a request is refused

Every refusal leaves one WARN line — `request refused` — with the status, the verb, the path, the remote address, the
caller when one was resolved, and the authenticator's or authorizer's own sentence as the reason. It is written where
the decision is made, because a middleware wrapped around the one that refused holds the request as it was before the
identity was attached and would report every refusal as anonymous.

It is a log line and not an audit record: no id, no closed vocabulary, nothing a collector's rule keys on. A component
with an audit trail writes that trail beside it, as its own middleware.

The access log writes the ordinary traffic at DEBUG and lifts only what an operator would look for: a refusal or a bad
request at WARN, a server-side failure at ERROR.

## What it measures

Four series, all labelled by method and by the route TEMPLATE (A5), and none of them collected unless a component passed
`WithMetrics`:

| Series                           | Type      | What it answers                                           |
|----------------------------------|-----------|-----------------------------------------------------------|
| `http_requests_total`            | counter   | traffic and the refusal rate, by status                   |
| `http_request_duration_seconds`  | histogram | latency, aggregatable across replicas                     |
| `http_requests_in_flight`        | gauge     | whether requests are piling up; watches and streams count |
| `http_response_size_bytes_total` | counter   | what the server actually wrote                            |

`Namespace` and `Subsystem` prefix them the Prometheus way; both empty gives the bare `http_` names, which is what a
single-server binary wants.

The measurement sits OUTSIDE authentication, so a refusal is counted with the status it was refused with — a server
whose 401s were invisible reports perfect health while nobody can reach it. The exposition (`metrics.Handler`) is bound
as an ordinary route and goes through the whole chain, so a scraper is a caller with a credential rather than a hole
carved out of the server.
