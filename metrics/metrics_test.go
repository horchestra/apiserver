package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/errors"
)

// server is a router with the measurement wired the way apiserver.WithMetrics wires it, plus the
// two routes the tests need.
func server(t *testing.T) (*bunrouter.Router, *Requests, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := New(reg, Options{})
	router := bunrouter.New(bunrouter.Use(m.Middleware()))
	router.GET("/apis/v1/applications/:name", func(w http.ResponseWriter, req bunrouter.Request) error {
		_, _ = w.Write([]byte("body"))
		return nil
	})
	router.GET("/apis/v1/refused", func(http.ResponseWriter, bunrouter.Request) error {
		return errors.Forbidden("no rule grants get on applications")
	})
	return router, m, reg
}

func get(t *testing.T, router *bunrouter.Router, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := router.ServeHTTPError(rec, httptest.NewRequest(http.MethodGet, path, nil)); err != nil {
		rec.Code = errors.StatusOf(err)
	}
	return rec
}

// TestRouteLabelIsTheTemplateAndNotThePath is what keeps this endpoint from growing without bound:
// the path carries object names, so labelling by it would open one series per application in the
// fleet — and per mistyped name anyone cares to send.
func TestRouteLabelIsTheTemplateAndNotThePath(t *testing.T) {
	router, m, _ := server(t)

	get(t, router, "/apis/v1/applications/web")
	get(t, router, "/apis/v1/applications/api")

	counted := testutil.ToFloat64(m.total.WithLabelValues(http.MethodGet, "/apis/v1/applications/:name", "200"))
	if counted != 2 {
		t.Fatalf("requests on the template = %v, want 2", counted)
	}
	if series := testutil.CollectAndCount(m.total); series != 1 {
		t.Fatalf("series = %d, want 1 — the path reached a label", series)
	}
}

// TestRefusalIsCountedWithItsStatus: a refusal is RETURNED up the chain and never written, so a
// measurement that only watched the ResponseWriter would report every 403 in the fleet as a 200.
func TestRefusalIsCountedWithItsStatus(t *testing.T) {
	router, m, _ := server(t)

	get(t, router, "/apis/v1/refused")

	if counted := testutil.ToFloat64(m.total.WithLabelValues(http.MethodGet, "/apis/v1/refused", "403")); counted != 1 {
		t.Fatalf("refusals counted = %v, want 1", counted)
	}
}

// TestUnroutedRequestsShareOneLabel: a path nothing serves is whatever a scanner typed, so it is
// counted under a fixed label. Otherwise reaching the socket is enough to grow the server's memory
// one series at a time.
func TestUnroutedRequestsShareOneLabel(t *testing.T) {
	router, m, _ := server(t)

	get(t, router, "/nothing/here")
	get(t, router, "/nothing/there")

	if counted := testutil.ToFloat64(m.total.WithLabelValues(http.MethodGet, unrouted, "404")); counted != 2 {
		t.Fatalf("unrouted requests = %v, want 2", counted)
	}
}

// TestInFlightReturnsToZero: the gauge is what an operator reads to see whether requests are
// piling up, so a path that forgot to decrement would show a server that is busy forever.
func TestInFlightReturnsToZero(t *testing.T) {
	router, m, _ := server(t)

	get(t, router, "/apis/v1/applications/web")
	get(t, router, "/apis/v1/refused")

	if flight := testutil.ToFloat64(m.inFlight); flight != 0 {
		t.Fatalf("in flight = %v, want 0", flight)
	}
}

// TestBodyBytesAreCounted: what the handler actually wrote, not what it meant to.
func TestBodyBytesAreCounted(t *testing.T) {
	router, m, _ := server(t)

	get(t, router, "/apis/v1/applications/web")

	if written := testutil.ToFloat64(m.written.WithLabelValues(http.MethodGet, "/apis/v1/applications/:name")); written != 4 {
		t.Fatalf("bytes = %v, want 4", written)
	}
}

// TestHandlerServesTheExposition: the endpoint is an ordinary route, and what comes out of it is
// the registry the component owns — not a package-level one two servers in a process would share.
func TestHandlerServesTheExposition(t *testing.T) {
	router, _, reg := server(t)
	router.GET("/metrics", Handler(reg))

	get(t, router, "/apis/v1/applications/web")
	rec := get(t, router, "/metrics")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE http_requests_total counter",
		"# TYPE http_request_duration_seconds histogram",
		"http_requests_in_flight",
		`route="/apis/v1/applications/:name"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the exposition does not carry %s:\n%s", want, body)
		}
	}
}

// TestNamespacedNames: a component reporting into a shared registry prefixes its series the
// Prometheus way, and the bare http_ names are what a single-server binary gets.
func TestNamespacedNames(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg, Options{Namespace: "horchestra", Subsystem: "apiserver"})

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var names []string
	for _, f := range families {
		names = append(names, f.GetName())
	}
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "horchestra_apiserver_http_requests_in_flight") {
		t.Fatalf("names = %s", joined)
	}
}
