// Package metrics measures what a server does with the requests it serves: how many, how long,
// how many are in flight and how much came back.
//
// It is Prometheus' own client, not a hand-written exposition: a histogram that a scraper can
// aggregate across replicas has to be a real histogram, and promhttp already answers the
// negotiation, the compression and the escaping that an endpoint written by hand gets wrong once
// and then serves wrongly forever.
//
// Nothing is measured unless a component asks for it (apiserver.WithMetrics), and the collectors
// go into the registry that component owns — a package-level registry would put two servers in one
// process into the same series.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/errors"
	"github.com/horchestra/apiserver/internal/respond"
)

// unrouted is the route label for a request that matched none. It is a fixed string rather than
// the path, because a path nothing serves is whatever a scanner typed — labelling by it hands
// anyone who can reach the socket the power to grow this server's memory one series at a time.
const unrouted = "<unrouted>"

// Options are what a component decides about its own series.
type Options struct {
	// Namespace and Subsystem prefix every metric, the Prometheus way: a Namespace of
	// "horchestra" and a Subsystem of "apiserver" give horchestra_apiserver_requests_total.
	// Both empty give the bare http_ names, which is what a single-server binary wants.
	Namespace string
	Subsystem string
	// Buckets are the latency buckets in seconds. Empty is prometheus.DefBuckets, which spans
	// 5ms to 10s — the range an API request lives in.
	Buckets []float64
	// ConstLabels are stamped on every series: the component's name when several report into one
	// registry, and nothing that varies per request.
	ConstLabels prometheus.Labels
}

// Requests is the collectors, registered.
type Requests struct {
	total    *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
	written  *prometheus.CounterVec
}

// New registers the collectors in reg (prometheus.DefaultRegisterer when nil) and returns them. It
// panics on a duplicate registration, as prometheus.MustRegister does: two servers reporting into
// one registry under one name is a misconfiguration that would otherwise show up as a metric that
// silently means two things.
func New(reg prometheus.Registerer, opts Options) *Requests {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	buckets := opts.Buckets
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}
	m := &Requests{
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: opts.Namespace, Subsystem: opts.Subsystem,
			Name:        "http_requests_total",
			Help:        "Requests served, by method, route and response status.",
			ConstLabels: opts.ConstLabels,
		}, []string{"method", "route", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: opts.Namespace, Subsystem: opts.Subsystem,
			Name:        "http_request_duration_seconds",
			Help:        "Time from the first middleware to the handler's return, in seconds.",
			Buckets:     buckets,
			ConstLabels: opts.ConstLabels,
		}, []string{"method", "route", "status"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: opts.Namespace, Subsystem: opts.Subsystem,
			Name:        "http_requests_in_flight",
			Help:        "Requests being served right now, watches and log streams included.",
			ConstLabels: opts.ConstLabels,
		}),
		written: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: opts.Namespace, Subsystem: opts.Subsystem,
			Name:        "http_response_size_bytes_total",
			Help:        "Body bytes written to clients, by method and route.",
			ConstLabels: opts.ConstLabels,
		}, []string{"method", "route"}),
	}
	reg.MustRegister(m.total, m.duration, m.inFlight, m.written)
	return m
}

// Middleware measures every request that passes through it.
//
// It belongs OUTSIDE authentication, so that the refusals count too: a server whose 401s were
// invisible reports perfect health while nobody can reach it. The status is taken the way the
// access log takes it — from the response when the handler wrote one, from the error it returned
// otherwise — because a refusal is returned up the chain and never written here.
func (m *Requests) Middleware() bunrouter.MiddlewareFunc {
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			started := time.Now()
			m.inFlight.Inc()
			defer m.inFlight.Dec()

			rec := respond.Wrap(w)
			err := next(rec, req)

			route := req.Route()
			if len(route) == 0 {
				route = unrouted
			}
			status := strconv.Itoa(statusOf(rec, err))
			m.total.WithLabelValues(req.Method, route, status).Inc()
			m.duration.WithLabelValues(req.Method, route, status).Observe(time.Since(started).Seconds())
			m.written.WithLabelValues(req.Method, route).Add(float64(rec.Written()))
			return err
		}
	}
}

func statusOf(rec *respond.Recorder, err error) int {
	if err != nil {
		return errors.StatusOf(err)
	}
	if code := rec.Status(); code != 0 {
		return code
	}
	return http.StatusOK
}

// Handler serves the exposition. It is a route like any other, so it goes through the same chain:
// a component that authorizes its API authorizes its metrics with it, and a scraper is a caller
// with a credential rather than an exception carved out of the server.
func Handler(gatherer prometheus.Gatherer) bunrouter.HandlerFunc {
	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}
	h := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{
		// The scrape says what went wrong and the server says it once; the alternative is a
		// scraper reading a 500 with no body and an operator with nothing to go on.
		ErrorHandling: promhttp.ContinueOnError,
	})
	return func(w http.ResponseWriter, req bunrouter.Request) error {
		h.ServeHTTP(w, req.Request)
		return nil
	}
}
