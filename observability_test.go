package apiserver

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/metrics"
)

// observed is a server with a logger and metrics, and a caller named by a header — what the
// product wiring is, so what is asserted is what an operator sees.
func observed(t *testing.T) (*Router, *bytes.Buffer, *prometheus.Registry) {
	t.Helper()
	var buf bytes.Buffer
	log := zerolog.New(&buf).Level(zerolog.DebugLevel)
	reg := prometheus.NewRegistry()
	r := New(WithLogger(&log), WithMetrics(metrics.New(reg, metrics.Options{})),
		WithAuthenticator(authn.Func(func(req *http.Request) (*authn.Identity, error) {
			switch who := req.Header.Get("X-Who"); who {
			case "":
				return nil, authn.ErrNoCredentials
			case "revoked":
				return nil, errors.New("revoked")
			default:
				return &authn.Identity{Name: who}, nil
			}
		})))
	r.GET("/v1/things", func(w http.ResponseWriter, _ Request) error { w.WriteHeader(http.StatusOK); return nil })
	return r, &buf, reg
}

func serve(r *Router, path, who string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if len(who) > 0 {
		req.Header.Set("X-Who", who)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// The access log names the caller authentication established further in.
func TestTheAccessLogNamesTheCaller(t *testing.T) {
	r, buf, _ := observed(t)
	serve(r, "/v1/things", "alice")
	if !strings.Contains(buf.String(), `"user":"alice"`) {
		t.Fatalf("the access line does not name the caller:\n%s", buf)
	}
}

func unroutedSeries(t *testing.T, reg *prometheus.Registry) int {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, mf := range mfs {
		if !strings.HasSuffix(mf.GetName(), "requests_total") {
			continue
		}
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if l.GetValue() == "<unrouted>" {
					n += int(m.GetCounter().GetValue())
				}
			}
		}
	}
	return n
}

// A request no route serves is still measured and logged — outside authorization, not outside
// everything — and a stranger's refusal there is a refusal in the log.
func TestUnroutedRequestsLeaveATrace(t *testing.T) {
	r, buf, reg := observed(t)
	if w := serve(r, "/nope", "alice"); w.Code != http.StatusNotFound {
		t.Fatalf("unrouted = %d", w.Code)
	}
	if w := serve(r, "/nope", "revoked"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unrouted with a refused credential = %d", w.Code)
	}
	if n := unroutedSeries(t, reg); n != 2 {
		t.Fatalf("<unrouted> counted %d requests, want 2", n)
	}
	log := buf.String()
	if !strings.Contains(log, `"path":"/nope","status":404`) || !strings.Contains(log, `"user":"alice"`) {
		t.Fatalf("the unrouted 404 left no access line naming its caller:\n%s", log)
	}
	if !strings.Contains(log, "request refused") {
		t.Fatalf("the unrouted 401 left no refusal line:\n%s", log)
	}

	buf.Reset()
	req := httptest.NewRequest(http.MethodGet, "/v1/a%2Fb", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(buf.String(), `"status":400`) {
		t.Fatalf("an encoded path = %d, log:\n%s", w.Code, buf.String())
	}
}

// A panic outside the chain is recovered, logged and answered, like one inside it.
func TestAPanicInTheNotFoundHandlerIsRecovered(t *testing.T) {
	var buf bytes.Buffer
	log := zerolog.New(&buf)
	r := New(WithLogger(&log), WithNotFound(func(http.ResponseWriter, Request) error { panic("boom") }))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(buf.String(), "recovered from a panic") {
		t.Fatalf("panic in not-found: %d, log:\n%s", w.Code, buf.String())
	}
}
