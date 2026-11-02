package authn

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stub struct {
	id  *Identity
	err error
}

func (s stub) Authenticate(*http.Request) (*Identity, error) { return s.id, s.err }

type challenging struct {
	stub
	header string
}

func (c challenging) Challenge(w http.ResponseWriter) { w.Header().Add("WWW-Authenticate", c.header) }

func request() *http.Request { return httptest.NewRequest(http.MethodGet, "/apis", nil) }

// TestChainSkipsAuthenticatorsWithNoCredentials: ErrNoCredentials means "not my kind of
// credential", so the chain moves on and the caller is resolved by whichever member does read the
// one they sent.
func TestChainSkipsAuthenticatorsWithNoCredentials(t *testing.T) {
	chain := Chain{
		stub{err: ErrNoCredentials},
		stub{id: &Identity{Name: "alice", Groups: []string{"team-a"}}},
	}

	id, err := chain.Authenticate(request())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Name != "alice" || !id.InGroup("team-a") {
		t.Fatalf("identity = %+v", id)
	}
}

// TestChainStopsAtARejectedCredential is the property the whole three-answer split exists for. A
// token that was presented and refused must NOT fall through to whatever stands behind it — with
// an anonymous authenticator last, falling through admits the caller as anonymous and answers 200
// to somebody holding a revoked token.
func TestChainStopsAtARejectedCredential(t *testing.T) {
	refused := fmt.Errorf("%w: unknown bearer token", ErrUnauthenticated)
	chain := Chain{
		stub{err: refused},
		stub{id: &Identity{Name: "system:anonymous"}},
	}

	id, err := chain.Authenticate(request())
	if id != nil {
		t.Fatalf("a refused credential was admitted as %q", id.Name)
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want the refusal itself", err)
	}
}

// TestChallengeOnlyWhenNobodyHadCredentials: every member that can challenge does so on the way to
// a 401, and none of them does when a member ahead of it resolved the caller.
func TestChallengeOnlyWhenNobodyHadCredentials(t *testing.T) {
	chain := Chain{
		challenging{stub: stub{err: ErrNoCredentials}, header: `Basic realm="one"`},
		challenging{stub: stub{err: ErrNoCredentials}, header: "Negotiate"},
	}

	rec := httptest.NewRecorder()
	if _, err := chain.AuthenticateHTTP(rec, request()); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
	if got := rec.Header().Values("WWW-Authenticate"); len(got) != 2 {
		t.Fatalf("challenges = %v, want both", got)
	}

	rec = httptest.NewRecorder()
	admitted := Chain{stub{id: &Identity{Name: "node-1"}}, chain[0]}
	if _, err := admitted.AuthenticateHTTP(rec, request()); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got := rec.Header().Values("WWW-Authenticate"); len(got) != 0 {
		t.Fatalf("an admitted caller was challenged: %v", got)
	}
}

// TestIdentityRoundTripsThroughTheContext: everything past the middleware reads the caller from
// the context, and a request that never passed through one names nobody.
func TestIdentityRoundTripsThroughTheContext(t *testing.T) {
	ctx := WithIdentity(t.Context(), &Identity{Name: "alice"})
	if id := FromContext(ctx); id == nil || id.Name != "alice" {
		t.Fatalf("identity = %+v", id)
	}
	if id := FromContext(t.Context()); id != nil {
		t.Fatalf("an unauthenticated context named %q", id.Name)
	}
}
