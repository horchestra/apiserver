package bearer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/horchestra/apiserver/authn"
)

func get(header, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/catalog/services", nil)
	if len(header) > 0 {
		r.Header.Set(header, value)
	}
	return r
}

// TestNoTokenIsNotARefusal: a request carrying no token is not this authenticator's, so the chain
// must be free to try the next one — a caller admitted by certificate never sends a token.
func TestNoTokenIsNotARefusal(t *testing.T) {
	a := Authenticator{Verifier: NewStatic(map[string]authn.Identity{"secret": {Name: "scraper"}})}

	if _, err := a.Authenticate(get("", "")); !errors.Is(err, authn.ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
}

// TestStaticTableAdmitsItsOwnTokenAndRefusesAnother.
func TestStaticTableAdmitsItsOwnTokenAndRefusesAnother(t *testing.T) {
	a := Authenticator{Verifier: NewStatic(map[string]authn.Identity{
		"secret": {Name: "scraper", Groups: []string{"system:monitoring"}},
	})}

	id, err := a.Authenticate(get("Authorization", "Bearer secret"))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Name != "scraper" || !id.InGroup("system:monitoring") {
		t.Fatalf("identity = %+v", id)
	}

	if _, err := a.Authenticate(get("Authorization", "Bearer guess")); !errors.Is(err, authn.ErrUnauthenticated) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// TestASecondHeaderCarriesTheSameSecret: a client that cannot be told where to put its credential
// — a Consul client sends X-Consul-Token and offers no other way — is admitted by naming its
// header, and it is the same table checked the same way.
func TestASecondHeaderCarriesTheSameSecret(t *testing.T) {
	a := Authenticator{
		Verifier: NewStatic(map[string]authn.Identity{"secret": {Name: "traefik"}}),
		Headers:  []string{"X-Consul-Token"},
	}

	id, err := a.Authenticate(get("X-Consul-Token", "secret"))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Name != "traefik" {
		t.Fatalf("identity = %+v", id)
	}
}

// A static token's identity is the whole identity it was configured with, Extra included.
func TestStaticKeepsExtra(t *testing.T) {
	s := NewStatic(map[string]authn.Identity{"t": {Name: "svc", Extra: map[string][]string{"scope": {"metrics"}}}})
	id, err := s.VerifyToken(context.Background(), "t")
	if err != nil || id.First("scope") != "metrics" {
		t.Fatalf("identity = %+v, %v; Extra was dropped", id, err)
	}
}

// TestStaticHandsOutACopy: the table outlives the request, so what one caller's identity is turned
// into must not reach the next caller with the same token.
func TestStaticHandsOutACopy(t *testing.T) {
	s := NewStatic(map[string]authn.Identity{"t": {
		Name: "svc", Groups: []string{"readers"}, Extra: map[string][]string{"scope": {"metrics"}},
	}})
	id, err := s.VerifyToken(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	id.Groups[0] = "admins"
	id.Extra["scope"][0] = "everything"
	again, err := s.VerifyToken(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if again.Groups[0] != "readers" || again.First("scope") != "metrics" {
		t.Fatalf("the table changed: %+v", again)
	}
}
