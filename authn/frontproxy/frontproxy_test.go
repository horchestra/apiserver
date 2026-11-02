package frontproxy

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/horchestra/apiserver/authn"
)

func proxied(cn, user string, groups ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/apis", nil)
	if len(cn) > 0 {
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{
			{Subject: pkix.Name{CommonName: cn}},
		}}}
	}
	if len(user) > 0 {
		r.Header.Set(DefaultUserHeader, user)
	}
	for _, g := range groups {
		r.Header.Add(DefaultGroupHeader, g)
	}
	return r
}

// TestAssertedCallerIsPrefixed: the proxy forwards groups verbatim, and a group this server
// compares as a literal — the admin group, the node group — must not be spellable from outside.
// Prefixed, an asserted caller can be granted rights but can never be mistaken for a local one.
func TestAssertedCallerIsPrefixed(t *testing.T) {
	a := Authenticator{AllowedNames: []string{"front-proxy"}, Prefix: "cluster:"}

	id, err := a.Authenticate(proxied("front-proxy", "alice", "system:masters"))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Name != "cluster:alice" {
		t.Fatalf("name = %q, want cluster:alice", id.Name)
	}
	if id.InGroup("system:masters") {
		t.Fatalf("an asserted group reached the server unprefixed: %v", id.Groups)
	}
	if !id.InGroup("cluster:system:masters") {
		t.Fatalf("groups = %v", id.Groups)
	}
}

// TestHeadersMeanNothingWithoutTheProxysCertificate: reading X-Remote-User off any connection
// publishes an unauthenticated impersonation header. Without a verified chain there is no proxy,
// so there is no assertion to believe.
func TestHeadersMeanNothingWithoutTheProxysCertificate(t *testing.T) {
	id, err := Authenticator{}.Authenticate(proxied("", "alice", "system:masters"))
	if id != nil {
		t.Fatalf("an unauthenticated assertion was admitted as %q", id.Name)
	}
	if !errors.Is(err, authn.ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
}

// TestAProxyNameThisServerDoesNotAdmitIsRefused: the certificate is valid and the assertion is
// well-formed, and it is still not a proxy this deployment pinned.
func TestAProxyNameThisServerDoesNotAdmitIsRefused(t *testing.T) {
	a := Authenticator{AllowedNames: []string{"front-proxy"}}

	if _, err := a.Authenticate(proxied("somebody-else", "alice")); !errors.Is(err, authn.ErrUnauthenticated) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}
