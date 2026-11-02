package clientcert

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

func cert(cn string, orgs ...string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn, Organization: orgs}}
}

func request(state *tls.ConnectionState) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/apis", nil)
	r.TLS = state
	return r
}

// TestVerifiedCertificateIsTheIdentity: the common name is the caller and the organization values
// are the groups a rule binds.
func TestVerifiedCertificateIsTheIdentity(t *testing.T) {
	state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert("node-1", "system:nodes")}}}

	id, err := Authenticator{}.Authenticate(request(state))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Name != "node-1" || !id.InGroup("system:nodes") {
		t.Fatalf("identity = %+v", id)
	}
}

// TestAnUnverifiedCertificateIsNobody is the property this package exists to hold. PeerCertificates
// holds whatever the peer sent, verified or not; reading it would turn "present any certificate"
// into "be anyone", so only the chain the TLS stack verified against the listener's pool counts.
func TestAnUnverifiedCertificateIsNobody(t *testing.T) {
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert("system:masters-please", "system:masters")}}

	id, err := Authenticator{}.Authenticate(request(state))
	if id != nil {
		t.Fatalf("an unverified certificate was admitted as %q", id.Name)
	}
	if !errors.Is(err, authn.ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
}

// TestNoTLSIsNoCredentials: a plaintext request carries nothing this authenticator reads, so the
// chain moves on rather than refusing on its behalf.
func TestNoTLSIsNoCredentials(t *testing.T) {
	if _, err := (Authenticator{}).Authenticate(request(nil)); !errors.Is(err, authn.ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
}
