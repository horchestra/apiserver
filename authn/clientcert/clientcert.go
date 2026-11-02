// Package clientcert authenticates a caller by the client certificate the TLS handshake already
// verified: the common name is the caller, the organization values are their groups.
//
// It reads VerifiedChains and never PeerCertificates. The second holds whatever the peer sent,
// verified or not, so trusting it would turn "present any certificate" into "be anyone" — the
// chain is verified by the TLS stack against the pool the listener was configured with, and that
// configuration is the whole of the trust decision.
package clientcert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"net/http"

	"github.com/horchestra/apiserver/authn"
)

// Authenticator maps a verified certificate to an identity.
type Authenticator struct {
	// Map, when set, replaces the default CN → name, O → groups reading. A deployment whose
	// certificates carry the caller in a SAN or in an extension names it here rather than
	// forking this package.
	Map func(*x509.Certificate) (*authn.Identity, error)
}

var _ authn.Authenticator = Authenticator{}

func (a Authenticator) Authenticate(r *http.Request) (*authn.Identity, error) {
	leaf := verifiedLeaf(r.TLS)
	if leaf == nil {
		return nil, authn.ErrNoCredentials
	}
	if a.Map != nil {
		return a.Map(leaf)
	}
	if len(leaf.Subject.CommonName) == 0 {
		return nil, fmt.Errorf("%w: the client certificate carries no common name", authn.ErrUnauthenticated)
	}
	return &authn.Identity{Name: leaf.Subject.CommonName, Groups: leaf.Subject.Organization}, nil
}

func verifiedLeaf(cs *tls.ConnectionState) *x509.Certificate {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return nil
	}
	return cs.VerifiedChains[0][0]
}
