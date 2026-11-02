// Package frontproxy admits the caller a trusted proxy asserts in headers — the shape a Kubernetes
// aggregator, an ingress that terminates single sign-on, or any other front door speaks.
//
// The trust is in two layers and BOTH are needed. TLS verifies the proxy: the listener this runs
// on requires a client certificate from the authority that signs the proxy's, and this checks the
// name on it against the names the deployment admits. Only then are the headers believed. A server
// that reads X-Remote-User off any connection has published an unauthenticated impersonation
// header, and the difference between the two is one `if`.
//
// Run it on a listener of its own. The authority that signs the proxy's certificate must not be in
// the pool that admits anything else, or a certificate issued for another purpose becomes a
// licence to assert any caller at all.
package frontproxy

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/horchestra/apiserver/authn"
)

// The headers a proxy asserts a caller in, when a deployment configured none of its own.
const (
	DefaultUserHeader  = "X-Remote-User"
	DefaultGroupHeader = "X-Remote-Group"
)

// Authenticator reads the asserted caller off a connection it has verified belongs to the proxy.
type Authenticator struct {
	// AllowedNames are the common names the proxy's certificate may carry. Empty means any
	// certificate the listener's authority signed, which is safe only where that authority signs
	// nothing else — a deployment that can pin the name should.
	AllowedNames []string
	// UserHeader and GroupHeaders are where the caller is asserted, as the PROXY spells them.
	// Empty falls back to the defaults above.
	UserHeader   string
	GroupHeaders []string
	// Prefix is stamped on the asserted name and on every asserted group, and it is a security
	// control rather than decoration: the proxy forwards the groups it was given verbatim, and a
	// group name this server compares as a literal — the admin group, the node group — would
	// otherwise be spellable from outside by whoever can reach the proxy. Prefixed, an asserted
	// caller can be granted rights but can never be mistaken for a local one.
	Prefix string
}

var _ authn.Authenticator = Authenticator{}

func (a Authenticator) Authenticate(r *http.Request) (*authn.Identity, error) {
	name, err := a.proxyName(r.TLS)
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(r.Header.Get(cmp.Or(a.UserHeader, DefaultUserHeader)))
	if len(user) == 0 {
		return nil, fmt.Errorf("%w: the proxy (%s) asserted no user", authn.ErrUnauthenticated, name)
	}
	id := &authn.Identity{Name: a.Prefix + user}
	headers := a.GroupHeaders
	if len(headers) == 0 {
		headers = []string{DefaultGroupHeader}
	}
	for _, h := range headers {
		for _, g := range r.Header.Values(h) {
			if g = strings.TrimSpace(g); len(g) > 0 {
				id.Groups = append(id.Groups, a.Prefix+g)
			}
		}
	}
	return id, nil
}

// proxyName is the verified common name of the proxy's own certificate. A connection that carries
// none is not this authenticator's — the headers on it mean nothing and the chain moves on.
func (a Authenticator) proxyName(cs *tls.ConnectionState) (string, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", authn.ErrNoCredentials
	}
	cn := cs.VerifiedChains[0][0].Subject.CommonName
	if len(a.AllowedNames) > 0 && !slices.Contains(a.AllowedNames, cn) {
		return "", fmt.Errorf("%w: %q is not a proxy name this server admits", authn.ErrUnauthenticated, cn)
	}
	return cn, nil
}
