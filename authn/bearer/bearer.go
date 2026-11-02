// Package bearer authenticates a caller by a token they present in a header.
//
// It is the TRANSPORT and not the check: which header a token may arrive in, and what to do when
// none does. What a token means is a Verifier — a fixed table for the handful of service
// credentials a component is configured with, or a signature check against whatever mints them.
// Splitting the two is what lets one component admit a static token and another an issued one
// without either reimplementing the header parsing that has to be identical in both.
package bearer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/horchestra/apiserver/authn"
)

// Verifier checks a token and reports who holds it. Returning ErrUnauthenticated (or anything
// else) refuses the request outright: a token was presented, so falling through to a later
// authenticator would admit a caller who believes they are somebody else.
type Verifier interface {
	VerifyToken(ctx context.Context, token string) (*authn.Identity, error)
}

// VerifierFunc adapts a function to Verifier.
type VerifierFunc func(ctx context.Context, token string) (*authn.Identity, error)

func (f VerifierFunc) VerifyToken(ctx context.Context, token string) (*authn.Identity, error) {
	return f(ctx, token)
}

// Authenticator reads the token and hands it to the Verifier.
type Authenticator struct {
	Verifier Verifier
	// Headers are the headers a token may arrive in BESIDE `Authorization: Bearer`. A client
	// that cannot be told where to put its credential — a Consul client sends X-Consul-Token and
	// offers no other way — is admitted by naming its header here. It is the same secret checked
	// the same way, not a second authentication path.
	Headers []string
}

var _ authn.Authenticator = Authenticator{}

func (a Authenticator) Authenticate(r *http.Request) (*authn.Identity, error) {
	token := a.token(r)
	if len(token) == 0 {
		return nil, authn.ErrNoCredentials
	}
	if a.Verifier == nil {
		return nil, fmt.Errorf("%w: this server verifies no bearer tokens", authn.ErrUnauthenticated)
	}
	id, err := a.Verifier.VerifyToken(r.Context(), token)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, authn.ErrUnauthenticated
	}
	return id, nil
}

func (a Authenticator) token(r *http.Request) string {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(tok)
	}
	for _, h := range a.Headers {
		if tok := strings.TrimSpace(r.Header.Get(h)); len(tok) > 0 {
			return tok
		}
	}
	return ""
}

// Static is a fixed token table: the credentials a component is configured with at startup.
//
// It keeps the DIGEST of each token rather than the token, and compares in constant time. The map
// it is built from is the only place the secrets themselves live, so a heap dump of a running
// server no longer hands over credentials that are still valid, and a lookup no longer leaks by
// how long it took.
type Static struct {
	byDigest map[[sha256.Size]byte]authn.Identity
}

var _ Verifier = (*Static)(nil)

// NewStatic builds the table from token → identity.
func NewStatic(tokens map[string]authn.Identity) *Static {
	s := &Static{byDigest: make(map[[sha256.Size]byte]authn.Identity, len(tokens))}
	for tok, id := range tokens {
		s.byDigest[sha256.Sum256([]byte(tok))] = id
	}
	return s
}

func (s *Static) VerifyToken(_ context.Context, token string) (*authn.Identity, error) {
	want := sha256.Sum256([]byte(token))
	for digest, id := range s.byDigest {
		if subtle.ConstantTimeCompare(digest[:], want[:]) == 1 {
			return id.Clone(), nil
		}
	}
	return nil, fmt.Errorf("%w: unknown bearer token", authn.ErrUnauthenticated)
}
