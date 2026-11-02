// Package authn is who the caller is: the identity every layer above reads, the interface an
// authenticator satisfies, and the Chain that asks several of them in an order somebody chose.
//
// It holds NO credential logic. Each kind of credential — a client certificate, a bearer token,
// headers asserted by a trusted proxy — is a package beside this one, so a component links the
// kinds it actually admits and a new kind is a new package rather than a new branch in a function
// every component shares.
package authn

import (
	"errors"
	"maps"
	"net/http"
	"slices"
)

// Identity is the caller, as every layer above this one sees them: a name that appears in a log
// line and an audit record, and the groups a rule may be written about.
type Identity struct {
	Name   string
	Groups []string
	// Extra is what the authenticator knows about the caller beyond a name and groups, under keys
	// that authenticator owns. It exists for the facts a rule is NOT written about and something
	// further in still needs: the name a rule matches is often a reduction — a realm stripped, a
	// certificate's subject shortened — and an audit line, or a service acting in the caller's
	// name, needs what it was reduced from. Nothing in this module reads it.
	Extra map[string][]string
}

// Clone is a copy that shares nothing with the identity, for an authenticator that hands out one it
// keeps: a caller who appends to a group must not change who the next request is.
func (id *Identity) Clone() *Identity {
	if id == nil {
		return nil
	}
	out := &Identity{Name: id.Name, Groups: slices.Clone(id.Groups), Extra: maps.Clone(id.Extra)}
	for k, v := range out.Extra {
		out.Extra[k] = slices.Clone(v)
	}
	return out
}

// First is the first value under key, or "" — for the keys that hold exactly one.
func (id *Identity) First(key string) string {
	if id == nil || len(id.Extra[key]) == 0 {
		return ""
	}
	return id.Extra[key][0]
}

// InGroup reports whether the identity carries the group. A nil identity is in no group, which is
// what lets a caller ask without first checking for one.
func (id *Identity) InGroup(group string) bool {
	return id != nil && slices.Contains(id.Groups, group)
}

// Authenticator resolves the caller of a request, or reports that it cannot.
//
// The three answers are distinct and the difference decides what a Chain does next:
//
//   - an identity and no error: this caller is authenticated, and no later authenticator runs;
//   - ErrNoCredentials: the request carries nothing THIS authenticator understands, so the chain
//     moves on;
//   - any other error: a credential was presented and refused, and the chain stops there.
//
// The last one is the one worth keeping: a bad token that fell through to an anonymous
// authenticator would answer 200 to a caller who believed they were authenticated, and grant
// whatever anonymous may do.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

// ResponseAuthenticator is an authenticator that must also drive the response — a scheme that
// negotiates, challenging on one request and confirming on the next, cannot work through the
// narrow interface, which has no ResponseWriter. The Chain prefers this form when an
// authenticator implements it.
type ResponseAuthenticator interface {
	Authenticator
	AuthenticateHTTP(w http.ResponseWriter, r *http.Request) (*Identity, error)
}

// Challenger stamps its "authenticate like this" header when the whole chain found no credentials
// at all. It runs only on the way to a 401, so a caller admitted by certificate is never told to
// present a password.
type Challenger interface {
	Challenge(w http.ResponseWriter)
}

// Func adapts a function to Authenticator.
type Func func(r *http.Request) (*Identity, error)

func (f Func) Authenticate(r *http.Request) (*Identity, error) { return f(r) }

var (
	// ErrNoCredentials means the request carried nothing this authenticator reads. It is not a
	// refusal: the chain continues, and only an exhausted chain turns it into a 401.
	ErrNoCredentials = errors.New("no credentials")
	// ErrUnauthenticated is a credential that was presented and rejected.
	ErrUnauthenticated = errors.New("invalid credentials")
)

// Chain asks its authenticators in order and takes the first identity one of them resolves.
// Groups are never merged across members: a caller is admitted by ONE credential and carries what
// that credential said, or a certificate's organization would quietly extend a token's rights.
//
// The order is the caller's to choose and it is a security decision, not a preference. Put the
// strongest credential first (a verified client certificate), the negotiating schemes next, and
// anonymous — if the component admits one at all — last.
type Chain []Authenticator

var (
	_ ResponseAuthenticator = Chain(nil)
	_ Challenger            = Chain(nil)
)

// Authenticate is the response-less path, for callers that hold no ResponseWriter (a gRPC
// interceptor, a test). An authenticator that needs one can still validate a credential that is
// present; it just cannot challenge for one.
func (c Chain) Authenticate(r *http.Request) (*Identity, error) {
	return c.AuthenticateHTTP(headerOnly{h: make(http.Header)}, r)
}

func (c Chain) AuthenticateHTTP(w http.ResponseWriter, r *http.Request) (*Identity, error) {
	for _, a := range c {
		id, err := authenticate(w, a, r)
		switch {
		case err == nil && id != nil:
			return id, nil
		case err == nil, errors.Is(err, ErrNoCredentials):
			continue
		default:
			return nil, err
		}
	}
	c.Challenge(w)
	return nil, ErrNoCredentials
}

// Challenge offers every member that can challenge the chance to say how to authenticate. All of
// them, not the first: a component that admits both a password and a negotiated scheme has to
// advertise both, or a client will only ever try the one that happened to be registered first.
func (c Chain) Challenge(w http.ResponseWriter) {
	for _, a := range c {
		if ch, ok := a.(Challenger); ok {
			ch.Challenge(w)
		}
	}
}

func authenticate(w http.ResponseWriter, a Authenticator, r *http.Request) (*Identity, error) {
	if ra, ok := a.(ResponseAuthenticator); ok {
		return ra.AuthenticateHTTP(w, r)
	}
	return a.Authenticate(r)
}

// headerOnly carries the headers an authenticator may set while discarding the body, so the
// response-less path cannot panic on a nil writer.
type headerOnly struct{ h http.Header }

func (x headerOnly) Header() http.Header       { return x.h }
func (headerOnly) Write(b []byte) (int, error) { return len(b), nil }
func (headerOnly) WriteHeader(int)             {}
