// Package basic authenticates a caller by a user name and a password in the Authorization header,
// and challenges for one when the request carries none.
//
// It is the plainest scheme there is and it sends the password on every request, so it belongs
// behind TLS and nowhere else. What makes it worth having is the surfaces that have no client-go
// and no certificate machinery — a maintenance endpoint an operator reaches with curl — where the
// alternative was no authentication at all.
package basic

import (
	"context"
	"fmt"
	"net/http"

	"github.com/horchestra/apiserver/authn"
)

// Checker verifies a password and reports who the caller is. It is an interface because where the
// passwords live — a file, a directory, a store — is the component's decision and never this
// package's.
type Checker interface {
	CheckPassword(ctx context.Context, user, password string) (*authn.Identity, error)
}

// CheckerFunc adapts a function to Checker.
type CheckerFunc func(ctx context.Context, user, password string) (*authn.Identity, error)

func (f CheckerFunc) CheckPassword(ctx context.Context, user, password string) (*authn.Identity, error) {
	return f(ctx, user, password)
}

// Authenticator reads the credential and asks the Checker about it.
type Authenticator struct {
	Checker Checker
	// Realm is what the challenge names. Empty is fine: a browser then shows the host, which is
	// what an operator typed anyway.
	Realm string
}

var (
	_ authn.Authenticator = Authenticator{}
	_ authn.Challenger    = Authenticator{}
)

func (a Authenticator) Authenticate(r *http.Request) (*authn.Identity, error) {
	user, password, ok := r.BasicAuth()
	if !ok {
		return nil, authn.ErrNoCredentials
	}
	if a.Checker == nil {
		return nil, fmt.Errorf("%w: this server checks no passwords", authn.ErrUnauthenticated)
	}
	id, err := a.Checker.CheckPassword(r.Context(), user, password)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, fmt.Errorf("%w: user %q", authn.ErrUnauthenticated, user)
	}
	return id, nil
}

// Challenge asks the client for a password. It is stamped only when the whole chain found no
// credentials, so a caller already admitted by another scheme never sees it.
func (a Authenticator) Challenge(w http.ResponseWriter) {
	realm := a.Realm
	if len(realm) == 0 {
		realm = "restricted"
	}
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realm))
}
