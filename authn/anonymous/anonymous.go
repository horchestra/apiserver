// Package anonymous admits a caller who presented nothing, as somebody: it is the last member of
// a chain, and it exists so that "unauthenticated" is a name an authorization rule can be written
// about rather than a hole below the authorizer.
//
// A component that adds it has decided that reaching its socket is enough to be let in as far as
// the authorizer's rules for this identity go. That is a real decision — leave it out and an
// unauthenticated request is refused at the door, which is the right default and why this is not
// wired anywhere by itself.
package anonymous

import (
	"net/http"

	"github.com/horchestra/apiserver/authn"
)

// The names an unauthenticated caller carries, spelled as Kubernetes spells them so one
// vocabulary covers both.
const (
	User  = "system:anonymous"
	Group = "system:unauthenticated"
)

// Authenticator answers with the same identity for every request.
type Authenticator struct {
	// Identity, when set, replaces the default system:anonymous / system:unauthenticated.
	Identity *authn.Identity
}

var _ authn.Authenticator = Authenticator{}

func (a Authenticator) Authenticate(*http.Request) (*authn.Identity, error) {
	if a.Identity != nil {
		return a.Identity.Clone(), nil
	}
	return &authn.Identity{Name: User, Groups: []string{Group}}, nil
}
