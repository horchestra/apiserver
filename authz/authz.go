// Package authz is what the caller may do: the attributes a decision is made about, the Authorizer
// that decides, and the union of several.
//
// It stores no rules and knows no policy engine. A component brings its own — RBAC over stored
// objects, a fixed grant a node agent holds, a policy file — and this package is what those agree
// on, so that a middleware, an access review endpoint and a handler that authorizes a second time
// all ask the same question in the same words.
package authz

import (
	"context"

	"github.com/horchestra/apiserver/authn"
)

// Decision is what an authorizer answers.
//
// NoOpinion is a third answer and not a polite no: it is what lets several authorizers stand in a
// union, each answering for the requests it knows about and leaving the rest to the next. Nothing
// is granted by NoOpinion — a union that ends with one refuses.
type Decision int

const (
	NoOpinion Decision = iota
	Allow
	Deny
)

// Attributes are the request, as a rule sees it.
type Attributes struct {
	User      *authn.Identity
	Verb      string
	Group     string
	Resource  string
	Namespace string
	Name      string
	// Subresource is the segment after the object's name — "status", "log". It is a SEPARATE
	// permission from the object it hangs off, because it is a different thing: a node's journal
	// is not its capacity, and the right to read one says nothing about the right to read the
	// other. Rules name it as "resource/subresource".
	Subresource string
	// ResourceRequest distinguishes a request for an object from one for a path — discovery, a
	// schema document, a health probe. A false one is not a free pass; it is a different kind of
	// rule, written about Path.
	ResourceRequest bool
	// Path is the request path, which is all a non-resource decision has to go on.
	Path string
}

// Target is what a rule names: the resource, or "resource/subresource" for a request that has
// one. Comparing against this is what keeps a grant of "nodes" from silently carrying "nodes/log".
func (a Attributes) Target() string {
	if len(a.Subresource) == 0 {
		return a.Resource
	}
	return a.Resource + "/" + a.Subresource
}

type Authorizer interface {
	Authorize(ctx context.Context, a Attributes) (Decision, error)
}

// Func adapts a function to Authorizer.
type Func func(ctx context.Context, a Attributes) (Decision, error)

func (f Func) Authorize(ctx context.Context, a Attributes) (Decision, error) { return f(ctx, a) }

// Union asks its members in order and takes the first one that has an opinion. An error stops it:
// an authorizer that could not reach what it needed has not decided anything, and continuing past
// it would let a store outage widen into an unnoticed grant.
type Union []Authorizer

var _ Authorizer = Union(nil)

func (u Union) Authorize(ctx context.Context, a Attributes) (Decision, error) {
	for _, az := range u {
		d, err := az.Authorize(ctx, a)
		if err != nil {
			return NoOpinion, err
		}
		if d != NoOpinion {
			return d, nil
		}
	}
	return NoOpinion, nil
}

// AllowAll is the authorizer a component uses when it has decided authentication alone is the
// gate. It is written out rather than left as a nil Authorizer, so that "everyone may do
// everything here" is a line somebody wrote and a reviewer can find.
var AllowAll Authorizer = Func(func(context.Context, Attributes) (Decision, error) {
	return Allow, nil
})

// DenyAll refuses everything, which is what an unconfigured server should do.
var DenyAll Authorizer = Func(func(context.Context, Attributes) (Decision, error) {
	return Deny, nil
})
