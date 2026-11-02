package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func attributesOf(t *testing.T, method, target string) Attributes {
	t.Helper()
	return REST(httptest.NewRequest(method, target, nil), nil)
}

// TestRESTReadsNamespacedPaths: the group, the namespace, the resource and the name each come out
// of the segment that holds them, and a read with no name is a list rather than a get.
func TestRESTReadsNamespacedPaths(t *testing.T) {
	at := attributesOf(t, http.MethodGet, "/apis/horchestra.io/v1/namespaces/team-a/applications/web")
	if at.Group != "horchestra.io" || at.Namespace != "team-a" || at.Resource != "applications" || at.Name != "web" {
		t.Fatalf("attributes = %+v", at)
	}
	if at.Verb != "get" || !at.ResourceRequest {
		t.Fatalf("verb = %q, resource request = %v", at.Verb, at.ResourceRequest)
	}
	if list := attributesOf(t, http.MethodGet, "/apis/horchestra.io/v1/applications"); list.Verb != "list" {
		t.Fatalf("verb = %q, want list", list.Verb)
	}
}

// TestSubresourceIsItsOwnTarget: the segment after the name is a separate permission. Dropping it
// makes every subresource inherit its parent's rule, so a grant to read a node's capacity would
// hand over the node's journal with it.
func TestSubresourceIsItsOwnTarget(t *testing.T) {
	at := attributesOf(t, http.MethodGet, "/apis/horchestra.io/v1/nodes/node-1/log")
	if at.Subresource != "log" {
		t.Fatalf("subresource = %q", at.Subresource)
	}
	if got := at.Target(); got != "nodes/log" {
		t.Fatalf("target = %q, want nodes/log", got)
	}
	if plain := attributesOf(t, http.MethodGet, "/apis/horchestra.io/v1/nodes/node-1"); plain.Target() != "nodes" {
		t.Fatalf("target = %q, want nodes", plain.Target())
	}
}

// TestWatchAndCollectionDeleteAreTheirOwnVerbs: streaming every change is not reading one object,
// and deleting a whole collection is not deleting one — a rule has to be able to grant one without
// the other.
func TestWatchAndCollectionDeleteAreTheirOwnVerbs(t *testing.T) {
	if at := attributesOf(t, http.MethodGet, "/apis/horchestra.io/v1/applications?watch=true"); at.Verb != "watch" {
		t.Fatalf("verb = %q, want watch", at.Verb)
	}
	if at := attributesOf(t, http.MethodDelete, "/apis/horchestra.io/v1/namespaces/team-a/applications"); at.Verb != "deletecollection" {
		t.Fatalf("verb = %q, want deletecollection", at.Verb)
	}
	if at := attributesOf(t, http.MethodDelete, "/apis/horchestra.io/v1/namespaces/team-a/applications/web"); at.Verb != "delete" {
		t.Fatalf("verb = %q, want delete", at.Verb)
	}
}

// TestNonResourcePathsCarryTheMethodAsTheirVerb: discovery, schemas and probes name no object, so
// the only rule that can reach them is one written about the path — and it needs a verb to
// compare.
func TestNonResourcePathsCarryTheMethodAsTheirVerb(t *testing.T) {
	at := attributesOf(t, http.MethodGet, "/openapi/v3")
	if at.ResourceRequest {
		t.Fatalf("attributes = %+v, want a non-resource request", at)
	}
	if at.Verb != "get" || at.Path != "/openapi/v3" {
		t.Fatalf("verb = %q, path = %q", at.Verb, at.Path)
	}
}

// TestUnionTakesTheFirstOpinion: NoOpinion is what lets several authorizers stand in a row, and a
// union that reaches the end of the row grants nothing.
func TestUnionTakesTheFirstOpinion(t *testing.T) {
	quiet := Func(func(context.Context, Attributes) (Decision, error) { return NoOpinion, nil })
	union := Union{
		quiet,
		Func(func(context.Context, Attributes) (Decision, error) { return Allow, nil }),
		Func(func(context.Context, Attributes) (Decision, error) { return Deny, nil }),
	}
	if d, err := union.Authorize(t.Context(), Attributes{}); err != nil || d != Allow {
		t.Fatalf("decision = %v, err = %v, want Allow", d, err)
	}
	if d, _ := (Union{quiet}).Authorize(t.Context(), Attributes{}); d != NoOpinion {
		t.Fatalf("decision = %v, want NoOpinion", d)
	}
}

// TestUnionStopsAtAnError: an authorizer that could not reach what it needed has decided nothing,
// and continuing past it would let a store outage read as a grant from whoever answers next.
func TestUnionStopsAtAnError(t *testing.T) {
	union := Union{
		Func(func(context.Context, Attributes) (Decision, error) {
			return NoOpinion, errors.New("the store is unreachable")
		}),
		AllowAll,
	}
	if d, err := union.Authorize(t.Context(), Attributes{}); err == nil || d == Allow {
		t.Fatalf("decision = %v, err = %v, want the error", d, err)
	}
}

// The watch parameter is read the way kube-apiserver reads it, and the verb follows: any value but
// false or 0 streams, so it must be authorized as the watch it is.
func TestWatchIsAnyValueButFalse(t *testing.T) {
	for q, want := range map[string]string{
		"watch=true": "watch", "watch=1": "watch", "watch=yes": "watch", "watch=": "watch", "watch=TRUE": "watch",
		"watch=false": "list", "watch=0": "list", "": "list",
	} {
		r := httptest.NewRequest(http.MethodGet, "/apis/horchestra.io/v1/applications?"+q, nil)
		if got := REST(r, nil).Verb; got != want {
			t.Errorf("?%s: verb %q, want %q", q, got, want)
		}
		if IsWatch(r) != (want == "watch") {
			t.Errorf("?%s: IsWatch disagrees with the verb", q)
		}
	}
}

// A path deeper than one subresource segment is not judged as the shallower subresource.
func TestADeeperPathIsItsOwnSubresource(t *testing.T) {
	at := attributesOf(t, http.MethodGet, "/apis/horchestra.io/v1/nodes/node-1/log/lines")
	if at.Target() == "nodes/log" {
		t.Fatalf("target = %q: the tail rode under nodes/log", at.Target())
	}
}
