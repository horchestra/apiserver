package authz

import (
	"net/http"
	"strings"

	"github.com/horchestra/apiserver/authn"
)

// AttributesFunc turns a request into the attributes it is judged by. A component whose paths are
// not REST-shaped — a metrics endpoint, a proxy's admin surface — writes its own and keeps the
// same authorizers.
type AttributesFunc func(r *http.Request, id *authn.Identity) Attributes

// REST reads a Kubernetes-shaped path: /apis/{group}/{version}/... and the core /api/{version}/...,
// namespaced or not, with the segment after an object's name taken as a subresource.
//
// The verb comes from the method, with the read methods split the way a rule is written: a list is
// not a get, and a watch is neither — a grant to read one object must not be a grant to stream
// every change to all of them.
//
// Anything that is not a resource path — discovery, a schema document, a probe — comes back with
// ResourceRequest false and the lowercased method as its verb, which is what a rule about Path is
// compared against.
func REST(r *http.Request, id *authn.Identity) Attributes {
	at := Attributes{User: id, Path: r.URL.Path}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var rest []string
	switch {
	case len(parts) >= 4 && parts[0] == "apis":
		at.Group = parts[1]
		rest = parts[3:] // after /apis/{group}/{version}
	case len(parts) >= 3 && parts[0] == "api":
		rest = parts[2:] // after /api/{version}; the core group has no name
	default:
		at.Verb = strings.ToLower(r.Method)
		return at
	}
	at.ResourceRequest = true
	// A namespaced request is /namespaces/{ns}/{resource}[/{name}] — three segments or more.
	// /namespaces and /namespaces/{name} are the cluster-scoped Namespace resource itself.
	if len(rest) >= 3 && rest[0] == "namespaces" {
		at.Namespace = rest[1]
		rest = rest[2:]
	}
	if len(rest) >= 1 {
		at.Resource = rest[0]
	}
	if len(rest) >= 2 {
		at.Name = rest[1]
	}
	if len(rest) >= 3 {
		// Everything after the name is the subresource, joined: a path deeper than one segment
		// asks for a subresource no rule names and is refused, rather than riding under the
		// shallower one a truncating parser would have judged it as.
		at.Subresource = strings.Join(rest[2:], "/")
	}
	at.Verb = verb(r, at.Name)
	return at
}

// Path is the attributes for a server whose paths name no resources: the verb is the method and
// the path is the whole of the request. Rules are written about Path alone.
func Path(r *http.Request, id *authn.Identity) Attributes {
	return Attributes{User: id, Verb: strings.ToLower(r.Method), Path: r.URL.Path}
}

// IsWatch is whether a read is a watch, by kube-apiserver's rule: the watch parameter present with
// any value but "false" or "0" — "true", "1", "yes", even empty. It is ONE function on purpose: the
// authorizer decides the verb with it and every handler decides whether to stream with it, and two
// readings of one parameter are a list grant that streams the day they part. A repeated parameter
// is read by its first value, as kube-apiserver reads it.
func IsWatch(r *http.Request) bool {
	vs, ok := r.URL.Query()["watch"]
	if !ok || len(vs) == 0 {
		return false
	}
	switch strings.ToLower(vs[0]) {
	case "false", "0":
		return false
	}
	return true
}

// verb names what the method does to a resource. Every method that changes nothing reads as a read,
// HEAD and OPTIONS included: neither returns more about the object than a get does, so a grant to
// read one covers them and no rule has to spell them out.
func verb(r *http.Request, name string) string {
	switch r.Method {
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		if len(name) == 0 {
			return "deletecollection"
		}
		return "delete"
	default:
		switch {
		case IsWatch(r):
			return "watch"
		case len(name) == 0:
			return "list"
		default:
			return "get"
		}
	}
}
