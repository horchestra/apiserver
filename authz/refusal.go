package authz

import "net/http"

// Refusal is the error a request the authorizer did not allow is answered with. It carries the
// attributes the decision was made about, so an error writer that renders more than a sentence —
// a Kubernetes Status names the group, the resource and the object — has them to render, instead
// of parsing them back out of the reason.
//
// An authorizer that knows why it refuses returns one itself, as a *Refusal — a pointer, which is
// what the middleware looks for: the request is then a 403 in the authorizer's words, where any
// other error from an authorizer is a 500.
type Refusal struct {
	Attributes Attributes
	Reason     string
}

func (r *Refusal) Error() string   { return r.Reason }
func (r *Refusal) HTTPStatus() int { return http.StatusForbidden }

// Object is the group, resource and name the refused request addressed — empty for a request
// that addressed no resource.
func (r *Refusal) Object() (group, resource, name string) {
	return r.Attributes.Group, r.Attributes.Resource, r.Attributes.Name
}
