package authn

import "context"

type identityKey struct{}

// WithIdentity puts the authenticated caller in the context, which is how every layer past the
// authentication middleware — authorization, admission, a handler, an audit record — reads it
// back without parsing the request a second time. It also tells an Observe further out.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	if s, ok := ctx.Value(slotKey{}).(*slot); ok {
		s.id = id
	}
	return context.WithValue(ctx, identityKey{}, id)
}

type slotKey struct{}

type slot struct{ id *Identity }

// Observe is for a layer OUTSIDE authentication that has to name the caller afterwards — the
// access log. A context only flows inward: the identity authentication adds lives in a copy of
// the request this layer never sees. Observe leaves a slot in the context it returns, WithIdentity
// fills it wherever further in it runs, and the function reads it once the request is served.
func Observe(ctx context.Context) (context.Context, func() *Identity) {
	s := &slot{}
	return context.WithValue(ctx, slotKey{}, s), func() *Identity { return s.id }
}

// FromContext is the identity WithIdentity stored, or nil for a request that never passed through
// authentication.
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}
