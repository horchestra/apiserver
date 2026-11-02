package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/authn"
	"github.com/horchestra/apiserver/errors"
)

// An authenticator that could not decide keeps the status it says; a refused credential is a 401.
func TestAnAuthenticatorOutageIsNotABadCredential(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{errors.Unavailable("the directory is unreachable"), http.StatusServiceUnavailable},
		{errors.Internal(errors.New(500, "boom")), http.StatusInternalServerError},
		{authn.ErrUnauthenticated, http.StatusUnauthorized},
		{errors.Unauthorized("expired"), http.StatusUnauthorized},
	} {
		a := authn.Func(func(*http.Request) (*authn.Identity, error) { return nil, tc.err })
		h := Authenticate(a, nil)(func(http.ResponseWriter, bunrouter.Request) error {
			t.Fatal("a failed authentication reached the handler")
			return nil
		})
		err := h(httptest.NewRecorder(), bunrouter.NewRequest(httptest.NewRequest(http.MethodGet, "/x", nil)))
		if got := errors.StatusOf(err); got != tc.want {
			t.Errorf("%v: status %d, want %d", tc.err, got, tc.want)
		}
	}
}
