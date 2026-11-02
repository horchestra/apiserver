package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uptrace/bunrouter"

	"github.com/horchestra/apiserver/authz"
	"github.com/horchestra/apiserver/errors"
)

// An authorizer's own refusal is a 403 in its own words, not the 500 an authorizer's failure is.
func TestAnAuthorizersOwnRefusalIsAForbiddenInItsWords(t *testing.T) {
	az := authz.Func(func(_ context.Context, a authz.Attributes) (authz.Decision, error) {
		return authz.Deny, &authz.Refusal{Attributes: a, Reason: "the upstream says no"}
	})
	h := Authorize(az, nil, nil)(func(http.ResponseWriter, bunrouter.Request) error {
		t.Fatal("a refused request reached the handler")
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/apis/g/v1/namespaces/n/things/x", nil)
	err := h(httptest.NewRecorder(), bunrouter.NewRequest(req))
	if errors.StatusOf(err) != http.StatusForbidden || err.Error() != "the upstream says no" {
		t.Fatalf("err = %v (%d), want the authorizer's refusal as a 403", err, errors.StatusOf(err))
	}
}
