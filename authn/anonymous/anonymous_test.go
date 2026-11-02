package anonymous

import (
	"net/http/httptest"
	"testing"

	"github.com/horchestra/apiserver/authn"
)

func TestTheDefaultIdentityIsOneARuleCanName(t *testing.T) {
	id, err := Authenticator{}.Authenticate(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != User || !id.InGroup(Group) {
		t.Fatalf("identity = %+v", id)
	}
}

// A configured identity is handed out to every request, so no request may change it.
func TestAConfiguredIdentityIsNotShared(t *testing.T) {
	a := Authenticator{Identity: &authn.Identity{Name: "guest", Groups: []string{"guests"}}}
	id, err := a.Authenticate(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	id.Groups[0] = "admins"
	if a.Identity.Groups[0] != "guests" {
		t.Fatalf("a request changed the configured identity: %+v", a.Identity)
	}
}
