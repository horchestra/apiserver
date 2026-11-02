package basic

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/horchestra/apiserver/authn"
)

var checker = CheckerFunc(func(_ context.Context, user, password string) (*authn.Identity, error) {
	switch {
	case password == "broken":
		return nil, errors.New("directory down")
	case user == "alice" && password == "right":
		return &authn.Identity{Name: user}, nil
	}
	return nil, nil
})

func TestAuthenticate(t *testing.T) {
	for name, tc := range map[string]struct {
		a        Authenticator
		user     string
		password string
		wantName string
		wantErr  error
	}{
		"nothing presented": {a: Authenticator{Checker: checker}, wantErr: authn.ErrNoCredentials},
		"right password":    {a: Authenticator{Checker: checker}, user: "alice", password: "right", wantName: "alice"},
		"wrong password":    {a: Authenticator{Checker: checker}, user: "alice", password: "wrong", wantErr: authn.ErrUnauthenticated},
		// A password presented to a server that checks none is refused, not passed over: the chain
		// must not carry on to an anonymous member.
		"no checker": {a: Authenticator{}, user: "alice", password: "right", wantErr: authn.ErrUnauthenticated},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if len(tc.user) > 0 {
				r.SetBasicAuth(tc.user, tc.password)
			}
			id, err := tc.a.Authenticate(r)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && id.Name != tc.wantName {
				t.Fatalf("identity = %+v, want %s", id, tc.wantName)
			}
		})
	}
}

// The checker's own failure is not a bad password: its error goes up as it came.
func TestACheckerFailureIsItsOwnError(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("alice", "broken")
	_, err := Authenticator{Checker: checker}.Authenticate(r)
	if err == nil || errors.Is(err, authn.ErrUnauthenticated) || errors.Is(err, authn.ErrNoCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestChallengeNamesARealm(t *testing.T) {
	for realm, want := range map[string]string{
		"":          `Basic realm="restricted"`,
		"ops":       `Basic realm="ops"`,
		`the "ops"`: `Basic realm="the \"ops\""`,
	} {
		rec := httptest.NewRecorder()
		Authenticator{Realm: realm}.Challenge(rec)
		if got := rec.Header().Get("WWW-Authenticate"); got != want {
			t.Fatalf("realm %q: challenge = %s, want %s", realm, got, want)
		}
	}
}
