package errors

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestStatusOfUnclassifiedErrorIs500: an error nobody gave a status to is a server fault, not a
// client one. The opposite default would answer 400 for a broken store and send an operator
// looking at the caller.
func TestStatusOfUnclassifiedErrorIs500(t *testing.T) {
	if got := StatusOf(errors.New("the store is unreachable")); got != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", got)
	}
	if got := StatusOf(nil); got != http.StatusOK {
		t.Fatalf("status of no error = %d, want 200", got)
	}
}

// TestInternalKeepsTheCauseOutOfTheMessage: the text a 500 shows the caller is fixed, while the
// cause stays reachable through the chain for the log that writes it.
func TestInternalKeepsTheCauseOutOfTheMessage(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.7:5432: connection refused")
	err := Internal(cause)

	if strings.Contains(err.Error(), "10.0.0.7") {
		t.Fatalf("the cause reached the message: %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("the cause is no longer in the chain, so nothing can log it")
	}
}

// TestWrapKeepsTheChain: a status put on an existing error must not cut errors.Is off from it, or
// a caller matching on a sentinel stops matching the moment a layer classifies it.
func TestWrapKeepsTheChain(t *testing.T) {
	sentinel := errors.New("no such object")
	err := Wrap(http.StatusNotFound, sentinel)

	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is no longer reaches the wrapped error")
	}
	if StatusOf(err) != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", StatusOf(err))
	}
}

// TestJSONWriterBody: the default rendering says the code, its reason and the message, and sets a
// content type — a client that reads the body has to be told it is JSON.
func TestJSONWriterBody(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON.WriteError(rec, httptest.NewRequest(http.MethodGet, "/x", nil), Forbidden("no rule grants get on nodes"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{`"code":403`, `"reason":"Forbidden"`, "no rule grants get on nodes"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s does not carry %s", body, want)
		}
	}
}

// TestRegisterStatusRacesNothing: a reading registered while requests are being served is a
// late registration and not a data race. It means something under -race.
func TestRegisterStatusRacesNothing(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			RegisterStatus(func(error) (int, bool) { return 0, false })
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			StatusOf(errors.New("unclassified"))
		}
	}()
	wg.Wait()
}
