package k8s

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/horchestra/apiserver/authz"
	"github.com/horchestra/apiserver/errors"
)

// TestPlainErrorBecomesAStatus: a client-go client reads a Status and nothing else, so even an
// error raised by a component that knows no apimachinery has to arrive as one.
func TestPlainErrorBecomesAStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	Writer.WriteError(rec, httptest.NewRequest(http.MethodGet, "/apis", nil), errors.Forbidden("no rule grants get on nodes"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"kind":"Status"`, `"apiVersion":"v1"`, `"code":403`, `"reason":"Forbidden"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s does not carry %s", body, want)
		}
	}
}

// TestApimachineryErrorKeepsItsOwnStatus: those carry details a client acts on — here the group
// and resource of the conflict — and rebuilding the Status from a status code would throw exactly
// that away.
func TestApimachineryErrorKeepsItsOwnStatus(t *testing.T) {
	err := apierrors.NewConflict(schema.GroupResource{Group: "horchestra.io", Resource: "applications"}, "web",
		nil)

	rec := httptest.NewRecorder()
	Writer.WriteError(rec, httptest.NewRequest(http.MethodPut, "/apis", nil), err)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"reason":"Conflict"`, `"group":"horchestra.io"`, `"name":"web"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s does not carry %s", body, want)
		}
	}
}

// TestARefusalNamesItsObject: kubectl and client-go read a 403's group, resource and name from the
// Status details, the way kube-apiserver writes them, so a refusal that knows them says them there.
func TestARefusalNamesItsObject(t *testing.T) {
	err := &authz.Refusal{
		Attributes: authz.Attributes{Group: "horchestra.io", Resource: "applications", Name: "web", Verb: "get"},
		Reason:     "no rule grants get on horchestra.io/applications named web",
	}

	rec := httptest.NewRecorder()
	Writer.WriteError(rec, httptest.NewRequest(http.MethodGet, "/apis", nil), err)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"reason":"Forbidden"`, `"group":"horchestra.io"`, `"kind":"applications"`,
		`"name":"web"`, `applications.horchestra.io \"web\" is forbidden: no rule grants get`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s does not carry %s", body, want)
		}
	}
}

// An apimachinery error a layer wrapped still answers with the Status it built — the details a
// client acts on survive the wrapping.
func TestAWrappedStatusKeepsItsDetails(t *testing.T) {
	inner := apierrors.NewConflict(schema.GroupResource{Group: "horchestra.io", Resource: "applications"}, "web", stderrors.New("stale"))
	rec := httptest.NewRecorder()
	Writer.WriteError(rec, nil, errors.Wrap(http.StatusConflict, inner))
	var st metav1.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Details == nil || st.Details.Name != "web" || st.Details.Group != "horchestra.io" {
		t.Fatalf("details = %+v, want the conflict's own", st.Details)
	}
}

// TestStatusOfReportsWhatTheCallerWasAnswered: the access log and the metrics read a status
// through errors.StatusOf, and for an apimachinery error that has to be the code this writer
// answers with — a refused delete is a 422 in the log as on the wire, not a 500.
func TestStatusOfReportsWhatTheCallerWasAnswered(t *testing.T) {
	invalid := apierrors.NewInvalid(schema.GroupKind{Group: "horchestra.io", Kind: "Service"}, "web", nil)
	rec := httptest.NewRecorder()
	Writer.WriteError(rec, httptest.NewRequest(http.MethodDelete, "/apis", nil), invalid)
	if got := errors.StatusOf(invalid); got != rec.Code || got != http.StatusUnprocessableEntity {
		t.Fatalf("StatusOf = %d, answered %d, want both 422", got, rec.Code)
	}
	if got := errors.StatusOf(stderrors.New("disk on fire")); got != http.StatusInternalServerError {
		t.Fatalf("an unknown error reads %d, want 500", got)
	}
}

// codelessStatus is a hand-made APIStatus that forgot its code.
type codelessStatus struct{}

func (codelessStatus) Error() string         { return "no code" }
func (codelessStatus) Status() metav1.Status { return metav1.Status{Message: "no code"} }

// TestTheWireAndTheLogAgree: whatever wrapped whatever, the code the writer answers with is the
// one the access log and the metrics read.
func TestTheWireAndTheLogAgree(t *testing.T) {
	invalid := apierrors.NewInvalid(schema.GroupKind{Group: "horchestra.io", Kind: "Service"}, "web", nil)
	conflict := apierrors.NewConflict(schema.GroupResource{Resource: "applications"}, "web", stderrors.New("stale"))
	refusal := &authz.Refusal{Reason: "no rule"}

	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"bare status":            {invalid, http.StatusUnprocessableEntity},
		"wrapped, same code":     {errors.Wrap(http.StatusConflict, conflict), http.StatusConflict},
		"wrapped, overruled":     {errors.Wrap(http.StatusBadRequest, invalid), http.StatusBadRequest},
		"internal over a status": {errors.Internal(conflict), http.StatusInternalServerError},
		"internal over refusal":  {errors.Internal(refusal), http.StatusInternalServerError},
		"status without a code":  {codelessStatus{}, http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Writer.WriteError(rec, httptest.NewRequest(http.MethodGet, "/apis", nil), tc.err)
			if got := errors.StatusOf(tc.err); got != tc.want || rec.Code != tc.want {
				t.Fatalf("StatusOf = %d, answered %d, want both %d", got, rec.Code, tc.want)
			}
			var st metav1.Status
			if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
				t.Fatal(err)
			}
			if int(st.Code) != tc.want {
				t.Fatalf("the body says %d, want %d", st.Code, tc.want)
			}
		})
	}
}

// TestInternalKeepsItsCauseToItself: errors.Internal's message is the sentence every 500 gets, and
// a cause that happens to be an apimachinery error, even a 500 of its own, does not change that.
func TestInternalKeepsItsCauseToItself(t *testing.T) {
	for _, cause := range []error{
		apierrors.NewConflict(schema.GroupResource{Resource: "secret-store"}, "web", stderrors.New("stale")),
		apierrors.NewInternalError(stderrors.New("secret-store is down")),
	} {
		rec := httptest.NewRecorder()
		Writer.WriteError(rec, httptest.NewRequest(http.MethodGet, "/apis", nil), errors.Internal(cause))
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret-store") {
			t.Fatalf("answered %d with %s", rec.Code, rec.Body)
		}
	}
}
