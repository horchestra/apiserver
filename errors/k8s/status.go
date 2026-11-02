// Package k8s renders a refusal as a Kubernetes metav1.Status, the body kubectl and every
// client-go client already know how to read.
//
// It is a package of its own — and the only thing in this module that imports apimachinery —
// because a node agent's metrics endpoint and a proxy's admin surface have no Kubernetes client in
// front of them and should not carry the dependency to answer a 403.
package k8s

import (
	"errors"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	ksapierror "github.com/horchestra/apiserver/errors"
)

// Writer answers every refusal with a Status object.
//
// An error that is already an apimachinery error is rendered as the Status IT built: those carry
// details a client acts on — the group and resource of a conflict, the causes of a failed
// validation, the seconds a 429 asks the client to wait — and rebuilding them from a status code
// would throw exactly that away.
var Writer ksapierror.Writer = ksapierror.WriterFunc(write)

// The codes this writer answers with are the ones StatusOf reports, so the access log and the
// metrics count what the caller was told and not a 500 for every error they cannot name. A Status
// with no code says nothing: WriteHeader panics on 0, and the log would turn it into a 200.
func init() {
	ksapierror.RegisterStatus(func(err error) (int, bool) {
		if apiStatus, ok := errors.AsType[statusError](err); ok {
			if code := apiStatus.Status().Code; code != 0 {
				return int(code), true
			}
		}
		return 0, false
	})
}

func write(w http.ResponseWriter, _ *http.Request, err error) {
	status := statusOf(err)
	status.APIVersion, status.Kind = "v1", "Status"
	ksapierror.WriteJSON(w, int(status.Code), status)
}

// statusError is an apimachinery error as the errors package can look for it in a chain: an error
// that carries the Status it builds.
type statusError interface {
	error
	apierrors.APIStatus
}

// objectRefusal is an authorization refusal that names its object (authz.Refusal). Matched by
// shape so this package, the only one that imports apimachinery, stays the leaf it is.
type objectRefusal interface {
	error
	Object() (group, resource, name string)
}

// statusOf answers with the code StatusOf reports, always, so the wire and the log cannot part. A
// Status found in the chain is rendered only when it says the same thing: a layer that classified
// an apimachinery error with Wrap and kept its code kept its details too, and those are the point,
// but a layer that gave it another code has overruled it.
//
// A classified 500 is never rendered from its cause, whatever code the cause carries: that is
// errors.Internal, whose message is not the caller's business.
func statusOf(err error) metav1.Status {
	code := ksapierror.StatusOf(err)
	_, classified := errors.AsType[ksapierror.Error](err)
	if !classified || code != http.StatusInternalServerError {
		if status, ok := renderedStatus(err); ok && int(status.Code) == code {
			return status
		}
	}
	return metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    int32(code),
		Reason:  metav1.StatusReason(ksapierror.Reason(code)),
		Message: err.Error(),
	}
}

// renderedStatus is the Status the chain already holds or names the parts of.
func renderedStatus(err error) (metav1.Status, bool) {
	// Found anywhere in the chain: Wrap keeps an apimachinery error as the cause.
	if apiStatus, ok := errors.AsType[statusError](err); ok {
		return apiStatus.Status(), true
	}

	// A refusal that knows what it refused is rendered the way kube-apiserver renders one, with
	// the group, resource and name in the details a client reads them from.
	if refusal, ok := errors.AsType[objectRefusal](err); ok {
		group, resource, name := refusal.Object()
		return apierrors.NewForbidden(schema.GroupResource{Group: group, Resource: resource}, name,
			errors.New(refusal.Error())).Status(), true
	}
	return metav1.Status{}, false
}
