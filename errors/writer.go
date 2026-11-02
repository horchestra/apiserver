package errors

import (
	"encoding/json"
	"net/http"
)

// Writer renders a refusal. One per component, chosen once at startup and used by every layer, so
// that the body a caller reads does not depend on which layer refused it.
type Writer interface {
	WriteError(w http.ResponseWriter, r *http.Request, err error)
}

// WriterFunc adapts a function to Writer.
type WriterFunc func(w http.ResponseWriter, r *http.Request, err error)

func (f WriterFunc) WriteError(w http.ResponseWriter, r *http.Request, err error) { f(w, r, err) }

// Body is the default rendering: the status, its reason and the message, and nothing else. It is
// deliberately not a Kubernetes Status — a component that needs one takes errors/k8s, and one
// that does not keeps apimachinery out of its binary.
type Body struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// JSON is the Writer a Server uses when a component names none.
var JSON Writer = WriterFunc(writeJSON)

func writeJSON(w http.ResponseWriter, _ *http.Request, err error) {
	code := StatusOf(err)
	WriteJSON(w, code, Body{Code: code, Reason: Reason(code), Message: err.Error()})
}

// WriteJSON writes v as the whole response. The header goes out BEFORE the body and is never
// written twice: an encoder that fails halfway has already sent bytes under the status it was
// given, and a second WriteHeader on that response is a log line and nothing else.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
