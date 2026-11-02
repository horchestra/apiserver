// Package errors is what a refusal looks like before anything renders it: an error that carries
// the HTTP status it deserves, and a Writer that turns one into a response body.
//
// The split is the point. A handler, a middleware and an authenticator all refuse in the same
// vocabulary — Forbidden, NotFound, Unauthorized — while the BODY those refusals come out as
// belongs to the component: the control plane answers a Kubernetes Status (errors/k8s) because
// kubectl reads one, and a metrics endpoint answers whatever its scraper reads. A package that
// hard-coded one body would have made every other component render its own errors by hand, which
// is how two surfaces of one platform come to disagree about what a 403 looks like.
package errors

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// Error is an error that knows the status the response should carry. Anything a handler returns
// that is not one is a 500: an error nobody classified is an error nobody meant to show.
type Error interface {
	error
	HTTPStatus() int
}

type statusError struct {
	code  int
	msg   string
	cause error
}

func (e *statusError) Error() string   { return e.msg }
func (e *statusError) HTTPStatus() int { return e.code }
func (e *statusError) Unwrap() error   { return e.cause }

// New is a refusal with a status and a message of its own.
func New(code int, format string, a ...any) Error {
	return &statusError{code: code, msg: fmt.Sprintf(format, a...)}
}

// Wrap gives an existing error a status while keeping it in the chain, so errors.Is and errors.As
// still reach the cause a caller may want to match on.
func Wrap(code int, err error) Error {
	if err == nil {
		return nil
	}
	return &statusError{code: code, msg: err.Error(), cause: err}
}

func BadRequest(format string, a ...any) Error {
	return New(http.StatusBadRequest, format, a...)
}

func Unauthorized(format string, a ...any) Error {
	return New(http.StatusUnauthorized, format, a...)
}

func Forbidden(format string, a ...any) Error {
	return New(http.StatusForbidden, format, a...)
}

func NotFound(format string, a ...any) Error {
	return New(http.StatusNotFound, format, a...)
}

func MethodNotAllowed(format string, a ...any) Error {
	return New(http.StatusMethodNotAllowed, format, a...)
}

func Conflict(format string, a ...any) Error {
	return New(http.StatusConflict, format, a...)
}

func TooManyRequests(format string, a ...any) Error {
	return New(http.StatusTooManyRequests, format, a...)
}

func Unavailable(format string, a ...any) Error {
	return New(http.StatusServiceUnavailable, format, a...)
}

// Internal is the one refusal whose message is NOT the caller's business: the text goes to the
// log, the caller gets the sentence every 500 gets. A cause that reaches the body leaks the shape
// of the store, the filesystem and the query behind it, one stack frame at a time.
func Internal(err error) Error {
	return &statusError{code: http.StatusInternalServerError, msg: "internal server error", cause: err}
}

// StatusOf is the status an error asks for: its own when it carries one, the one a registered
// reader finds in it, 500 otherwise. A nil error has no status and reports 200, so a caller can log
// one number for both outcomes.
func StatusOf(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if se, ok := errors.AsType[Error](err); ok {
		return se.HTTPStatus()
	}
	statusReadersMu.RLock()
	readers := statusReaders
	statusReadersMu.RUnlock()
	for _, read := range readers {
		if code, ok := read(err); ok {
			return code
		}
	}
	return http.StatusInternalServerError
}

// statusReaders are the readings of errors this package cannot name: a Writer that renders a kind
// of error of its own registers how to read that kind's status, so everything that reports a
// status — the access log, the metrics — reports the one the caller was answered with. Without it
// the Kubernetes writer answered a refused delete with 422 while the log said 500 (the stand,
// 2026-10-10). The list only grows, so the slice a reader copied under the lock stays valid.
var (
	statusReadersMu sync.RWMutex
	statusReaders   []func(error) (int, bool)
)

// RegisterStatus adds a reading to StatusOf. A reading is asked only about an error that carries
// no status of its own: the outermost classification decides, and a Writer has to answer with it.
func RegisterStatus(read func(error) (int, bool)) {
	statusReadersMu.Lock()
	defer statusReadersMu.Unlock()
	statusReaders = append(statusReaders, read)
}

// Reason is the short, machine-read name of a status, spelled as Kubernetes spells it so a client
// that already knows those words needs no second table.
func Reason(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "BadRequest"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusMethodNotAllowed:
		return "MethodNotAllowed"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	case http.StatusInternalServerError:
		return "InternalError"
	default:
		return http.StatusText(code)
	}
}
