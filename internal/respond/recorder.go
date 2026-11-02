// Package respond holds the one ResponseWriter wrapper this module needs: the layers that report
// on a request afterwards — the access log, the metrics — have to know what the handler answered,
// and a second copy of this would be a second chance to get the streaming behaviour wrong.
package respond

import "net/http"

// Recorder remembers the status and the byte count of a response, which is the only thing about a
// served request that cannot be read back from anywhere else.
//
// It forwards nothing else: Unwrap is what http.NewResponseController follows, so flushing a watch
// and hijacking a connection reach the real writer untouched. A wrapper that swallowed those would
// turn every streaming endpoint into one that buffers until it finishes.
type Recorder struct {
	http.ResponseWriter
	status  int
	written int64
}

// Wrap returns the recorder, or the one already in place: the chain wraps a request twice — once
// for the log, once for the metrics — and a recorder around a recorder would count the response
// under whichever of the two the handler happened to write through.
func Wrap(w http.ResponseWriter) *Recorder {
	if rec, ok := w.(*Recorder); ok {
		return rec
	}
	return &Recorder{ResponseWriter: w}
}

// Status is the code the handler wrote, or 0 when it wrote none — a handler that returned an error
// instead, and whose status is the one that error renders as.
func (rec *Recorder) Status() int { return rec.status }

// Written is how many bytes of body reached the client.
func (rec *Recorder) Written() int64 { return rec.written }

func (rec *Recorder) WriteHeader(code int) {
	if rec.status == 0 {
		rec.status = code
	}
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *Recorder) Write(b []byte) (int, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	n, err := rec.ResponseWriter.Write(b)
	rec.written += int64(n)
	return n, err
}

func (rec *Recorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// Flush keeps a streaming handler streaming under the older interface, for the writers and
// libraries that look for http.Flusher rather than going through http.ResponseController.
func (rec *Recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
