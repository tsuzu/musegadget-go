// Package streaming mirrors musegadget.streaming: bounded, duplex HTTP
// response streams over a link session, plus the NDJSON record reader.
//
// A slow consumer fails its own stream rather than blocking control or
// other requests on the multiplexed connection. Callers must Close streams,
// including when they abandon a response before EOF.
package streaming

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"musegadget/noise"
	"musegadget/wirejson"
)

const (
	MaxBufferBytes  = 2 * 1024 * 1024
	MaxBufferChunks = 256
	MaxLineBytes    = 1024 * 1024
	MaxErrorBytes   = 64 * 1024
	MaxSendBytes    = 64 * 1024
)

// ErrClosed reports use of a closed request stream.
var ErrClosed = errors.New("request stream closed")

// HTTPStatusError reports a non-2xx response head; Body holds up to
// 64 KiB of the drained response body.
type HTTPStatusError struct {
	Status int
	Body   []byte
}

func (e *HTTPStatusError) Error() string { return fmt.Sprintf("request refused: HTTP %d", e.Status) }

// Session is what a StreamingRequest needs from its link session: the
// send lock ceremony (check runs under the lock, before encryption, so a
// stale stream consumes no nonce) and the transport itself.
type Session interface {
	SendEncrypted(encrypt func() ([][]byte, error), check func() error) error
	Transport() *noise.Transport
	UnregisterRequest(streamID int64)
}

// StreamingRequest is one request with independent input and output
// lifetimes; one reader.
type StreamingRequest struct {
	session         Session
	StreamID        int64
	MaxBufferBytes  int
	MaxBufferChunks int

	Status  *int
	Headers []noise.Header

	mu            sync.Mutex
	changed       chan struct{}
	chunks        [][]byte
	bufferedBytes int
	err           error
	ended         bool
	closed        bool
	inputClosed   bool // EOF intent blocks new body producers immediately.
	inputEOFSent  bool
	closeComplete bool
	endMu         sync.Mutex
}

// New creates a StreamingRequest registered (by the caller) on a session.
func New(session Session, streamID int64, maxBufferBytes, maxBufferChunks int) *StreamingRequest {
	return &StreamingRequest{
		session: session, StreamID: streamID,
		MaxBufferBytes: maxBufferBytes, MaxBufferChunks: maxBufferChunks,
		changed: make(chan struct{}),
	}
}

// Ended reports whether the response reached end_body.
func (r *StreamingRequest) Ended() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ended
}

func (r *StreamingRequest) signalLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *StreamingRequest) checkLocked() error {
	if r.err != nil {
		return r.err
	}
	if r.closed {
		return ErrClosed
	}
	return nil
}

// Fail fails the stream with err, discarding buffered data.
func (r *StreamingRequest) Fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
	r.chunks = nil
	r.bufferedBytes = 0
	r.signalLocked()
}

// OnFrame dispatches one inbound frame to the stream.
func (r *StreamingRequest) OnFrame(frame *noise.DecryptedFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	if r.ended {
		r.failLocked(errors.New("response data after EOF"))
		return
	}
	var data []byte
	var endBody bool
	switch frame.Kind {
	case noise.FrameReset:
		r.failLocked(errors.New("request stream reset"))
		return
	case noise.FrameResponse:
		if r.Status != nil || frame.Response.Status < 100 || frame.Response.Status > 599 {
			r.failLocked(errors.New("invalid or duplicate response head"))
			return
		}
		status := int(frame.Response.Status)
		r.Status = &status
		r.Headers = frame.Response.Headers
		data, endBody = frame.Response.Body, frame.Response.EndBody
	case noise.FrameBodyChunk:
		if r.Status == nil {
			r.failLocked(errors.New("response body before head"))
			return
		}
		data, endBody = frame.BodyChunk.Data, frame.BodyChunk.EndBody
	default:
		r.failLocked(errors.New("response body before head"))
		return
	}
	if len(data) > 0 {
		if r.bufferedBytes+len(data) > r.MaxBufferBytes || len(r.chunks) >= r.MaxBufferChunks {
			r.failLocked(errors.New("response stream buffer full"))
			return
		}
		r.chunks = append(r.chunks, data)
		r.bufferedBytes += len(data)
	}
	r.ended = endBody
	r.signalLocked()
}

func (r *StreamingRequest) failLocked(err error) {
	if r.err == nil {
		r.err = err
	}
	r.chunks = nil
	r.bufferedBytes = 0
	r.signalLocked()
}

func (r *StreamingRequest) waitChanged(ctx context.Context) error {
	r.mu.Lock()
	changed := r.changed
	r.mu.Unlock()
	select {
	case <-changed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitResponse waits for the response head, validates the status, and
// returns it. A non-2xx status drains up to 64 KiB of body and fails with
// *HTTPStatusError.
func (r *StreamingRequest) WaitResponse(ctx context.Context) (int, error) {
	for {
		r.mu.Lock()
		status := r.Status
		checkErr := r.checkLocked()
		r.mu.Unlock()
		if checkErr != nil {
			return 0, checkErr
		}
		if status != nil {
			break
		}
		if err := r.waitChanged(ctx); err != nil {
			return 0, err
		}
	}
	r.mu.Lock()
	checkErr := r.checkLocked()
	status := *r.Status
	r.mu.Unlock()
	if checkErr != nil {
		return 0, checkErr
	}
	if status < 200 || status >= 300 {
		body := []byte{}
		for len(body) < MaxErrorBytes {
			chunk, err := r.Read(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				return 0, err
			}
			take := MaxErrorBytes - len(body)
			if len(chunk) < take {
				take = len(chunk)
			}
			body = append(body, chunk[:take]...)
		}
		return 0, &HTTPStatusError{Status: status, Body: body}
	}
	return status, nil
}

// Read returns the next nonempty response chunk, or (nil, io.EOF) at clean
// EOF.
func (r *StreamingRequest) Read(ctx context.Context) ([]byte, error) {
	for {
		r.mu.Lock()
		if err := r.checkLocked(); err != nil {
			r.mu.Unlock()
			return nil, err
		}
		if len(r.chunks) > 0 {
			chunk := r.chunks[0]
			r.chunks = r.chunks[1:]
			r.bufferedBytes -= len(chunk)
			r.mu.Unlock()
			return chunk, nil
		}
		if r.ended {
			r.mu.Unlock()
			return nil, io.EOF
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (r *StreamingRequest) checkSendLocked() error {
	if err := r.checkLocked(); err != nil {
		return err
	}
	if r.inputEOFSent {
		return errors.New("request body already closed")
	}
	return nil
}

// SendBody sends one chunk (at most 64 KiB). The optional check runs under
// the session's send lock before encryption.
func (r *StreamingRequest) SendBody(data []byte, endBody bool, check func() error) error {
	r.mu.Lock()
	err := r.checkLocked()
	closed := r.inputClosed
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if closed {
		return errors.New("request body already closed")
	}
	if len(data) > MaxSendBytes {
		return errors.New("request chunk exceeds 64 KiB")
	}
	if endBody {
		r.mu.Lock()
		r.inputClosed = true
		r.mu.Unlock()
		r.endMu.Lock()
		defer r.endMu.Unlock()
		return r.sendBody(data, true, check)
	}
	return r.sendBody(data, false, check)
}

func (r *StreamingRequest) sendBody(data []byte, endBody bool, check func() error) error {
	admissible := func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := r.checkSendLocked(); err != nil {
			return err
		}
		if check != nil {
			return check()
		}
		return nil
	}
	transport := r.session.Transport()
	err := r.session.SendEncrypted(func() ([][]byte, error) {
		return transport.EncryptBodyChunk(r.StreamID, data, nil, endBody)
	}, admissible)
	if err != nil {
		return err
	}
	if endBody {
		r.mu.Lock()
		r.inputEOFSent = true
		r.mu.Unlock()
	}
	return nil
}

// HalfClose ends only the upload side.
func (r *StreamingRequest) HalfClose() error {
	r.mu.Lock()
	r.inputClosed = true
	r.mu.Unlock()
	r.endMu.Lock()
	defer r.endMu.Unlock()
	r.mu.Lock()
	err := r.checkLocked()
	sent := r.inputEOFSent
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if !sent {
		return r.sendBody(nil, true, nil)
	}
	return nil
}

// Close abandons the stream: unless the response ended and the request
// body was fully sent, it resets the stream, then unregisters it.
func (r *StreamingRequest) Close() error {
	r.mu.Lock()
	if r.closeComplete {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.chunks = nil
	r.bufferedBytes = 0
	r.signalLocked()
	r.mu.Unlock()

	r.endMu.Lock()
	defer r.endMu.Unlock()
	r.mu.Lock()
	if r.closeComplete {
		r.mu.Unlock()
		return nil
	}
	ended, eofSent := r.ended, r.inputEOFSent
	r.mu.Unlock()
	if !(ended && eofSent) {
		transport := r.session.Transport()
		if err := r.session.SendEncrypted(func() ([][]byte, error) {
			return transport.EncryptReset(r.StreamID, "client closed stream")
		}, nil); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.closeComplete = true
	r.mu.Unlock()
	r.session.UnregisterRequest(r.StreamID)
	return nil
}

// NDJSONReader yields JSON objects from arbitrarily fragmented NDJSON.
// LF is required even on the last record; CRLF and blank lines are
// accepted. Malformed JSON, non-object records and a truncated final line
// fail explicitly.
type NDJSONReader struct {
	next    func() ([]byte, error)
	maxLine int
	pending []byte
	records []map[string]any
	eof     bool
	err     error
}

// ChunkSource returns the next chunk of a stream, or io.EOF at its end.
type ChunkSource func() ([]byte, error)

// NewNDJSONReader creates a reader over chunk source next. A maxLineBytes
// of 0 uses the 1 MiB default.
func NewNDJSONReader(next ChunkSource, maxLineBytes int) (*NDJSONReader, error) {
	if maxLineBytes == 0 {
		maxLineBytes = MaxLineBytes
	}
	if maxLineBytes < 1 {
		return nil, errors.New("line limit must be positive")
	}
	return &NDJSONReader{next: next, maxLine: maxLineBytes}, nil
}

// Next returns the next record, or io.EOF when the stream is exhausted.
func (r *NDJSONReader) Next() (map[string]any, error) {
	for len(r.records) == 0 {
		if r.err != nil {
			return nil, r.err
		}
		if r.eof {
			return nil, io.EOF
		}
		if err := r.fill(); err != nil {
			r.err = err
			return nil, err
		}
	}
	record := r.records[0]
	r.records = r.records[1:]
	return record, nil
}

func (r *NDJSONReader) fill() error {
	chunk, err := r.next()
	if err == io.EOF {
		r.eof = true
		if len(r.pending) > 0 {
			return errors.New("response ended within an NDJSON record")
		}
		return nil
	}
	if err != nil {
		return err
	}
	offset := 0
	for offset < len(chunk) {
		newline := indexByte(chunk[offset:], '\n')
		var segment []byte
		if newline < 0 {
			segment = chunk[offset:]
		} else {
			segment = chunk[offset : offset+newline+1]
		}
		if len(r.pending)+len(segment) > r.maxLine {
			return errors.New("NDJSON line too large")
		}
		r.pending = append(r.pending, segment...)
		offset += len(segment)
		if newline >= 0 {
			if err := r.emitLine(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *NDJSONReader) emitLine() error {
	line := r.pending
	r.pending = nil
	if len(bytesTrimSpace(line)) == 0 {
		return nil
	}
	value, err := wirejson.Decode(line)
	if err != nil {
		return errors.New("invalid NDJSON record")
	}
	record, ok := value.(map[string]any)
	if !ok {
		return errors.New("NDJSON record must be an object")
	}
	r.records = append(r.records, record)
	return nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
