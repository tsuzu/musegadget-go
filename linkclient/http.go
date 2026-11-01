package linkclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"musegadget/noise"
	"musegadget/streaming"
	"musegadget/wirejson"
)

// pendingRequest collects the response to one request stream.
type pendingRequest struct {
	done     chan struct{}
	mu       sync.Mutex
	finished bool
	status   int
	body     []byte
	err      error
}

func newPendingRequest() *pendingRequest {
	return &pendingRequest{done: make(chan struct{})}
}

func (r *pendingRequest) Fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return
	}
	r.finished = true
	r.err = err
	close(r.done)
}

func (r *pendingRequest) OnFrame(frame *noise.DecryptedFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return
	}
	fail := func(err error) {
		r.finished = true
		r.err = err
		close(r.done)
	}
	if frame.Kind == noise.FrameReset {
		fail(fmt.Errorf("stream reset: %s", frame.Reset.Reason))
		return
	}
	var data []byte
	var ended bool
	if frame.Kind == noise.FrameResponse {
		if r.status != 0 || frame.Response.Status < 100 || frame.Response.Status > 599 {
			fail(errors.New("invalid or duplicate response head"))
			return
		}
		r.status = int(frame.Response.Status)
		data, ended = frame.Response.Body, frame.Response.EndBody
	} else if frame.Kind == noise.FrameBodyChunk && r.status != 0 {
		data, ended = frame.BodyChunk.Data, frame.BodyChunk.EndBody
	} else {
		fail(errors.New("response body before head"))
		return
	}
	if len(r.body)+len(data) > MaxResponseBytes {
		fail(errors.New("response too large"))
		return
	}
	r.body = append(r.body, data...)
	if ended {
		r.finished = true
		close(r.done)
	}
}

// httpHeaders adds the headers every device-originated HTTP request
// carries: a request id and the app id.
func (s *Session) httpHeaders(headers []noise.Header) []noise.Header {
	out := append([]noise.Header(nil), headers...)
	out = append(out,
		noise.Header{Key: "x-request-id", Value: newUUID()},
		noise.Header{Key: "x-app-id", Value: AppID},
	)
	return out
}

// Request performs a buffered request for small JSON replies, including
// call cleanup. The result is {"ok", "status", "response"}.
func (s *Session) Request(ctx context.Context, method, path string, body []byte,
	headers []noise.Header, timeout time.Duration) (map[string]any, error) {
	if timeout == 0 {
		timeout = RequestTimeout
	}
	return s.doRequest(ctx, method, path, body, headers, timeout)
}

func (s *Session) doRequest(ctx context.Context, method, path string, body []byte,
	headers []noise.Header, timeout time.Duration) (map[string]any, error) {
	uploadInParts := len(body) > MaxInlineRequestBytes
	request := newPendingRequest()
	var streamID int64
	haveStream := false

	encrypt := func() (*noise.EncryptedFrames, error) {
		var encrypted *noise.EncryptedFrames
		var err error
		if uploadInParts {
			encrypted, err = s.Transport().StartStreamRequest(method, path, nil, headers)
		} else {
			encrypted, err = s.Transport().EncryptHTTPRequest(method, path, body, nil, headers)
		}
		if err != nil {
			return nil, err
		}
		streamID = encrypted.StreamID
		haveStream = true
		s.requestsMu.Lock()
		s.requests[streamID] = request
		s.requestsMu.Unlock()
		return encrypted, nil
	}

	completed := false
	defer func() {
		if haveStream {
			s.requestsMu.Lock()
			delete(s.requests, streamID)
			s.requestsMu.Unlock()
		}
		if !completed && haveStream && !s.isClosed() {
			resetCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = s.SendEncrypted(func() ([][]byte, error) {
					return s.Transport().EncryptReset(streamID, "request ended")
				}, nil)
			}()
			select {
			case <-done:
			case <-resetCtx.Done():
			}
		}
	}()

	if _, err := s.sendEncryptedRequest(encrypt, nil); err != nil {
		return nil, err
	}
	if uploadInParts {
		for offset := 0; offset < len(body); offset += RequestChunkBytes {
			end := offset + RequestChunkBytes
			if end > len(body) {
				end = len(body)
			}
			part := body[offset:end]
			last := end == len(body)
			if err := s.SendEncrypted(func() ([][]byte, error) {
				return s.Transport().EncryptBodyChunk(streamID, part, nil, last)
			}, nil); err != nil {
				return nil, err
			}
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-request.done:
	case <-waitCtx.Done():
		return nil, waitCtx.Err()
	}
	if request.err != nil {
		return nil, request.err
	}
	completed = true
	status, response := request.status, request.body
	var decoded any
	if len(response) > 0 {
		if value, err := wirejson.Decode(response); err == nil {
			decoded = value
		} else {
			decoded = truncateRunes(toValidUTF8(string(response)), 2000)
		}
	}
	return map[string]any{
		"ok":       status >= 200 && status < 300,
		"status":   status,
		"response": decoded,
	}, nil
}

func toValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// -- Device-originated chat requests ----------------------------------------

// SendChat posts a user message to the Muse as coming from this device.
// sessionID targets a side chat; empty goes to the main chat.
func (s *Session) SendChat(ctx context.Context, message, sessionID, outputModality string) (map[string]any, error) {
	if outputModality == "" {
		outputModality = "text"
	}
	body := wirejson.Obj{
		{Key: "message", Value: message},
		{Key: "output_modality", Value: outputModality},
		{Key: "device_id", Value: s.device.NodeID},
	}
	if sessionID != "" {
		body = append(body, wirejson.Pair{Key: "session_id", Value: sessionID})
	}
	return s.postChat(ctx, body)
}

// SendVoice posts a WAV voice note, optionally with instructions in
// message. outputModality is sent only when non-empty.
func (s *Session) SendVoice(ctx context.Context, wavBytes []byte, sessionID, message, outputModality string) (map[string]any, error) {
	if len(wavBytes) == 0 || len(wavBytes) > MaxVoiceBytes {
		return nil, errors.New("voice note must contain at most 2 MiB of WAV audio")
	}
	items := []any{}
	if strings.TrimSpace(message) != "" {
		items = append(items, wirejson.Obj{
			{Key: "type", Value: "text"},
			{Key: "text", Value: message},
		})
	}
	items = append(items, wirejson.Obj{
		{Key: "type", Value: "file"},
		{Key: "mime_type", Value: "audio/wav"},
		{Key: "filename", Value: "voice_note.wav"},
		{Key: "data_base64", Value: base64.StdEncoding.EncodeToString(wavBytes)},
	})
	body := wirejson.Obj{
		{Key: "message", Value: message},
		{Key: "device_id", Value: s.device.NodeID},
		{Key: "items", Value: items},
	}
	if sessionID != "" {
		body = append(body, wirejson.Pair{Key: "session_id", Value: sessionID})
	}
	if outputModality != "" {
		body = append(body, wirejson.Pair{Key: "output_modality", Value: outputModality})
	}
	return s.postChat(ctx, body)
}

// SendImage posts a picture for Muse to look at, with message as its text.
func (s *Session) SendImage(ctx context.Context, imageBytes []byte, mimeType, sessionID, message, filename, outputModality string) (map[string]any, error) {
	if err := CheckImage(imageBytes, mimeType); err != nil {
		return nil, err
	}
	if outputModality == "" {
		outputModality = "text"
	}
	image := wirejson.Obj{
		{Key: "type", Value: "image"},
		{Key: "mime_type", Value: mimeType},
		{Key: "data_base64", Value: base64.StdEncoding.EncodeToString(imageBytes)},
	}
	if filename != "" {
		image = append(image, wirejson.Pair{Key: "filename", Value: filename})
	}
	items := []any{}
	if strings.TrimSpace(message) != "" {
		items = append(items, wirejson.Obj{
			{Key: "type", Value: "text"},
			{Key: "text", Value: message},
		})
	}
	items = append(items, image)
	body := wirejson.Obj{
		{Key: "message", Value: message},
		{Key: "output_modality", Value: outputModality},
		{Key: "device_id", Value: s.device.NodeID},
		{Key: "items", Value: items},
	}
	if sessionID != "" {
		body = append(body, wirejson.Pair{Key: "session_id", Value: sessionID})
	}
	return s.postChat(ctx, body)
}

func (s *Session) postChat(ctx context.Context, requestBody wirejson.Obj) (map[string]any, error) {
	if !s.isRunning() {
		return nil, errors.New("Muse session is not connected")
	}
	encoded := wirejson.MustMarshal(requestBody)
	return s.doRequest(ctx, "POST", ChatPath, encoded,
		s.httpHeaders([]noise.Header{{Key: "Content-Type", Value: "application/json"}}),
		RequestTimeout)
}

// RequestRejected reports that Muse refused a conversation request.
type RequestRejected struct{ Status *int }

func (e *RequestRejected) Error() string {
	if e.Status == nil {
		return "Muse rejected conversation request: HTTP <nil>"
	}
	return fmt.Sprintf("Muse rejected conversation request: HTTP %d", *e.Status)
}

// Acknowledgement returns Muse's acknowledgement in a SendChat, SendVoice
// or SendImage result, raising RequestRejected when Muse refused the
// request and a plain error when it accepted without an acknowledgement.
func Acknowledgement(result map[string]any) (map[string]any, error) {
	if ok, _ := result["ok"].(bool); !ok {
		var status *int
		if raw, present := result["status"]; present {
			if value, ok := wirejson.AsInt64(raw); ok {
				v := int(value)
				status = &v
			}
		}
		return nil, &RequestRejected{Status: status}
	}
	response, ok := result["response"].(map[string]any)
	if !ok {
		return nil, errors.New("Muse did not acknowledge the request")
	}
	return response, nil
}

// -- HTTP response streams ----------------------------------------------------

// HttpStreamError reports that Muse refused an HTTP request carried by
// the Noise session.
type HttpStreamError struct {
	Status int
	Path   string
}

func (e *HttpStreamError) Error() string {
	return fmt.Sprintf("Muse request %s failed: HTTP %d", e.Path, e.Status)
}

// httpStream is a response stream with headers and bounded byte chunks
// dispatched by the reader.
type httpStream struct {
	Status  int
	Headers []noise.Header

	mu             sync.Mutex
	changed        chan struct{}
	readySet       bool
	readyErr       error
	ended          bool
	resetRequested bool
	finished       bool
	chunks         [][]byte
	buffered       int
	err            error
	maxBuffer      int
}

func newHTTPStream(maxBuffer int) *httpStream {
	return &httpStream{changed: make(chan struct{}), maxBuffer: maxBuffer}
}

func (s *httpStream) signalLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// onFrame returns false when the session should reset this stream
// (consumer fell behind, or body arrived before headers).
func (s *httpStream) onFrame(frame *noise.DecryptedFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return true
	}
	if frame.Kind == noise.FrameReset {
		s.ended = true
		s.failLocked(errors.New("Muse response stream reset"))
		return true
	}
	var data []byte
	var ended bool
	if frame.Kind == noise.FrameResponse {
		s.Status = int(frame.Response.Status)
		s.Headers = frame.Response.Headers
		if !s.readySet {
			s.readySet = true
		}
		s.signalLocked()
		data, ended = frame.Response.Body, frame.Response.EndBody
	} else {
		if !s.readySet {
			s.failLocked(errors.New("Muse response body arrived without headers"))
			return false
		}
		data, ended = frame.BodyChunk.Data, frame.BodyChunk.EndBody
	}
	if len(data) > 0 {
		if s.buffered+len(data) > s.maxBuffer {
			s.failLocked(errors.New("Muse response consumer fell behind"))
			return false
		}
		s.buffered += len(data)
		offset := 0
		if len(s.chunks) > 0 && len(s.chunks[len(s.chunks)-1]) < StreamChunkBytes {
			last := len(s.chunks) - 1
			take := StreamChunkBytes - len(s.chunks[last])
			if take > len(data) {
				take = len(data)
			}
			s.chunks[last] = append(s.chunks[last], data[:take]...)
			offset = take
		}
		for offset < len(data) {
			end := offset + StreamChunkBytes
			if end > len(data) {
				end = len(data)
			}
			s.chunks = append(s.chunks, append([]byte(nil), data[offset:end]...))
			offset = end
		}
		s.signalLocked()
	}
	if ended {
		s.ended = true
		s.finished = true
		s.signalLocked()
	}
	return true
}

func (s *httpStream) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(err)
}

func (s *httpStream) failLocked(err error) {
	if s.finished {
		return
	}
	s.finished = true
	if !s.readySet {
		s.readySet = true
		s.readyErr = err
	}
	s.chunks = nil
	s.buffered = 0
	s.err = err
	s.signalLocked()
}

func (s *httpStream) closeInternal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readySet {
		s.readySet = true
		s.readyErr = errors.New("stream closed before response")
	}
	s.finished = true
	s.err = nil
	s.chunks = nil
	s.buffered = 0
	s.signalLocked()
}

// Ready waits for the response head.
func (s *httpStream) Ready(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.readySet {
			err := s.readyErr
			s.mu.Unlock()
			return err
		}
		if s.finished {
			err := s.err
			s.mu.Unlock()
			if err != nil {
				return err
			}
			return errors.New("stream closed before response")
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Next returns the next buffered chunk, or io.EOF at the end.
func (s *httpStream) Next(ctx context.Context) ([]byte, error) {
	for {
		s.mu.Lock()
		if len(s.chunks) > 0 {
			chunk := s.chunks[0]
			s.chunks = s.chunks[1:]
			s.buffered -= len(chunk)
			s.mu.Unlock()
			return chunk, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return nil, err
		}
		if s.finished {
			s.mu.Unlock()
			return nil, io.EOF
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// HTTPStream is a live response stream from StreamHTTP. Read chunks with
// Next, then Close.
type HTTPStream struct {
	*httpStream
	session  *Session
	streamID int64
	closed   bool
}

// Close cancels the request if it has not ended, as the reference's
// context manager exit does.
func (s *HTTPStream) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.session.requestsMu.Lock()
	delete(s.session.streams, s.streamID)
	s.session.requestsMu.Unlock()
	s.mu.Lock()
	ended, resetRequested := s.ended, s.resetRequested
	s.mu.Unlock()
	if !ended && !resetRequested {
		s.resetRequested = true
		s.session.resetStream(s.streamID)
	}
	s.closeInternal()
}

func (s *Session) resetStream(streamID int64) {
	if !s.isRunning() {
		return
	}
	if err := s.SendEncrypted(func() ([][]byte, error) {
		return s.Transport().EncryptReset(streamID, "consumer closed")
	}, nil); err != nil {
		log.Printf("musegadget: could not cancel closed Muse stream: %v", err)
	}
}

// StreamHTTP opens a bounded HTTP response stream; the response status and
// headers are available on the returned stream. Closing it cancels its
// request. Consumers read chunks without holding up the control stream.
func (s *Session) StreamHTTP(ctx context.Context, method, path string, body []byte,
	headers []noise.Header, maxBufferBytes int) (*HTTPStream, error) {
	if maxBufferBytes == 0 {
		maxBufferBytes = MaxStreamBufferBytes
	}
	if !s.isRunning() {
		return nil, errors.New("Muse session is not connected")
	}
	stream := newHTTPStream(maxBufferBytes)
	var streamID int64
	encrypt := func() (*noise.EncryptedFrames, error) {
		encrypted, err := s.Transport().EncryptHTTPRequest(method, path, body, nil, s.httpHeaders(headers))
		if err != nil {
			return nil, err
		}
		streamID = encrypted.StreamID
		s.requestsMu.Lock()
		s.streams[streamID] = stream
		s.requestsMu.Unlock()
		return encrypted, nil
	}
	handle := &HTTPStream{httpStream: stream, session: s}
	if _, err := s.sendEncryptedRequest(encrypt, nil); err != nil {
		return nil, err
	}
	handle.streamID = streamID
	readyCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	if err := stream.Ready(readyCtx); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

// OpenSideChat looks up the side chat sessionID without reading its events.
func (s *Session) OpenSideChat(ctx context.Context, sessionID string) (SideChat, error) {
	path := "/chat/subscribe"
	body := wirejson.MustMarshal(wirejson.Obj{{Key: "session_id", Value: sessionID}})
	stream, err := s.StreamHTTP(ctx, "POST", path, body, []noise.Header{
		{Key: "Content-Type", Value: "application/json"},
		{Key: "Accept", Value: "application/x-ndjson"},
	}, MaxStreamBufferBytes)
	if err != nil {
		return SideChat{}, err
	}
	defer stream.Close()
	if stream.Status >= 200 && stream.Status < 300 {
		return SideChat{SessionID: sessionID, Exists: true}, nil
	}
	if stream.Status == 404 {
		return SideChat{SessionID: sessionID, Exists: false}, nil
	}
	return SideChat{}, &HttpStreamError{Status: stream.Status, Path: path}
}

// ChatSubscription is an active /chat/subscribe NDJSON stream.
type ChatSubscription struct {
	stream  *HTTPStream
	session *Session
	pending []byte
	queue   []map[string]any
	eof     bool
}

// SubscribeChat subscribes to Muse chat events (NDJSON). Only events
// (JSON objects with type == "event") are delivered.
func (s *Session) SubscribeChat(ctx context.Context, sessionID string) (*ChatSubscription, error) {
	path := "/chat/subscribe"
	bodyObj := wirejson.Obj{}
	if sessionID != "" {
		bodyObj = append(bodyObj, wirejson.Pair{Key: "session_id", Value: sessionID})
	}
	stream, err := s.StreamHTTP(ctx, "POST", path, wirejson.MustMarshal(bodyObj), []noise.Header{
		{Key: "Content-Type", Value: "application/json"},
		{Key: "Accept", Value: "application/x-ndjson"},
	}, MaxStreamBufferBytes)
	if err != nil {
		return nil, err
	}
	if stream.Status < 200 || stream.Status >= 300 {
		stream.Close()
		return nil, &HttpStreamError{Status: stream.Status, Path: path}
	}
	s.setChatSubscribed(true)
	return &ChatSubscription{stream: stream, session: s}, nil
}

// Next returns the next chat event, or io.EOF at the end of the stream.
func (c *ChatSubscription) Next(ctx context.Context) (map[string]any, error) {
	for len(c.queue) == 0 {
		if c.eof {
			return nil, io.EOF
		}
		chunk, err := c.stream.Next(ctx)
		if err == io.EOF {
			c.eof = true
			if len(c.pending) > 0 {
				if event := chatEvent(c.pending); event != nil {
					c.queue = append(c.queue, event)
				}
				c.pending = nil
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		c.pending = append(c.pending, chunk...)
		if len(c.pending) > MaxChatEventBytes {
			return nil, errors.New("Muse chat event exceeds 256 KiB")
		}
		for {
			idx := indexByte(c.pending, '\n')
			if idx < 0 {
				break
			}
			line := c.pending[:idx+1]
			c.pending = c.pending[idx+1:]
			if event := chatEvent(line); event != nil {
				c.queue = append(c.queue, event)
			}
			if len(c.pending) > MaxChatEventBytes {
				return nil, errors.New("Muse chat event exceeds 256 KiB")
			}
		}
	}
	event := c.queue[0]
	c.queue = c.queue[1:]
	return event, nil
}

// Close ends the subscription.
func (c *ChatSubscription) Close() {
	c.session.setChatSubscribed(false)
	c.stream.Close()
}

func chatEvent(raw []byte) map[string]any {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	value, err := wirejson.Decode(raw)
	if err != nil {
		log.Printf("musegadget: dropping malformed chat event (%d bytes)", len(raw))
		return nil
	}
	event, ok := value.(map[string]any)
	if !ok || event["type"] != "event" {
		return nil
	}
	return event
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// StreamTTS opens the MP3 stream for a voice-modality assistant reply,
// with the legacy path fallback on 404.
func (s *Session) StreamTTS(ctx context.Context, messageID string) (*HTTPStream, error) {
	encodedID := quoteURIComponent(messageID, uriComponentSafe)
	for _, prefix := range []string{"/api/voice/tts-stream", "/voice/tts-stream"} {
		path := prefix + "?message_id=" + encodedID
		stream, err := s.StreamHTTP(ctx, "GET", path, nil, []noise.Header{
			{Key: "Accept", Value: "audio/mpeg"},
		}, MaxTTSBufferBytes)
		if err != nil {
			return nil, err
		}
		if stream.Status == 404 && prefix == "/api/voice/tts-stream" {
			stream.Close()
			continue
		}
		if stream.Status < 200 || stream.Status >= 300 {
			stream.Close()
			return nil, &HttpStreamError{Status: stream.Status, Path: prefix}
		}
		return stream, nil
	}
	return nil, errors.New("unreachable")
}

// StreamRequest opens a duplex streaming request on the session, as
// musegadget.streaming consumers use it.
func (s *Session) StreamRequest(ctx context.Context, method, path string, headers []noise.Header,
	maxBufferBytes, maxBufferChunks int) (*streaming.StreamingRequest, error) {
	if maxBufferBytes == 0 {
		maxBufferBytes = streaming.MaxBufferBytes
	}
	if maxBufferChunks == 0 {
		maxBufferChunks = streaming.MaxBufferChunks
	}
	if maxBufferBytes < 1 || maxBufferChunks < 1 {
		return nil, errors.New("stream limits must be positive")
	}
	var stream *streaming.StreamingRequest
	encrypt := func() (*noise.EncryptedFrames, error) {
		encrypted, err := s.Transport().StartStreamRequest(method, path, nil, headers)
		if err != nil {
			return nil, err
		}
		stream = streaming.New(s, encrypted.StreamID, maxBufferBytes, maxBufferChunks)
		s.requestsMu.Lock()
		s.requests[encrypted.StreamID] = stream
		s.requestsMu.Unlock()
		return encrypted, nil
	}
	if _, err := s.sendEncryptedRequest(encrypt, nil); err != nil {
		if stream != nil {
			s.UnregisterRequest(stream.StreamID)
		}
		return nil, err
	}
	return stream, nil
}
