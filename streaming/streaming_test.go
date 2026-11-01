package streaming

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"musegadget/noise"
)

type fakeSession struct {
	transport    *noise.Transport
	sent         [][]byte
	unregistered []int64
}

func (s *fakeSession) SendEncrypted(encrypt func() ([][]byte, error), check func() error) error {
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	frames, err := encrypt()
	if err != nil {
		return err
	}
	s.sent = append(s.sent, frames...)
	return nil
}

func (s *fakeSession) Transport() *noise.Transport { return s.transport }

func (s *fakeSession) UnregisterRequest(streamID int64) {
	s.unregistered = append(s.unregistered, streamID)
}

func transportPair(t *testing.T) (*noise.Transport, *noise.CipherState) {
	t.Helper()
	initiator := noise.NewInitiator()
	responder := noise.NewResponder(nil)
	if err := initiator.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := responder.Initialize(); err != nil {
		t.Fatal(err)
	}
	m1, err := initiator.WriteMessage1()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := responder.ReadMessage1AndWriteMessage2(m1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.ReadMessage2(m2); err != nil {
		t.Fatal(err)
	}
	m3, err := initiator.WriteMessage3()
	if err != nil {
		t.Fatal(err)
	}
	if err := responder.ReadMessage3(m3); err != nil {
		t.Fatal(err)
	}
	isend, irecv, err := initiator.Split()
	if err != nil {
		t.Fatal(err)
	}
	_, rrecv, err := responder.Split()
	if err != nil {
		t.Fatal(err)
	}
	return noise.NewTransport(isend, irecv), rrecv
}

// decodeSent decrypts everything the session sent and returns the frames.
func decodeSent(t *testing.T, session *fakeSession, serverRecv *noise.CipherState) []*noise.ServiceFrame {
	t.Helper()
	decoder := noise.NewNoiseFrameDecoder()
	var frames []*noise.ServiceFrame
	for _, ct := range session.sent {
		plain, err := serverRecv.DecryptWithAD(nil, ct)
		if err != nil {
			t.Fatal(err)
		}
		reassembled, err := decoder.Decode(plain)
		if err != nil {
			t.Fatal(err)
		}
		if reassembled == nil {
			continue
		}
		frame, err := noise.DecodeRequestEnvelope(reassembled)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	session.sent = nil
	return frames
}

func responseFrame(status int32, body string, end bool) *noise.DecryptedFrame {
	return &noise.DecryptedFrame{Kind: noise.FrameResponse, StreamID: 7,
		Response: &noise.ApplicationResponse{Status: status, Body: []byte(body), EndBody: end}}
}

func chunkFrame(data string, end bool) *noise.DecryptedFrame {
	return &noise.DecryptedFrame{Kind: noise.FrameBodyChunk, StreamID: 7,
		BodyChunk: &noise.BodyChunk{Data: []byte(data), EndBody: end}}
}

func TestStreamingRequestResponseFlow(t *testing.T) {
	ctx := context.Background()
	session := &fakeSession{}
	req := New(session, 7, MaxBufferBytes, MaxBufferChunks)
	req.OnFrame(responseFrame(200, "he", false))
	req.OnFrame(chunkFrame("llo", true))
	status, err := req.WaitResponse(ctx)
	if err != nil || status != 200 {
		t.Fatalf("WaitResponse = %d, %v", status, err)
	}
	var got []byte
	for {
		chunk, err := req.Read(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, chunk...)
	}
	if string(got) != "hello" {
		t.Fatalf("body = %q", got)
	}
	if !req.Ended() {
		t.Fatal("not ended")
	}
}

func TestStreamingRequestStatusErrorDrainsBody(t *testing.T) {
	ctx := context.Background()
	req := New(&fakeSession{}, 7, MaxBufferBytes, MaxBufferChunks)
	req.OnFrame(responseFrame(500, "oo", false))
	req.OnFrame(chunkFrame("ps", true))
	_, err := req.WaitResponse(ctx)
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("err = %v", err)
	}
	if httpErr.Status != 500 || string(httpErr.Body) != "oops" {
		t.Fatalf("HTTPStatusError = %+v", httpErr)
	}
	if httpErr.Error() != "request refused: HTTP 500" {
		t.Fatalf("message = %q", httpErr.Error())
	}
}

func TestStreamingRequestBufferFull(t *testing.T) {
	ctx := context.Background()
	req := New(&fakeSession{}, 7, 4, MaxBufferChunks)
	req.OnFrame(responseFrame(200, "12345", false))
	if _, err := req.Read(ctx); err == nil || !strings.Contains(err.Error(), "buffer full") {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamingRequestBodyBeforeHead(t *testing.T) {
	ctx := context.Background()
	req := New(&fakeSession{}, 7, MaxBufferBytes, MaxBufferChunks)
	req.OnFrame(chunkFrame("x", false))
	if _, err := req.Read(ctx); err == nil || !strings.Contains(err.Error(), "before head") {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamingRequestSendAndClose(t *testing.T) {
	clientTransport, serverRecv := transportPair(t)
	session := &fakeSession{transport: clientTransport}
	req := New(session, 7, MaxBufferBytes, MaxBufferChunks)

	if err := req.SendBody([]byte("abc"), false, nil); err != nil {
		t.Fatal(err)
	}
	frames := decodeSent(t, session, serverRecv)
	if len(frames) != 1 || frames[0].Kind != noise.FrameBodyChunk || frames[0].StreamID != 7 ||
		string(frames[0].BodyChunk.Data) != "abc" || frames[0].BodyChunk.EndBody {
		t.Fatalf("frames = %+v", frames)
	}
	if err := req.SendBody(make([]byte, MaxSendBytes+1), false, nil); err == nil {
		t.Fatal("oversize chunk accepted")
	}
	if err := req.HalfClose(); err != nil {
		t.Fatal(err)
	}
	frames = decodeSent(t, session, serverRecv)
	if len(frames) != 1 || !frames[0].BodyChunk.EndBody || len(frames[0].BodyChunk.Data) != 0 {
		t.Fatalf("half-close frames = %+v", frames)
	}
	if err := req.SendBody([]byte("x"), false, nil); err == nil {
		t.Fatal("send after half-close accepted")
	}
	// Not ended on the response side: Close must reset the stream.
	if err := req.Close(); err != nil {
		t.Fatal(err)
	}
	frames = decodeSent(t, session, serverRecv)
	if len(frames) != 1 || frames[0].Kind != noise.FrameReset ||
		frames[0].Reset.Reason != "client closed stream" || frames[0].Reset.Code != noise.ResetCancelled {
		t.Fatalf("close frames = %+v", frames)
	}
	if len(session.unregistered) != 1 || session.unregistered[0] != 7 {
		t.Fatalf("unregistered = %v", session.unregistered)
	}
	// A second Close is a no-op.
	if err := req.Close(); err != nil {
		t.Fatal(err)
	}
	if frames := decodeSent(t, session, serverRecv); len(frames) != 0 {
		t.Fatalf("second close sent %+v", frames)
	}
}

func TestStreamingRequestCloseAfterEndSendsNoReset(t *testing.T) {
	clientTransport, serverRecv := transportPair(t)
	session := &fakeSession{transport: clientTransport}
	req := New(session, 7, MaxBufferBytes, MaxBufferChunks)
	if err := req.SendBody([]byte("done"), true, nil); err != nil {
		t.Fatal(err)
	}
	decodeSent(t, session, serverRecv)
	req.OnFrame(responseFrame(200, "", true))
	if err := req.Close(); err != nil {
		t.Fatal(err)
	}
	if frames := decodeSent(t, session, serverRecv); len(frames) != 0 {
		t.Fatalf("close after end sent %+v", frames)
	}
}

func chunkSource(chunks ...[]byte) ChunkSource {
	queue := append([][]byte(nil), chunks...)
	return func() ([]byte, error) {
		if len(queue) == 0 {
			return nil, io.EOF
		}
		chunk := queue[0]
		queue = queue[1:]
		return chunk, nil
	}
}

func TestNDJSONReader(t *testing.T) {
	reader, err := NewNDJSONReader(chunkSource(
		[]byte("{\"a\":1}\n{\"b\":"),
		[]byte("2}\r\n\n{\"c\":3}\n"),
	), 0)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for {
		record, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for k := range record {
			keys = append(keys, k)
		}
	}
	if strings.Join(keys, ",") != "a,b,c" {
		t.Fatalf("keys = %v", keys)
	}
}

func TestNDJSONReaderErrors(t *testing.T) {
	cases := []struct {
		name    string
		chunks  [][]byte
		maxLine int
		want    string
	}{
		{"truncated", [][]byte{[]byte("{\"a\":1}")}, 0, "response ended within an NDJSON record"},
		{"invalid", [][]byte{[]byte("{nope}\n")}, 0, "invalid NDJSON record"},
		{"non-object", [][]byte{[]byte("[1,2]\n")}, 0, "NDJSON record must be an object"},
		{"too large", [][]byte{[]byte("{\"aaaaaaaaaa\":1}\n")}, 8, "NDJSON line too large"},
	}
	for _, tc := range cases {
		reader, err := NewNDJSONReader(chunkSource(tc.chunks...), tc.maxLine)
		if err != nil {
			t.Fatal(err)
		}
		for {
			_, err = reader.Next()
			if err != nil {
				break
			}
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := NewNDJSONReader(chunkSource(), -1); err == nil {
		t.Error("negative line limit accepted")
	}
}
