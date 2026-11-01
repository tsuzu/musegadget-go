package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"musegadget/config"
	"musegadget/executor"
	"musegadget/linkclient"
	"musegadget/noise"
	"musegadget/wirejson"
)

// fakeBackend is a minimal Muse backend for the supervisor test: the
// fetch_vms API plus a Noise VM that accepts link.register and answers
// /chat/stream.
type fakeBackend struct {
	sendMu  sync.Mutex
	send    *noise.CipherState
	recv    *noise.CipherState
	conn    *websocket.Conn
	decoder *noise.NoiseFrameDecoder
	control *controlSink
	chats   chan map[string]any
}

type controlSink struct {
	decoder *messageFeeder
	stream  int64
}

type messageFeeder struct{ buffer []byte }

func (f *messageFeeder) feed(data []byte) []map[string]any {
	f.buffer = append(f.buffer, data...)
	var messages []map[string]any
	for len(f.buffer) >= 4 {
		n := int(f.buffer[0]) | int(f.buffer[1])<<8 | int(f.buffer[2])<<16 | int(f.buffer[3])<<24
		if n == 0 {
			f.buffer = f.buffer[4:]
			continue
		}
		if len(f.buffer) < 4+n {
			break
		}
		raw := f.buffer[4 : 4+n]
		f.buffer = f.buffer[4+n:]
		if message, err := wirejson.DecodeMap(raw); err == nil {
			messages = append(messages, message)
		}
	}
	return messages
}

var wsUpgrader = websocket.Upgrader{}

func (b *fakeBackend) sendFrame(frame *noise.ServiceFrame) {
	envelope, err := noise.EncodeResponseEnvelope(frame)
	if err != nil {
		return
	}
	protoFrames, err := noise.EncodeNoiseFrames(envelope, nil)
	if err != nil {
		return
	}
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	for _, pf := range protoFrames {
		ct, err := b.send.EncryptWithAD(nil, pf)
		if err != nil {
			return
		}
		if err := b.conn.WriteMessage(websocket.BinaryMessage, ct); err != nil {
			return
		}
	}
}

func (b *fakeBackend) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	b.conn = conn
	responder := noise.NewResponder(nil)
	if err := responder.Initialize(); err != nil {
		return
	}
	_, msg1, err := conn.ReadMessage()
	if err != nil {
		return
	}
	msg2, err := responder.ReadMessage1AndWriteMessage2(msg1)
	if err != nil {
		return
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, msg2); err != nil {
		return
	}
	_, msg3, err := conn.ReadMessage()
	if err != nil {
		return
	}
	if err := responder.ReadMessage3(msg3); err != nil {
		return
	}
	b.send, b.recv, err = responder.Split()
	if err != nil {
		return
	}
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		plain, err := b.recv.DecryptWithAD(nil, raw)
		if err != nil {
			return
		}
		reassembled, err := b.decoder.Decode(plain)
		if err != nil || reassembled == nil {
			continue
		}
		frame, err := noise.DecodeRequestEnvelope(reassembled)
		if err != nil {
			continue
		}
		b.handle(frame)
	}
}

func (b *fakeBackend) handle(frame *noise.ServiceFrame) {
	switch frame.Kind {
	case noise.FrameRequest:
		switch frame.Request.Path {
		case "/link-control":
			b.control.stream = frame.StreamID
			b.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{Status: 200}))
		case "/chat/stream":
			body, _ := wirejson.DecodeMap(frame.Request.Body)
			b.chats <- body
			b.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{
				Status: 200, Body: []byte(`{}`), EndBody: true,
			}))
		default:
			b.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{Status: 404, EndBody: true}))
		}
	case noise.FrameBodyChunk:
		if frame.StreamID == b.control.stream {
			for _, message := range b.control.decoder.feed(frame.BodyChunk.Data) {
				if message["method"] == "link.register" {
					reply := wirejson.Obj{
						{Key: "id", Value: message["id"]},
						{Key: "ok", Value: true},
					}
					encoded := wirejson.MustMarshal(reply)
					frame2 := append([]byte{
						byte(len(encoded)), byte(len(encoded) >> 8),
						byte(len(encoded) >> 16), byte(len(encoded) >> 24),
					}, encoded...)
					b.sendFrame(noise.BodyChunkFrame(frame.StreamID, &noise.BodyChunk{Data: frame2}))
				}
			}
		}
	}
}

func TestServiceRunEndToEnd(t *testing.T) {
	backend := &fakeBackend{
		decoder: noise.NewNoiseFrameDecoder(),
		control: &controlSink{decoder: &messageFeeder{}},
		chats:   make(chan map[string]any, 4),
	}
	mux := http.NewServeMux()
	var wsURL string
	mux.HandleFunc("/fetch_vms", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"vm_list": [{"vm_id": "vm1", "vm_name": "fake", "vm_ws_url": %q, "vm_auth_token": "vm-token", "default": true}]}`,
			wsURL)
	})
	mux.HandleFunc("/v1/noise", backend.serveWS)
	server := httptest.NewServer(mux)
	defer server.Close()
	wsURL = "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/noise"

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "musegadget.sock")
	t.Setenv("MUSEGADGET_SOCKET", socketPath)
	pairing := map[string]any{
		"access_token":          "at",
		"refresh_token":         "rt",
		"token_type":            "device",
		"api_url_v2":            server.URL,
		"access_token_saved_at": time.Now().Unix(),
	}
	if err := config.SaveJSON(config.PairingFile, pairing, stateDir); err != nil {
		t.Fatal(err)
	}
	account := executor.Account{Name: "tester", UID: os.Getuid(), GID: os.Getgid(), Home: stateDir}
	svc := &Service{
		Identity:    testIdentity(),
		Executor:    executor.NewExecutor(account, nil),
		DisplayName: "testbox",
		StateDir:    stateDir,
		// Production sessions dial wss://<noise host>/v1/noise?vm_id=...;
		// point this one at the fake VM instead.
		SessionFactory: func(noiseHost, vmID, vmAuthToken string, device linkclient.DeviceDescription,
			runCommand linkclient.RunCommandFunc, opts ...linkclient.Option) (*linkclient.Session, error) {
			return linkclient.NewSession(noiseHost, vmID, vmAuthToken, device, runCommand,
				append(opts, linkclient.WithURL(wsURL))...)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- svc.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if session := svc.CurrentSession(); session != nil && session.RegisteredAt() != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if session := svc.CurrentSession(); session == nil || session.RegisteredAt() == nil {
		t.Fatal("service never registered")
	}
	if err := SendLocalMessage(socketPath, "hello via socket", "", nil); err != nil {
		t.Fatalf("send via local socket: %v", err)
	}
	select {
	case chat := <-backend.chats:
		// Chat requests carry the node id as device_id (reference behavior).
		if chat["device_id"] != "homelink-334455" {
			t.Fatalf("chat device_id = %v", chat["device_id"])
		}
		if raw := string(wirejson.MustMarshal(chat)); !strings.Contains(raw, "hello via socket") {
			t.Fatalf("chat body = %s", raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VM never received the chat")
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("service run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("service did not stop")
	}
}
