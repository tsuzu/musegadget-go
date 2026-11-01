package linkclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"musegadget/noise"
	"musegadget/wirejson"
)

// fakeVM is a minimal Muse VM: it upgrades, runs the Noise responder
// handshake, and speaks the service envelope, so the client is exercised
// end to end over a real WebSocket.
type fakeVM struct {
	t    *testing.T
	conn *websocket.Conn
	send *noise.CipherState
	recv *noise.CipherState

	writeMu         sync.Mutex
	decoder         *noise.NoiseFrameDecoder
	controlDecoder  *MessageDecoder
	controlStreamID int64

	registers chan map[string]any
	results   chan map[string]any
	chatReqs  chan map[string]any
	resets    chan int64
}

var upgrader = websocket.Upgrader{}

func newFakeVM(t *testing.T) (*fakeVM, *httptest.Server) {
	t.Helper()
	vm := &fakeVM{
		t:              t,
		decoder:        noise.NewNoiseFrameDecoder(),
		controlDecoder: &MessageDecoder{},
		registers:      make(chan map[string]any, 4),
		results:        make(chan map[string]any, 4),
		chatReqs:       make(chan map[string]any, 4),
		resets:         make(chan int64, 4),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vm-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		vm.conn = conn
		go vm.serve()
	}))
	return vm, server
}

func (vm *fakeVM) serve() {
	responder := noise.NewResponder(nil)
	if err := responder.Initialize(); err != nil {
		return
	}
	_, msg1, err := vm.conn.ReadMessage()
	if err != nil {
		return
	}
	msg2, err := responder.ReadMessage1AndWriteMessage2(msg1)
	if err != nil {
		return
	}
	if err := vm.conn.WriteMessage(websocket.BinaryMessage, msg2); err != nil {
		return
	}
	_, msg3, err := vm.conn.ReadMessage()
	if err != nil {
		return
	}
	if err := responder.ReadMessage3(msg3); err != nil {
		return
	}
	vm.send, vm.recv, err = responder.Split()
	if err != nil {
		return
	}
	for {
		_, raw, err := vm.conn.ReadMessage()
		if err != nil {
			return
		}
		plain, err := vm.recv.DecryptWithAD(nil, raw)
		if err != nil {
			return
		}
		reassembled, err := vm.decoder.Decode(plain)
		if err != nil || reassembled == nil {
			continue
		}
		frame, err := noise.DecodeRequestEnvelope(reassembled)
		if err != nil {
			continue
		}
		vm.handleFrame(frame)
	}
}

func (vm *fakeVM) sendFrame(frame *noise.ServiceFrame) {
	envelope, err := noise.EncodeResponseEnvelope(frame)
	if err != nil {
		return
	}
	protoFrames, err := noise.EncodeNoiseFrames(envelope, nil)
	if err != nil {
		return
	}
	vm.writeMu.Lock()
	defer vm.writeMu.Unlock()
	for _, pf := range protoFrames {
		ct, err := vm.send.EncryptWithAD(nil, pf)
		if err != nil {
			return
		}
		if err := vm.conn.WriteMessage(websocket.BinaryMessage, ct); err != nil {
			return
		}
	}
}

func (vm *fakeVM) handleFrame(frame *noise.ServiceFrame) {
	switch frame.Kind {
	case noise.FrameRequest:
		switch frame.Request.Path {
		case ControlPath:
			vm.controlStreamID = frame.StreamID
			vm.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{Status: 200}))
		case ChatPath:
			var body map[string]any
			_ = json.Unmarshal(frame.Request.Body, &body)
			vm.chatReqs <- body
			vm.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{
				Status: 200, Body: []byte(`{"replied":true}`), EndBody: true,
			}))
		case "/chat/subscribe":
			vm.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{Status: 200}))
			events := []byte("{\"type\":\"event\",\"n\":1}\n{\"type\":\"other\"}\n{\"type\":\"event\",\"n\":2}\n")
			vm.sendFrame(noise.BodyChunkFrame(frame.StreamID, &noise.BodyChunk{Data: events}))
			vm.sendFrame(noise.BodyChunkFrame(frame.StreamID, &noise.BodyChunk{EndBody: true}))
		default:
			vm.sendFrame(noise.ResponseFrame(frame.StreamID, &noise.ApplicationResponse{Status: 404, EndBody: true}))
		}
	case noise.FrameBodyChunk:
		if frame.StreamID == vm.controlStreamID {
			messages, err := vm.controlDecoder.Feed(frame.BodyChunk.Data)
			if err != nil {
				return
			}
			for _, message := range messages {
				switch message["method"] {
				case "link.register":
					params, _ := message["params"].(map[string]any)
					vm.registers <- params
					reply, _ := EncodeMessage(map[string]any{"id": message["id"], "ok": true})
					vm.sendFrame(noise.BodyChunkFrame(frame.StreamID, &noise.BodyChunk{Data: reply}))
				case "link.result":
					vm.results <- message
				}
			}
		}
	case noise.FrameReset:
		vm.resets <- frame.StreamID
	}
}

// sendControl queues a raw control message to the client.
func (vm *fakeVM) sendControl(message map[string]any) {
	encoded, err := EncodeMessage(message)
	if err != nil {
		vm.t.Fatalf("encode control: %v", err)
	}
	vm.sendFrame(noise.BodyChunkFrame(vm.controlStreamID, &noise.BodyChunk{Data: encoded}))
}

func runCommandStub(name string, params map[string]any, timeoutMs *int64) map[string]any {
	if name == "device.health" {
		return map[string]any{"ok": true, "payload": map[string]any{"version": "0.1.0"}}
	}
	return map[string]any{"ok": false, "error": "unsupported command: " + name}
}

func TestSessionEndToEnd(t *testing.T) {
	vm, server := newFakeVM(t)
	defer server.Close()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/noise?vm_id=test-vm"

	device := DeviceDescription{
		NodeID: "homelink-000001", DisplayName: "testbox", Version: "0.1.0",
		Commands: map[string]any{},
	}
	session, err := NewSession("unused", "test-vm", "vm-token", device, runCommandStub, WithURL(url))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct {
		outcome Outcome
		err     error
	}, 1)
	go func() {
		outcome, err := session.Run(ctx)
		runDone <- struct {
			outcome Outcome
			err     error
		}{outcome, err}
	}()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := session.WaitRegistered(waitCtx); err != nil {
		t.Fatalf("wait registered: %v", err)
	}
	select {
	case params := <-vm.registers:
		if params["platform"] != "linux" || params["device_family"] != "homehub" ||
			params["node_id"] != "homelink-000001" || params["model_id"] != "linux" {
			t.Fatalf("register params = %v", params)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VM never saw link.register")
	}

	// send_chat round trip.
	result, err := session.SendChat(context.Background(), "hello Muse", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result["ok"] != true || result["status"] != 200 {
		t.Fatalf("send_chat result = %v", result)
	}
	ack, err := Acknowledgement(result)
	if err != nil || ack["replied"] != true {
		t.Fatalf("ack = %v, %v", ack, err)
	}
	select {
	case body := <-vm.chatReqs:
		if body["message"] != "hello Muse" || body["device_id"] != "homelink-000001" ||
			body["output_modality"] != "text" {
			t.Fatalf("chat body = %v", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VM never saw /chat/stream")
	}

	// link.invoke for a real command.
	vm.sendControl(map[string]any{
		"method": "link.invoke", "id": "inv-1", "command": "device.health",
		"params": map[string]any{},
	})
	select {
	case result := <-vm.results:
		if result["id"] != "inv-1" || result["ok"] != true {
			t.Fatalf("invoke result = %v", result)
		}
		payload, _ := result["payload"].(map[string]any)
		if payload["version"] != "0.1.0" {
			t.Fatalf("payload = %v", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no link.result for invoke")
	}

	// link.invoke with a non-string command.
	vm.sendControl(map[string]any{
		"method": "link.invoke", "id": "inv-2", "command": json.Number("42"),
	})
	select {
	case result := <-vm.results:
		if result["ok"] != false || result["error"] != "command must be a string" {
			t.Fatalf("invoke result = %v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no link.result for bad command")
	}

	// subscribe_chat filters non-event records.
	sub, err := session.SubscribeChat(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var ns []int
	for {
		event, err := sub.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := event["n"].(json.Number); ok {
			v, _ := n.Int64()
			ns = append(ns, int(v))
		}
	}
	sub.Close()
	if len(ns) != 2 || ns[0] != 1 || ns[1] != 2 {
		t.Fatalf("events = %v", ns)
	}

	// The unpaired event ends the session.
	vm.sendControl(map[string]any{"event": "link.unpaired"})
	select {
	case res := <-runDone:
		if res.outcome != OutcomeUnpaired || res.err != nil {
			t.Fatalf("run = %v, %v", res.outcome, res.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session did not end after unpaired")
	}
}

func TestUpgradeRejectedOutcomes(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   Outcome
	}{
		{401, OutcomeAuthRejected},
		{403, OutcomeForbidden},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no", tc.status)
		}))
		url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/noise?vm_id=x"
		session, err := NewSession("unused", "x", "bad-token",
			DeviceDescription{NodeID: "homelink-000001"}, runCommandStub, WithURL(url))
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := session.Run(context.Background())
		server.Close()
		if err != nil || outcome != tc.want {
			t.Fatalf("HTTP %d: outcome = %v, err = %v; want %v", tc.status, outcome, err, tc.want)
		}
	}
}

func TestEncodeMessageGolden(t *testing.T) {
	message := wirejson.Obj{
		{Key: "type", Value: "req"},
		{Key: "id", Value: "x"},
		{Key: "method", Value: "link.register"},
		{Key: "params", Value: map[string]any{"a": 1}},
	}
	encoded, err := EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	want := "410000007b2274797065223a22726571222c226964223a2278222c226d6574686f64223a226c696e6b2e7265676973746572222c22706172616d73223a7b2261223a317d7d"
	if got := hexEncode(encoded); got != want {
		t.Fatalf("encode_message = %s, want %s", got, want)
	}
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&0xF])
	}
	return sb.String()
}

func TestNoiseURLAndAppID(t *testing.T) {
	url, err := NoiseURL("hatch.metaaivm.com", "vm 1/x", "")
	if err != nil {
		t.Fatal(err)
	}
	if url != "wss://hatch.metaaivm.com/v1/noise?vm_id=vm%201%2Fx" {
		t.Fatalf("url = %s", url)
	}
	url, err = NoiseURL("h", "v", "00123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(url, "&app_id=123") {
		t.Fatalf("url = %s", url)
	}
	if _, err := NoiseURL("h", "v", "hatch-web"); err != nil {
		t.Fatalf("hatch-web: %v", err)
	}
	for _, bad := range []string{"0", "-5", "12345678901234567890", "9223372036854775808", "12a", ""} {
		if bad == "" {
			continue // empty means "no app id" at the URL layer
		}
		if _, err := ValidateAppID(bad); err == nil {
			t.Errorf("app id %q accepted", bad)
		}
	}
	if v, err := ValidateAppID("9223372036854775807"); err != nil || v != "9223372036854775807" {
		t.Errorf("max int64 app id = %q, %v", v, err)
	}
}

func TestMessageDecoder(t *testing.T) {
	decoder := &MessageDecoder{}
	encoded, err := EncodeMessage(map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	// Split mid-prefix and mid-body.
	messages, err := decoder.Feed(encoded[:3])
	if err != nil || len(messages) != 0 {
		t.Fatalf("partial feed = %v, %v", messages, err)
	}
	messages, err = decoder.Feed(encoded[3:])
	if err != nil || len(messages) != 1 || messages[0]["a"] == nil {
		t.Fatalf("rest feed = %v, %v", messages, err)
	}
	// Keepalive (zero length) skipped; malformed dropped.
	messages, err = decoder.Feed([]byte{0, 0, 0, 0})
	if err != nil || len(messages) != 0 {
		t.Fatalf("keepalive = %v, %v", messages, err)
	}
	bad := append([]byte{8, 0, 0, 0}, []byte("not json")...)
	messages, err = decoder.Feed(bad)
	if err != nil || len(messages) != 0 {
		t.Fatalf("malformed = %v, %v", messages, err)
	}
	// Oversize length is an error.
	if _, err := decoder.Feed([]byte{0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("oversize message accepted")
	}
}

func TestCheckImage(t *testing.T) {
	if err := CheckImage([]byte{1}, "image/png"); err != nil {
		t.Fatal(err)
	}
	if err := CheckImage([]byte{1}, "image/bmp"); err == nil {
		t.Fatal("bmp accepted")
	}
	if err := CheckImage(nil, "image/png"); err == nil {
		t.Fatal("empty accepted")
	}
	err := CheckImage(make([]byte, MaxImageBytes+1), "image/png")
	if err == nil || !strings.Contains(err.Error(), "2,097,153 bytes") {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestSessionCanOnlyRunOnce(t *testing.T) {
	session, err := NewSession("unused", "x", "tok", DeviceDescription{}, runCommandStub,
		WithURL("ws://127.0.0.1:1/v1/noise"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = session.Run(context.Background()) // connection refused
	if _, err := session.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}
}
