// Package linkclient mirrors musegadget.link_client: one control session
// with a Muse VM. It opens a WebSocket to /v1/noise with the per-VM bearer,
// runs the Noise XX handshake, then opens a long-lived POST /link-control
// stream. Both directions of that stream carry JSON messages, each prefixed
// with its length as a little-endian u32. Device-originated messages to the
// Muse (SendChat and friends) go as separate HTTP requests multiplexed on
// the same Noise session.
package linkclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"musegadget/museapi"
	"musegadget/noise"
	"musegadget/wirejson"
)

const (
	NoisePath   = "/v1/noise"
	ControlPath = "/link-control"
	ChatPath    = "/chat/stream"
	AppID       = "musegadget"

	RequestTimeout    = 60 * time.Second
	HandshakeTimeout  = 20 * time.Second
	PingInterval      = 20 * time.Second
	MaxMessageSize    = 128 * 1024
	MaxResponseBytes  = 1024 * 1024
	MaxInboundMessage = 4 * 1024 * 1024
	// Documented VM limit: 256 KiB per device control message, including
	// the u32 length prefix.
	MaxControlMessageBytes = 256 * 1024
	RegisterIDBytes        = 36 // str(uuid.uuid4())
	MaxChatEventBytes      = 256 * 1024
	MaxStreamBufferBytes   = 1024 * 1024
	MaxTTSBufferBytes      = 8 * 1024 * 1024
	StreamChunkBytes       = 16 * 1024
	MaxVoiceBytes          = 2 * 1024 * 1024
	MaxImageBytes          = 2 * 1024 * 1024
	RequestChunkBytes      = 16 * 1024
	MaxInlineRequestBytes  = 64 * 1024
	MaxConcurrentInvokes   = 4
)

// uriComponentSafe matches JavaScript's encodeURIComponent, as the
// firmware does.
const uriComponentSafe = "-_.!~*'()"

// Outcome is how a session ended.
type Outcome string

const (
	OutcomeClosed       Outcome = "closed"        // connection ended; reconnect normally
	OutcomeAuthRejected Outcome = "auth_rejected" // edge refused the VM bearer; re-fetch VMs
	OutcomeForbidden    Outcome = "forbidden"     // authenticated but not allowed right now
	OutcomeUnpaired     Outcome = "unpaired"      // the Muse removed this device
	OutcomeStopped      Outcome = "stopped"
)

// DeviceDescription describes the device registered with Muse each session.
type DeviceDescription struct {
	NodeID      string
	DisplayName string
	Version     string
	Commands    map[string]any // commands_v2: name -> spec
}

// RegisterParams builds the link.register params, in the reference's order.
func (d DeviceDescription) RegisterParams() wirejson.Obj {
	return wirejson.Obj{
		{Key: "node_id", Value: d.NodeID},
		{Key: "display_name", Value: d.DisplayName},
		{Key: "platform", Value: "linux"},
		{Key: "version", Value: d.Version},
		{Key: "device_family", Value: "homehub"},
		{Key: "model_id", Value: "linux"},
		{Key: "is_wakeup_supported", Value: false},
		{Key: "commands_v2", Value: d.Commands},
	}
}

// RegisterMessage builds the link.register control message.
func (d DeviceDescription) RegisterMessage(requestID string) wirejson.Obj {
	return wirejson.Obj{
		{Key: "type", Value: "req"},
		{Key: "id", Value: requestID},
		{Key: "method", Value: "link.register"},
		{Key: "params", Value: d.RegisterParams()},
	}
}

// EncodeMessage frames a control message: little-endian u32 length prefix
// plus compact JSON.
func EncodeMessage(obj any) ([]byte, error) {
	data, err := wirejson.Marshal(obj)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4, 4+len(data))
	binary.LittleEndian.PutUint32(out, uint32(len(data)))
	return append(out, data...), nil
}

// MessageDecoder splits the control stream into length-prefixed JSON
// messages. A message may span body chunks, so bytes are buffered until
// complete.
type MessageDecoder struct {
	buf []byte
}

// Feed adds bytes and returns any complete messages. Zero-length frames
// are keepalives; malformed JSON and non-object messages are dropped.
func (d *MessageDecoder) Feed(data []byte) ([]map[string]any, error) {
	d.buf = append(d.buf, data...)
	var messages []map[string]any
	for len(d.buf) >= 4 {
		length := binary.LittleEndian.Uint32(d.buf)
		if length > MaxInboundMessage {
			return nil, fmt.Errorf("inbound message too large: %d", length)
		}
		if len(d.buf) < 4+int(length) {
			break
		}
		raw := d.buf[4 : 4+length]
		d.buf = d.buf[4+length:]
		if len(raw) == 0 {
			continue // keepalive
		}
		message, err := wirejson.DecodeMap(raw)
		if err != nil {
			log.Printf("musegadget: dropping malformed control message (%d bytes)", length)
			continue
		}
		messages = append(messages, message)
	}
	return messages, nil
}

// ValidateAppID checks a voice app identity, fixed for a whole connection.
func ValidateAppID(appID string) (string, error) {
	if appID == "hatch-web" {
		return appID, nil
	}
	if isASCIIDecimal(appID) && len(appID) <= 19 {
		if value, err := parseInt64Decimal(appID); err == nil && value > 0 {
			return strings.TrimLeft(appID, "0"), nil
		}
	}
	return "", errors.New("app ID must be a positive int64 or hatch-web")
}

func isASCIIDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseInt64Decimal(s string) (int64, error) {
	var v int64
	for i := 0; i < len(s); i++ {
		digit := int64(s[i] - '0')
		if v > (1<<63-1-digit)/10 {
			return 0, errors.New("int64 overflow")
		}
		v = v*10 + digit
	}
	return v, nil
}

// quoteURIComponent quotes like JavaScript's encodeURIComponent with the
// given extra safe set; letters, digits and "_.-~" are never quoted.
func quoteURIComponent(s string, safe string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '_' || c == '.' || c == '-' || c == '~':
			b.WriteByte(c)
		case strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// NoiseURL builds the WebSocket URL for a VM.
func NoiseURL(noiseHost, vmID, appID string) (string, error) {
	url := "wss://" + noiseHost + NoisePath + "?vm_id=" + quoteURIComponent(vmID, uriComponentSafe)
	if appID != "" {
		validated, err := ValidateAppID(appID)
		if err != nil {
			return "", err
		}
		url += "&app_id=" + quoteURIComponent(validated, "")
	}
	return url, nil
}

// SideChat reports whether Muse has a chat with a session id. A false
// Exists means the first SendChat to it creates it.
type SideChat struct {
	SessionID string
	Exists    bool
}

// CheckImage validates a picture for SendImage.
func CheckImage(imageBytes []byte, mimeType string) error {
	switch mimeType {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
	default:
		return errors.New("images must be JPEG, PNG, GIF or WebP")
	}
	if len(imageBytes) == 0 {
		return errors.New("the image is empty")
	}
	if len(imageBytes) > MaxImageBytes {
		return fmt.Errorf("the image is %s bytes; images must be 2 MiB or less", commaInt(len(imageBytes)))
	}
	return nil
}

func commaInt(n int) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// RunCommandFunc handles one command from Muse. It returns a result dict:
// {"ok":true,"payload":{...}} or {"ok":false,"error":"..."}.
type RunCommandFunc func(name string, params map[string]any, timeoutMs *int64) map[string]any

type frameHandler interface {
	OnFrame(frame *noise.DecryptedFrame)
	Fail(err error)
}

type noRequest struct{}

func (noRequest) OnFrame(frame *noise.DecryptedFrame) {}
func (noRequest) Fail(err error)                      {}

var noHandler frameHandler = noRequest{}

// Session is one control session with a Muse VM. It can only run once.
type Session struct {
	url            string
	urlOverride    string
	appID          string
	registerDevice bool
	token          string
	device         DeviceDescription
	runCommand     RunCommandFunc
	invokeSlots    chan struct{}
	dialer         *websocket.Dialer

	mu             sync.Mutex
	used           bool
	closed         bool
	running        bool
	ws             *websocket.Conn
	transport      *noise.Transport
	controlStream  int64
	registerID     string
	registeredAt   *time.Time
	chatSubscribed bool

	sendMu sync.Mutex

	requestsMu sync.Mutex
	requests   map[int64]frameHandler
	streams    map[int64]*httpStream

	transportReady      chan struct{}
	registrationChanged chan struct{}
	registrationErr     error
	done                chan struct{}
}

// Option configures a Session.
type Option func(*Session)

// WithRegisterDevice(false) skips the control stream and link.register,
// preserving another connection's registration for the same device.
func WithRegisterDevice(register bool) Option {
	return func(s *Session) { s.registerDevice = register }
}

// WithAppID sets the voice app identity for the connection URL.
func WithAppID(appID string) Option {
	return func(s *Session) { s.appID = appID }
}

// WithInvokeSlots shares the invoke semaphore (the service passes one
// across sessions, so a running command keeps its slot across reconnects).
func WithInvokeSlots(slots chan struct{}) Option {
	return func(s *Session) {
		if slots != nil {
			s.invokeSlots = slots
		}
	}
}

// WithURL overrides the computed wss URL (tests and fake VMs).
func WithURL(url string) Option {
	return func(s *Session) { s.urlOverride = url }
}

// NewSession creates a session for one VM.
func NewSession(noiseHost, vmID, vmAuthToken string, device DeviceDescription,
	runCommand RunCommandFunc, opts ...Option) (*Session, error) {
	s := &Session{
		registerDevice:      true,
		token:               vmAuthToken,
		device:              device,
		runCommand:          runCommand,
		invokeSlots:         make(chan struct{}, MaxConcurrentInvokes),
		requests:            map[int64]frameHandler{},
		streams:             map[int64]*httpStream{},
		transportReady:      make(chan struct{}),
		registrationChanged: make(chan struct{}),
		done:                make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.urlOverride != "" {
		s.url = s.urlOverride
	} else {
		url, err := NoiseURL(noiseHost, vmID, s.appID)
		if err != nil {
			return nil, err
		}
		s.url = url
	}
	return s, nil
}

// RegisteredAt returns when link.register was acknowledged, if it was.
func (s *Session) RegisteredAt() *time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registeredAt
}

// ChatSubscribed reports whether a chat subscription is active.
func (s *Session) ChatSubscribed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chatSubscribed
}

func (s *Session) setChatSubscribed(v bool) {
	s.mu.Lock()
	s.chatSubscribed = v
	s.mu.Unlock()
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Transport returns the session's Noise transport (nil before the
// handshake). It satisfies streaming.Session.
func (s *Session) Transport() *noise.Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transport
}

// UnregisterRequest removes a request handler; part of streaming.Session.
func (s *Session) UnregisterRequest(streamID int64) {
	s.requestsMu.Lock()
	delete(s.requests, streamID)
	s.requestsMu.Unlock()
}

// Run connects, registers and serves until the connection ends or ctx is
// cancelled. Abnormal endings return the outcome CLOSED with the error.
func (s *Session) Run(ctx context.Context) (Outcome, error) {
	s.mu.Lock()
	if s.used {
		s.mu.Unlock()
		return OutcomeClosed, errors.New("a LinkSession can only run once")
	}
	s.used = true
	s.mu.Unlock()

	defer s.teardown()

	ws, outcome, err := s.open(ctx)
	if err != nil {
		return OutcomeClosed, err
	}
	if outcome != "" {
		return outcome, nil
	}
	s.mu.Lock()
	s.ws = ws
	s.mu.Unlock()

	transport, err := s.handshake(ws)
	if err != nil {
		return OutcomeClosed, err
	}
	s.mu.Lock()
	s.transport = transport
	s.running = true
	s.mu.Unlock()

	if s.registerDevice {
		if err := s.openControlStream(); err != nil {
			return OutcomeClosed, err
		}
	}
	close(s.transportReady)

	type result struct {
		outcome Outcome
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		outcome, err := s.readLoop()
		resultCh <- result{outcome, err}
	}()
	select {
	case <-ctx.Done():
		return OutcomeStopped, nil
	case res := <-resultCh:
		return res.outcome, res.err
	}
}

func (s *Session) teardown() {
	s.mu.Lock()
	s.running = false
	s.closed = true
	s.registeredAt = nil
	ws := s.ws
	s.mu.Unlock()

	select {
	case <-s.transportReady:
	default:
		close(s.transportReady)
	}
	select {
	case <-s.registrationChanged:
	default:
		close(s.registrationChanged)
	}
	s.requestsMu.Lock()
	for _, handler := range s.requests {
		handler.Fail(errors.New("session ended"))
	}
	s.requests = map[int64]frameHandler{}
	for _, stream := range s.streams {
		stream.fail(errors.New("session ended"))
	}
	s.streams = map[int64]*httpStream{}
	s.requestsMu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
	close(s.done)
}

// open dials the WebSocket. It returns a non-empty outcome (with nil error)
// for an upgrade the edge refuses with 401/403.
func (s *Session) open(ctx context.Context) (*websocket.Conn, Outcome, error) {
	dialer := s.dialer
	if dialer == nil {
		dialer = &websocket.Dialer{HandshakeTimeout: HandshakeTimeout}
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+s.token)
	headers.Set("User-Agent", museapi.UserAgent())
	ws, resp, err := dialer.DialContext(ctx, s.url, headers)
	if err != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			log.Printf("musegadget: VM refused connection: HTTP %d", resp.StatusCode)
			if resp.StatusCode == 401 {
				return nil, OutcomeAuthRejected, nil
			}
			return nil, OutcomeForbidden, nil
		}
		return nil, "", err
	}
	ws.SetReadLimit(MaxMessageSize)
	return ws, "", nil
}

func (s *Session) handshake(ws *websocket.Conn) (*noise.Transport, error) {
	_ = ws.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	defer ws.SetReadDeadline(time.Time{})
	initiator := noise.NewInitiator()
	if err := initiator.Initialize(); err != nil {
		return nil, err
	}
	msg1, err := initiator.WriteMessage1()
	if err != nil {
		return nil, err
	}
	if err := ws.WriteMessage(websocket.BinaryMessage, msg1); err != nil {
		return nil, err
	}
	messageType, msg2, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	if messageType == websocket.TextMessage {
		return nil, errors.New("Noise handshake got a text frame")
	}
	if _, err := initiator.ReadMessage2(msg2); err != nil {
		return nil, err
	}
	// The bearer already authenticated us at the upgrade; message 3
	// carries an empty payload.
	msg3, err := initiator.WriteMessage3()
	if err != nil {
		return nil, err
	}
	if err := ws.WriteMessage(websocket.BinaryMessage, msg3); err != nil {
		return nil, err
	}
	send, recv, err := initiator.Split()
	if err != nil {
		return nil, err
	}
	log.Printf("musegadget: Noise session established")
	return noise.NewTransport(send, recv), nil
}

func (s *Session) openControlStream() error {
	encrypted, err := s.sendEncryptedRequest(func() (*noise.EncryptedFrames, error) {
		return s.Transport().StartStreamRequest("POST", ControlPath, nil, nil)
	}, nil)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.controlStream = encrypted.StreamID
	s.registerID = newUUID()
	registerID := s.registerID
	s.mu.Unlock()
	message := s.device.RegisterMessage(registerID)
	encoded, err := EncodeMessage(message)
	if err != nil {
		return err
	}
	if len(encoded) > MaxControlMessageBytes {
		return errors.New("link.register exceeds the VM's control message budget")
	}
	if err := s.Send(message); err != nil {
		return err
	}
	log.Printf("musegadget: sent link.register as %s", s.device.NodeID)
	return nil
}

// Send sends one control message on the control stream.
func (s *Session) Send(message any) error {
	if !s.registerDevice {
		return errors.New("no device control stream on this session")
	}
	encoded, err := EncodeMessage(message)
	if err != nil {
		return err
	}
	s.mu.Lock()
	streamID := s.controlStream
	s.mu.Unlock()
	return s.SendEncrypted(func() ([][]byte, error) {
		return s.Transport().EncryptBodyChunk(streamID, encoded, nil, false)
	}, nil)
}

// SendEncrypted runs encrypt under the send lock (acquired BEFORE
// encrypting, so concurrent requests and cancelled sends cannot reorder
// ciphertext), writes the frames, and returns encrypt's error. A failed
// send fails the whole session: delivery is ambiguous and the cipher state
// is never reused. It satisfies streaming.Session.
func (s *Session) SendEncrypted(encrypt func() ([][]byte, error), check func() error) error {
	_, err := s.sendEncryptedInternal(func() (*noise.EncryptedFrames, error) {
		frames, err := encrypt()
		if err != nil {
			return nil, err
		}
		return &noise.EncryptedFrames{Frames: frames}, nil
	}, check)
	return err
}

func (s *Session) sendEncryptedRequest(encrypt func() (*noise.EncryptedFrames, error), check func() error) (*noise.EncryptedFrames, error) {
	return s.sendEncryptedInternal(encrypt, check)
}

func (s *Session) sendEncryptedInternal(encrypt func() (*noise.EncryptedFrames, error), check func() error) (*noise.EncryptedFrames, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.isClosed() {
		return nil, errors.New("session closed")
	}
	if check != nil {
		if err := check(); err != nil {
			return nil, err
		}
	}
	result, err := encrypt()
	if err != nil {
		s.failSendLocked()
		return nil, err
	}
	s.mu.Lock()
	ws := s.ws
	s.mu.Unlock()
	for _, frame := range result.Frames {
		if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			s.failSendLocked()
			return nil, err
		}
	}
	return result, nil
}

// failSendLocked marks the session closed and fails all pending work.
// Callers hold the send lock.
func (s *Session) failSendLocked() {
	s.mu.Lock()
	s.closed = true
	s.running = false
	ws := s.ws
	s.mu.Unlock()
	s.requestsMu.Lock()
	for _, handler := range s.requests {
		handler.Fail(errors.New("send failed"))
	}
	for _, stream := range s.streams {
		stream.fail(errors.New("send failed"))
	}
	s.requestsMu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
}

// WaitTransportReady waits for the authenticated upgrade, Noise handshake
// and receive loop.
func (s *Session) WaitTransportReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	select {
	case <-s.transportReady:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.isClosed() || s.Transport() == nil {
		return errors.New("Noise transport did not become ready")
	}
	return nil
}

// WaitRegistered waits for the registration ACK, not merely an open
// WebSocket.
func (s *Session) WaitRegistered(ctx context.Context) error {
	if !s.registerDevice {
		return errors.New("device registration is disabled on this session")
	}
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	select {
	case <-s.registrationChanged:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registrationErr != nil {
		return s.registrationErr
	}
	if s.closed || s.registeredAt == nil {
		return errors.New("session ended before registration")
	}
	return nil
}

func (s *Session) readLoop() (Outcome, error) {
	decoder := &MessageDecoder{}
	for {
		messageType, raw, err := s.ws.ReadMessage()
		if err != nil {
			log.Printf("musegadget: control connection closed: %v", err)
			return OutcomeClosed, nil
		}
		if messageType == websocket.TextMessage {
			log.Printf("musegadget: ignoring text frame on Noise connection")
			continue
		}
		frame, err := s.Transport().DecryptFrame(raw)
		if err != nil {
			return OutcomeClosed, err
		}
		if frame == nil {
			continue
		}
		s.mu.Lock()
		controlStream := s.controlStream
		s.mu.Unlock()
		if !s.registerDevice || frame.StreamID != controlStream {
			s.requestsMu.Lock()
			stream := s.streams[frame.StreamID]
			var handler frameHandler
			if stream == nil {
				handler = s.requests[frame.StreamID]
				if handler == nil {
					handler = noHandler
				}
			}
			s.requestsMu.Unlock()
			if stream != nil {
				if !stream.onFrame(frame) {
					stream.resetRequested = true
					go s.resetStream(frame.StreamID)
				}
			} else {
				handler.OnFrame(frame)
			}
			continue
		}
		if frame.Kind == noise.FrameReset {
			log.Printf("musegadget: control stream reset: %s", frame.Reset.Reason)
			return OutcomeClosed, nil
		}
		var data []byte
		var ended bool
		if frame.Kind == noise.FrameResponse {
			status := frame.Response.Status
			if status < 200 || status >= 300 {
				log.Printf("musegadget: /link-control refused: HTTP %d", status)
				if status == 403 {
					return OutcomeForbidden, nil
				}
				return OutcomeClosed, nil
			}
			data, ended = frame.Response.Body, frame.Response.EndBody
		} else {
			data, ended = frame.BodyChunk.Data, frame.BodyChunk.EndBody
		}
		messages, err := decoder.Feed(data)
		if err != nil {
			return OutcomeClosed, err
		}
		for _, message := range messages {
			if outcome := s.handleMessage(message); outcome != nil {
				return *outcome, nil
			}
		}
		if ended {
			log.Printf("musegadget: control stream ended by VM")
			return OutcomeClosed, nil
		}
	}
}

func (s *Session) handleMessage(message map[string]any) *Outcome {
	s.mu.Lock()
	registerID := s.registerID
	s.mu.Unlock()
	if id, _ := message["id"].(string); id == registerID && registerID != "" {
		if _, hasMethod := message["method"]; !hasMethod || message["method"] == nil {
			if truthy(message["error"]) || message["ok"] == false {
				s.mu.Lock()
				s.registrationErr = errors.New("link registration rejected")
				s.mu.Unlock()
				select {
				case <-s.registrationChanged:
				default:
					close(s.registrationChanged)
				}
				log.Printf("musegadget: link.register rejected")
				outcome := OutcomeForbidden
				return &outcome
			}
			now := time.Now()
			s.mu.Lock()
			s.registeredAt = &now
			s.mu.Unlock()
			select {
			case <-s.registrationChanged:
			default:
				close(s.registrationChanged)
			}
			log.Printf("musegadget: registered with the Muse")
			return nil
		}
	}
	if event, _ := message["event"].(string); event == "link.unpaired" || event == "node.unpaired" {
		log.Printf("musegadget: the Muse removed this device")
		outcome := OutcomeUnpaired
		return &outcome
	}
	if method, _ := message["method"].(string); method == "link.invoke" {
		go s.invoke(message)
	}
	return nil
}

func (s *Session) invoke(message map[string]any) {
	invokeID, hasID := invokeIDValue(message["id"])
	if !hasID {
		return
	}
	commandValue := message["command"]
	command, isString := commandValue.(string)
	if !truthy(commandValue) {
		command, isString = "", true
	}
	if !isString {
		_ = s.Send(resultMessage(invokeID, map[string]any{"ok": false, "error": "command must be a string"}))
		return
	}
	params, _ := message["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	timeoutMs := timeoutValue(message["timeout_ms"])

	select {
	case s.invokeSlots <- struct{}{}:
	case <-s.done:
		return
	}
	defer func() { <-s.invokeSlots }()

	result := func() (result map[string]any) {
		defer func() {
			if recover() != nil {
				result = map[string]any{"ok": false, "error": "command failed"}
			}
		}()
		result = s.runCommand(command, params, timeoutMs)
		if _, err := EncodeMessage(resultMessage(invokeID, result)); err != nil {
			return map[string]any{"ok": false, "error": "command failed"}
		}
		return result
	}()
	_ = s.Send(resultMessage(invokeID, result))
}

// resultMessage builds a link.result control message in the reference's
// key order: method, id, then the result's own keys (ok, then payload or
// error, then any others sorted).
func resultMessage(invokeID any, result map[string]any) wirejson.Obj {
	message := wirejson.Obj{
		{Key: "method", Value: "link.result"},
		{Key: "id", Value: invokeID},
	}
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	ordered := []string{}
	for _, preferred := range []string{"ok", "payload", "error"} {
		for _, k := range keys {
			if k == preferred {
				ordered = append(ordered, k)
			}
		}
	}
	rest := []string{}
	for _, k := range keys {
		if k != "ok" && k != "payload" && k != "error" {
			rest = append(rest, k)
		}
	}
	sortStrings(rest)
	for _, k := range append(ordered, rest...) {
		message = append(message, wirejson.Pair{Key: k, Value: result[k]})
	}
	return message
}

func invokeIDValue(v any) (any, bool) {
	if !truthy(v) {
		return nil, false
	}
	return v, true
}

func timeoutValue(v any) *int64 {
	if !truthy(v) {
		return nil
	}
	if f, ok := wirejson.AsFloat64(v); ok {
		i := int64(f)
		return &i
	}
	return nil
}

// truthy mirrors Python truthiness for JSON values.
func truthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case json.Number:
		f, err := value.Float64()
		return err == nil && f != 0
	case float64:
		return value != 0
	case map[string]any:
		return len(value) > 0
	case []any:
		return len(value) > 0
	}
	return true
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// newUUID returns a random RFC 4122 version 4 UUID string.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
