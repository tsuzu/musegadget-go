package ble

import (
	"errors"
	"log"
	"sync"
	"time"
	"unicode/utf8"

	"musegadget/identity"
	"musegadget/pairing"
	"musegadget/wirejson"
)

// Transport is what a BLE GATT server provides to the setup controller:
// framed notifications out, and a way to drop the connection.
type Transport interface {
	// SendPackets notifies each packet in order; it blocks until all are
	// queued.
	SendPackets(packets [][]byte)
	// MTU is the current ATT MTU.
	MTU() int
	// Disconnect drops the connection after delay.
	Disconnect(delay time.Duration)
}

// Network reports connectivity for the setup flow.
type Network interface {
	IsOnline() bool
	CurrentConnectionEntry() map[string]any
}

// Credentials are the provisioning fields of a provision_v2 command. The
// Wi-Fi fields of the command are deliberately dropped, as in the
// reference: this device only sets up when it is already online.
type Credentials struct {
	AccessToken  string
	RefreshToken string
	Username     string
	APIURL       string
	APIURLV2     string
	NoiseHost    string
}

// ProvisionFailed reports that setup could not finish; Status is what the
// app is told.
type ProvisionFailed struct{ Status string }

func (e *ProvisionFailed) Error() string { return e.Status }

// ProvisionFunc verifies credentials and persists them through commit
// (which runs under the pairing lock), returning a *ProvisionFailed on
// failure.
type ProvisionFunc func(creds Credentials, commit func(save func() bool) bool) error

var sensitiveActions = map[string]bool{
	"provision": true, "provision_v2": true, "wifi_scan": true, "ota": true,
	"device.ota": true, "unpair": true, "set_wifi": true, "set_auth": true,
}

// Statuses that may be sent in plaintext, and only before pairing starts.
var plaintextStatuses = map[string]bool{
	"error_encryption_required":   true,
	"error_pairing_invalid_hello": true,
	"error_pairing_unavailable":   true,
	"error_pairing_decrypt":       true,
}

const disconnectAfterError = 300 * time.Millisecond

// Controller handles one BLE setup client at a time. Messages are handled
// one at a time on a worker goroutine, in arrival order, and every send
// happens under one lock so encrypted record counters reach the phone in
// order.
type Controller struct {
	pairing    *pairing.Session
	identity   identity.Identity
	version    string
	transport  Transport
	network    Network
	provision  ProvisionFunc
	onComplete func()

	assembler        *ChunkAssembler
	inbox            *messageQueue
	txMu             sync.Mutex
	stateMu          sync.Mutex
	plaintextBlocked bool
	provisioning     bool
}

// NewController wires a controller to its transport and callbacks.
func NewController(pairingSession *pairing.Session, id identity.Identity, version string,
	transport Transport, network Network, provision ProvisionFunc, onComplete func()) *Controller {
	if onComplete == nil {
		onComplete = func() {}
	}
	return &Controller{
		pairing:    pairingSession,
		identity:   id,
		version:    version,
		transport:  transport,
		network:    network,
		provision:  provision,
		onComplete: onComplete,
		assembler:  NewChunkAssembler(),
		inbox:      newMessageQueue(),
	}
}

// Start launches the message worker.
func (c *Controller) Start() { go c.run() }

// Stop ends the message worker after queued messages drain.
func (c *Controller) Stop() { c.inbox.close() }

func (c *Controller) run() {
	for {
		message, ok := c.inbox.get()
		if !ok {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("musegadget: setup command failed: %v", r)
				}
			}()
			c.HandleMessage(message, false)
		}()
	}
}

// OnWrite is the transport callback for one received packet.
func (c *Controller) OnWrite(packet []byte) {
	if message, complete := c.assembler.Feed(packet); complete {
		c.inbox.put(message)
	}
}

// OnDisconnect is the transport callback for a dropped connection.
func (c *Controller) OnDisconnect() {
	log.Printf("musegadget: BLE client disconnected; clearing pairing session")
	c.assembler.Reset()
	c.stateMu.Lock()
	c.plaintextBlocked = false
	c.stateMu.Unlock()
	c.pairing.Reset()
}

// HandleMessage dispatches one reassembled message. decrypted marks a
// message that arrived inside a pairing_encrypted record.
func (c *Controller) HandleMessage(raw []byte, decrypted bool) {
	command, ok := decodeCommand(raw)
	if !ok {
		log.Printf("musegadget: invalid command JSON (%d bytes)", len(raw))
		c.SendStatus("error_invalid_command", 0)
		return
	}
	action, _ := command["action"].(string)
	c.stateMu.Lock()
	plaintextBlocked := c.plaintextBlocked
	c.stateMu.Unlock()

	switch {
	case !decrypted && action == "pairing_client_hello":
		c.handleHello(command)
	case !decrypted && action == "pairing_encrypted":
		c.handleRecord(command)
	case action == "get_device_info":
		// Public metadata, safe in plaintext at any point.
		c.SendJSON(c.DeviceInfo())
	case !decrypted && plaintextBlocked:
		log.Printf("musegadget: plaintext command ignored after pairing started: %s", action)
	case !decrypted && sensitiveActions[action]:
		c.SendStatus("error_encryption_required", 0)
	case decrypted && action == "pairing_client_finished":
		c.handleClientFinished(command)
	case decrypted && sensitiveActions[action] && !c.pairing.Confirmed():
		c.SendStatus("error_pairing_confirm_required", 0)
	case decrypted && action == "wifi_scan":
		c.handleWifiScan()
	case decrypted && action == "provision_v2":
		c.handleProvision(command)
	default:
		c.SendStatus("error_unknown_action", 0)
	}
}

func decodeCommand(raw []byte) (map[string]any, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	command, err := wirejson.DecodeMap(raw)
	if err != nil {
		return nil, false
	}
	return command, true
}

// DeviceInfo builds the get_device_info reply.
func (c *Controller) DeviceInfo() wirejson.Obj {
	info := wirejson.Obj{
		{Key: "type", Value: "device_info"},
		{Key: "node_id", Value: c.identity.NodeID()},
		{Key: "version", Value: c.version},
	}
	info = append(info, c.pairing.DeviceInfo()...)
	info = append(info,
		wirejson.Pair{Key: "build_sha", Value: ""},
		wirejson.Pair{Key: "network_ready", Value: c.network.IsOnline()},
	)
	return info
}

func (c *Controller) handleHello(command map[string]any) {
	ready, err := c.pairing.HandleHello(command)
	if err != nil {
		c.SendStatus(statusOf(err), 0)
		return
	}
	c.stateMu.Lock()
	c.plaintextBlocked = true
	c.stateMu.Unlock()
	c.SendJSON(ready)
}

func (c *Controller) handleRecord(envelope map[string]any) {
	plaintext, err := c.pairing.Decrypt(envelope)
	if err != nil {
		c.SendStatus(statusOf(err), 0)
		c.transport.Disconnect(disconnectAfterError)
		return
	}
	c.HandleMessage([]byte(plaintext), true)
}

func (c *Controller) handleClientFinished(command map[string]any) {
	generation := c.pairing.HandleClientFinished(command)
	if generation == 0 {
		c.SendStatus("error_pairing_decrypt", 0)
		c.transport.Disconnect(disconnectAfterError)
		return
	}
	log.Printf("musegadget: pairing confirmed (app consent)")
	c.SendStatus("pairing_confirmed", generation)
}

func (c *Controller) handleWifiScan() {
	networks := []any{}
	if c.network.IsOnline() {
		networks = append(networks, c.network.CurrentConnectionEntry())
	}
	c.SendEncryptedJSON(wirejson.Obj{
		{Key: "type", Value: "wifi_scan_result"},
		{Key: "networks", Value: networks},
	}, 0)
}

func (c *Controller) handleProvision(command map[string]any) {
	text := func(key string) string {
		value, _ := command[key].(string)
		return value
	}
	_, ssidIsString := command["ssid"].(string)
	_, passwordIsString := command["password"].(string)
	if !ssidIsString || !passwordIsString ||
		text("access_token") == "" || text("refresh_token") == "" ||
		text("token_type") != "device" {
		c.SendStatus("error_missing_credentials", 0)
		return
	}
	var generation int64
	refusal := ""
	c.stateMu.Lock()
	if c.provisioning {
		refusal = "error_operation_in_progress"
	} else {
		generation = c.pairing.MarkProvisioning()
		if generation == 0 {
			refusal = "error_pairing_confirm_required"
		}
		c.provisioning = generation != 0
	}
	c.stateMu.Unlock()
	// Sent after the lock is released: SendStatus takes stateMu itself when
	// the session has no keys, and the lock is not reentrant.
	if refusal != "" {
		c.SendStatus(refusal, 0)
		return
	}
	credentials := Credentials{
		AccessToken:  text("access_token"),
		RefreshToken: text("refresh_token"),
		Username:     text("username"),
		APIURL:       text("api_url"),
		APIURLV2:     text("api_url_v2"),
		NoiseHost:    text("noise_host"),
	}
	go c.runProvision(credentials, generation)
}

func (c *Controller) runProvision(credentials Credentials, generation int64) {
	defer func() {
		c.stateMu.Lock()
		c.provisioning = false
		c.stateMu.Unlock()
	}()
	c.SendStatus("wifi_connecting", generation)
	if !c.network.IsOnline() {
		// Stay in provisioning so the app can retry, as the firmware does.
		c.pairing.ExtendProvisioning(generation)
		c.SendStatus("wifi_failed", generation)
		return
	}
	c.SendStatus("wifi_connected", generation)

	commit := func(save func() bool) bool {
		return c.pairing.CommitProvisioning(generation, save)
	}
	err := c.provision(credentials, commit)
	if err != nil {
		if failed, ok := err.(*ProvisionFailed); ok {
			log.Printf("musegadget: provisioning failed: %s", failed.Status)
			c.SendStatus(failed.Status, generation)
			c.transport.Disconnect(500 * time.Millisecond)
			return
		}
		// The reference lets other failures end the provision thread
		// without a status.
		log.Printf("musegadget: provisioning failed: %v", err)
		return
	}
	c.SendStatus("auth_ok", generation)
	log.Printf("musegadget: setup complete")
	c.onComplete()
}

// SendStatus sends a status, encrypted when a pairing session exists. A few
// early errors may go in plaintext, as the bare status string, only before
// pairing starts; anything else without a session is suppressed.
func (c *Controller) SendStatus(status string, generation int64) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	if envelope, ok := c.pairing.EncryptStatus(status, generation); ok {
		c.sendLocked(string(wirejson.MustMarshal(envelope)))
		return
	}
	c.stateMu.Lock()
	blocked := c.plaintextBlocked
	c.stateMu.Unlock()
	if generation != 0 || blocked || !plaintextStatuses[status] {
		return
	}
	c.transport.SendPackets([][]byte{[]byte(status)})
}

// SendJSON sends a plaintext JSON reply, chunk-framed.
func (c *Controller) SendJSON(obj any) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	c.sendLocked(string(wirejson.MustMarshal(obj)))
}

// SendEncryptedJSON seals a JSON reply in the pairing session; it is
// suppressed when there is no live session for the generation.
func (c *Controller) SendEncryptedJSON(obj any, generation int64) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	envelope, ok := c.pairing.EncryptJSON(string(wirejson.MustMarshal(obj)), generation)
	if !ok {
		return
	}
	c.sendLocked(string(wirejson.MustMarshal(envelope)))
}

func (c *Controller) sendLocked(text string) {
	packets, err := EncodeChunks([]byte(text), c.transport.MTU())
	if err != nil {
		log.Printf("musegadget: cannot frame %d-byte reply: %v", len(text), err)
		return
	}
	c.transport.SendPackets(packets)
}

func statusOf(err error) string {
	var perr *pairing.Error
	if errors.As(err, &perr) {
		return perr.Status
	}
	return pairing.StatusDecrypt
}

// messageQueue is an unbounded FIFO for reassembled setup messages.
type messageQueue struct {
	mu     sync.Mutex
	cond   sync.Cond
	items  [][]byte
	closed bool
}

func newMessageQueue() *messageQueue {
	q := &messageQueue{}
	q.cond.L = &q.mu
	return q
}

func (q *messageQueue) put(message []byte) {
	q.mu.Lock()
	q.items = append(q.items, message)
	q.mu.Unlock()
	q.cond.Signal()
}

func (q *messageQueue) get() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return nil, false
	}
	message := q.items[0]
	q.items = q.items[1:]
	return message, true
}

func (q *messageQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}
