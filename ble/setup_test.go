package ble

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"musegadget/identity"
	"musegadget/pairing"
	"musegadget/wirejson"
)

// The controller test drives a full setup flow against the pairing test
// vectors, through the framing layer, exactly as a phone would.

type fakeTransport struct {
	mu          sync.Mutex
	packets     [][]byte
	disconnects []time.Duration
}

func (f *fakeTransport) SendPackets(packets [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range packets {
		f.packets = append(f.packets, append([]byte(nil), p...))
	}
}

func (f *fakeTransport) MTU() int { return 512 }

func (f *fakeTransport) Disconnect(delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnects = append(f.disconnects, delay)
}

// drain reassembles everything the device has sent so far.
func (f *fakeTransport) drain(assembler *ChunkAssembler) [][]byte {
	f.mu.Lock()
	packets := f.packets
	f.packets = nil
	f.mu.Unlock()
	var messages [][]byte
	for _, p := range packets {
		if message, complete := assembler.Feed(p); complete {
			messages = append(messages, message)
		}
	}
	return messages
}

type fakeNetwork struct{ online bool }

func (n *fakeNetwork) IsOnline() bool { return n.online }
func (n *fakeNetwork) CurrentConnectionEntry() map[string]any {
	return map[string]any{"ssid": "Use current connection", "rssi": -40, "secure": false}
}

type vector struct {
	DeviceID                 string `json:"device_id"`
	NodeID                   string `json:"node_id"`
	MAC                      string `json:"mac"`
	FirmwareVersion          string `json:"firmware_version"`
	MobilePub                string `json:"mobile_pub"`
	MobileNonce              string `json:"mobile_nonce"`
	DeviceNonce              string `json:"device_nonce"`
	DevicePrivateScalarHex   string `json:"device_private_scalar_hex"`
	MobileTxKeyHex           string `json:"mobile_tx_key_hex"`
	MobileRxKeyHex           string `json:"mobile_rx_key_hex"`
	SessionID                string `json:"session_id"`
	ClientFinishedCiphertext string `json:"client_finished_ciphertext"`
	ClientFinishedTag        string `json:"client_finished_tag"`
}

func loadAppVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile("../pairing/testdata/link_pairing_v5.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		if v.SessionID == "z0eNLGw5mczvD4a1F2ubSQ" {
			return v
		}
	}
	t.Fatal("community_app_v5 vector not found")
	return vector{}
}

type mobileSide struct {
	t         *testing.T
	tx, rx    cipher.AEAD
	sessionID string
	counter   uint64
}

func newMobileSide(t *testing.T, v vector) *mobileSide {
	t.Helper()
	gcm := func(hexKey string) cipher.AEAD {
		key, err := hex.DecodeString(hexKey)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	return &mobileSide{t: t, tx: gcm(v.MobileTxKeyHex), rx: gcm(v.MobileRxKeyHex), sessionID: v.SessionID}
}

func (m *mobileSide) seal(plaintext string) map[string]any {
	counter := m.counter
	m.counter++
	sealed := m.tx.Seal(nil, pairing.RecordNonce(0, counter), []byte(plaintext), pairing.RecordAAD(m.sessionID, 0, counter))
	return map[string]any{
		"action":     "pairing_encrypted",
		"session_id": m.sessionID,
		"counter":    strconv.FormatUint(counter, 10),
		"ciphertext": pairing.B64URLEncode(sealed[:len(sealed)-16]),
		"tag":        pairing.B64URLEncode(sealed[len(sealed)-16:]),
	}
}

func (m *mobileSide) open(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	envelope, err := wirejson.DecodeMap(raw)
	if err != nil {
		t.Fatalf("device record is not JSON: %v (%q)", err, raw)
	}
	if envelope["type"] != "pairing_encrypted" {
		t.Fatalf("device record type = %v, raw %q", envelope["type"], raw)
	}
	counter, err := pairing.ParseCounter(envelope["counter"])
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := pairing.B64URLDecode(envelope["ciphertext"].(string), 16384)
	tag, _ := pairing.B64URLDecode(envelope["tag"].(string), 4096)
	sealed := append(append([]byte(nil), ct...), tag...)
	plaintext, err := m.rx.Open(nil, pairing.RecordNonce(1, counter), sealed, pairing.RecordAAD(m.sessionID, 1, counter))
	if err != nil {
		t.Fatalf("open device record: %v", err)
	}
	decoded, err := wirejson.DecodeMap(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

type fixture struct {
	controller *Controller
	transport  *fakeTransport
	assembler  *ChunkAssembler

	mu          sync.Mutex
	provisioned []Credentials
	completed   bool
}

func (f *fixture) provisionedCreds() []Credentials {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Credentials(nil), f.provisioned...)
}

func (f *fixture) isCompleted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.completed
}

func newFixture(t *testing.T, v vector, online bool) *fixture {
	t.Helper()
	scalar, err := hex.DecodeString(v.DevicePrivateScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	deviceNonce, err := pairing.B64URLDecode(v.DeviceNonce, 4096)
	if err != nil {
		t.Fatal(err)
	}
	session := pairing.NewSession(pairing.Options{
		NodeID: v.NodeID, DeviceID: v.DeviceID, MAC: v.MAC, FirmwareVersion: v.FirmwareVersion,
		GenerateKey: func() (*ecdh.PrivateKey, error) { return key, nil },
		RandomBytes: func(n int) ([]byte, error) { return append([]byte(nil), deviceNonce...), nil },
	})
	f := &fixture{transport: &fakeTransport{}, assembler: NewChunkAssembler()}
	id := identity.Identity{MAC: v.MAC}
	f.controller = NewController(session, id, "0.1.0", f.transport, &fakeNetwork{online: online},
		func(creds Credentials, commit func(func() bool) bool) error {
			f.mu.Lock()
			f.provisioned = append(f.provisioned, creds)
			f.mu.Unlock()
			if !commit(func() bool { return true }) {
				return &ProvisionFailed{Status: "error_storage"}
			}
			return nil
		},
		func() {
			f.mu.Lock()
			f.completed = true
			f.mu.Unlock()
		},
	)
	return f
}

func (f *fixture) send(t *testing.T, message []byte) {
	t.Helper()
	packets, err := EncodeChunks(message, 512)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packets {
		f.controller.OnWrite(p)
	}
}

func (f *fixture) waitMessages(t *testing.T, want int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var messages [][]byte
	for time.Now().Before(deadline) {
		messages = append(messages, f.transport.drain(f.assembler)...)
		if len(messages) >= want {
			return messages
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("got %d messages, want %d", len(messages), want)
	return nil
}

func TestControllerFullSetupFlow(t *testing.T) {
	v := loadAppVector(t)
	f := newFixture(t, v, true)
	f.controller.Start()
	defer f.controller.Stop()
	phone := newMobileSide(t, v)

	// Plaintext sensitive action before pairing: bare status string back.
	f.send(t, []byte(`{"action":"provision_v2"}`))
	messages := f.waitMessages(t, 1)
	if string(messages[0]) != "error_encryption_required" {
		t.Fatalf("plaintext provision reply = %q", messages[0])
	}

	// device_info is public plaintext.
	f.send(t, []byte(`{"action":"get_device_info"}`))
	messages = f.waitMessages(t, 1)
	info, err := wirejson.DecodeMap(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if info["type"] != "device_info" || info["node_id"] != v.NodeID || info["pairing_policy"] != "confirm_app" {
		t.Fatalf("device_info = %v", info)
	}

	// Hello -> pairing_ready.
	hello := `{"action":"pairing_client_hello","version":5,"pairing_auth":"none","pairing_policy":"confirm_app","mobile_pub":"` +
		v.MobilePub + `","mobile_nonce":"` + v.MobileNonce + `"}`
	f.send(t, []byte(hello))
	messages = f.waitMessages(t, 1)
	ready, err := wirejson.DecodeMap(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if ready["type"] != "pairing_ready" || ready["session_id"] != v.SessionID {
		t.Fatalf("pairing_ready = %v", ready)
	}

	// After hello, plaintext sensitive actions are ignored silently.
	f.send(t, []byte(`{"action":"wifi_scan"}`))
	time.Sleep(150 * time.Millisecond)
	if extra := f.transport.drain(f.assembler); len(extra) != 0 {
		t.Fatalf("plaintext wifi_scan after hello got a reply: %q", extra)
	}

	// Encrypted client_finished -> encrypted pairing_confirmed.
	finished := map[string]any{
		"action": "pairing_encrypted", "session_id": v.SessionID, "counter": "0",
		"ciphertext": v.ClientFinishedCiphertext, "tag": v.ClientFinishedTag,
	}
	f.send(t, wirejson.MustMarshal(finished))
	messages = f.waitMessages(t, 1)
	status := phone.open(t, messages[0])
	if status["type"] != "status" || status["status"] != "pairing_confirmed" {
		t.Fatalf("status = %v", status)
	}
	phone.counter = 1 // client_finished consumed counter 0

	// Encrypted wifi_scan -> encrypted result with the current connection.
	f.send(t, wirejson.MustMarshal(phone.seal(`{"action":"wifi_scan"}`)))
	messages = f.waitMessages(t, 1)
	scan := phone.open(t, messages[0])
	if scan["type"] != "wifi_scan_result" {
		t.Fatalf("scan = %v", scan)
	}
	networks, _ := scan["networks"].([]any)
	if len(networks) != 1 {
		t.Fatalf("networks = %v", scan["networks"])
	}

	// Encrypted provision_v2 -> wifi_connecting, wifi_connected, auth_ok.
	provision := `{"action":"provision_v2","ssid":"Home","password":"pw",` +
		`"access_token":"at","refresh_token":"rt","token_type":"device","username":"u"}`
	f.send(t, wirejson.MustMarshal(phone.seal(provision)))
	messages = f.waitMessages(t, 3)
	var statuses []string
	for _, raw := range messages {
		statuses = append(statuses, phone.open(t, raw)["status"].(string))
	}
	if len(statuses) != 3 || statuses[0] != "wifi_connecting" || statuses[1] != "wifi_connected" || statuses[2] != "auth_ok" {
		t.Fatalf("provision statuses = %v", statuses)
	}
	provisioned := f.provisionedCreds()
	if len(provisioned) != 1 || provisioned[0].AccessToken != "at" {
		t.Fatalf("provisioned = %+v", provisioned)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !f.isCompleted() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !f.isCompleted() {
		t.Fatal("on_complete was not called")
	}
}

func TestControllerBadRecordDisconnects(t *testing.T) {
	v := loadAppVector(t)
	f := newFixture(t, v, true)
	f.controller.Start()
	defer f.controller.Stop()

	hello := `{"action":"pairing_client_hello","version":5,"pairing_auth":"none","pairing_policy":"confirm_app","mobile_pub":"` +
		v.MobilePub + `","mobile_nonce":"` + v.MobileNonce + `"}`
	f.send(t, []byte(hello))
	f.waitMessages(t, 1)

	bad := map[string]any{
		"action": "pairing_encrypted", "session_id": v.SessionID, "counter": "0",
		"ciphertext": "AAAA", "tag": "AAAAAAAAAAAAAAAAAAAAAA",
	}
	f.send(t, wirejson.MustMarshal(bad))
	// The failed decrypt clears the session; with plaintext blocked after
	// the hello, the reference suppresses the status and simply drops the
	// connection after 0.3s.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.transport.mu.Lock()
		n := len(f.transport.disconnects)
		f.transport.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if extra := f.transport.drain(f.assembler); len(extra) != 0 {
		t.Fatalf("bad record got a reply: %q", extra)
	}
	f.transport.mu.Lock()
	disconnects := append([]time.Duration(nil), f.transport.disconnects...)
	f.transport.mu.Unlock()
	if len(disconnects) != 1 || disconnects[0] != 300*time.Millisecond {
		t.Fatalf("disconnects = %v", disconnects)
	}
}

func TestControllerBadHelloGetsPlaintextStatus(t *testing.T) {
	v := loadAppVector(t)
	f := newFixture(t, v, true)
	f.controller.Start()
	defer f.controller.Stop()

	hello := `{"action":"pairing_client_hello","version":4,"pairing_auth":"none","pairing_policy":"confirm_app","mobile_pub":"` +
		v.MobilePub + `","mobile_nonce":"` + v.MobileNonce + `"}`
	f.send(t, []byte(hello))
	messages := f.waitMessages(t, 1)
	if string(messages[0]) != "error_pairing_invalid_hello" {
		t.Fatalf("bad hello reply = %q", messages[0])
	}
}
