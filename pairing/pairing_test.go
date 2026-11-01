package pairing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"musegadget/wirejson"
)

type vector struct {
	Name                     string `json:"name"`
	Community                bool   `json:"community"`
	PairingAuthEpoch         int    `json:"pairing_auth_epoch"`
	PairingPolicy            string `json:"pairing_policy"`
	DeviceID                 string `json:"device_id"`
	NodeID                   string `json:"node_id"`
	MAC                      string `json:"mac"`
	FirmwareVersion          string `json:"firmware_version"`
	MobilePub                string `json:"mobile_pub"`
	DevicePub                string `json:"device_pub"`
	MobileNonce              string `json:"mobile_nonce"`
	DeviceNonce              string `json:"device_nonce"`
	DevicePrivateScalarHex   string `json:"device_private_scalar_hex"`
	ECDHSecretHex            string `json:"ecdh_secret_hex"`
	Transcript               string `json:"transcript"`
	TranscriptHash           string `json:"transcript_hash"`
	MobileTxKeyHex           string `json:"mobile_tx_key_hex"`
	MobileRxKeyHex           string `json:"mobile_rx_key_hex"`
	SessionID                string `json:"session_id"`
	ClientFinishedCiphertext string `json:"client_finished_ciphertext"`
	ClientFinishedTag        string `json:"client_finished_tag"`
	ClientFinishedPlaintext  string `json:"client_finished_plaintext"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile("testdata/link_pairing_v5.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 3 {
		t.Fatalf("got %d vectors, want 3", len(file.Vectors))
	}
	return file.Vectors
}

func appVector(t *testing.T) vector {
	t.Helper()
	for _, v := range loadVectors(t) {
		if v.Name == "community_app_v5" {
			return v
		}
	}
	t.Fatal("community_app_v5 vector missing")
	return vector{}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := B64URLDecode(s, maxB64Chars)
	if err != nil {
		t.Fatalf("b64 decode %q: %v", s, err)
	}
	return b
}

type fakeClock struct{ now float64 }

func (c *fakeClock) Now() float64      { return c.now }
func (c *fakeClock) Advance(s float64) { c.now += s }

func makeDevice(t *testing.T, v vector, clock *fakeClock, sdkToken string) *Session {
	t.Helper()
	scalar, err := hex.DecodeString(v.DevicePrivateScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	deviceNonce := unb64(t, v.DeviceNonce)
	return NewSession(Options{
		NodeID:          v.NodeID,
		DeviceID:        v.DeviceID,
		MAC:             v.MAC,
		FirmwareVersion: v.FirmwareVersion,
		SDKToken:        sdkToken,
		Clock:           clock.Now,
		GenerateKey:     func() (*ecdh.PrivateKey, error) { return key, nil },
		RandomBytes: func(n int) ([]byte, error) {
			if n != len(deviceNonce) {
				t.Fatalf("random_bytes(%d), device nonce is %d bytes", n, len(deviceNonce))
			}
			return append([]byte(nil), deviceNonce...), nil
		},
	})
}

func helloFor(v vector) map[string]any {
	return map[string]any{
		"action":         "pairing_client_hello",
		"version":        json.Number("5"),
		"pairing_auth":   "none",
		"pairing_policy": "confirm_app",
		"mobile_pub":     v.MobilePub,
		"mobile_nonce":   v.MobileNonce,
	}
}

func clientFinishedRecord(v vector) map[string]any {
	return map[string]any{
		"action":     "pairing_encrypted",
		"session_id": v.SessionID,
		"counter":    "0",
		"ciphertext": v.ClientFinishedCiphertext,
		"tag":        v.ClientFinishedTag,
	}
}

func TestTranscriptMatchesEveryVector(t *testing.T) {
	for _, v := range loadVectors(t) {
		transcript, err := BuildTranscript(TranscriptParams{
			Community:       v.Community,
			AuthEpoch:       v.PairingAuthEpoch,
			Policy:          v.PairingPolicy,
			DeviceID:        v.DeviceID,
			NodeID:          v.NodeID,
			MAC:             v.MAC,
			FirmwareVersion: v.FirmwareVersion,
			MobilePub:       v.MobilePub,
			DevicePub:       v.DevicePub,
			MobileNonce:     v.MobileNonce,
			DeviceNonce:     v.DeviceNonce,
		})
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if transcript != v.Transcript {
			t.Errorf("%s: transcript mismatch:\n got: %q\nwant: %q", v.Name, transcript, v.Transcript)
		}
		hash := sha256.Sum256([]byte(transcript))
		if got := B64URLEncode(hash[:]); got != v.TranscriptHash {
			t.Errorf("%s: transcript_hash = %s, want %s", v.Name, got, v.TranscriptHash)
		}
	}
}

func TestKeyScheduleMatchesEveryVector(t *testing.T) {
	for _, v := range loadVectors(t) {
		secret, err := hex.DecodeString(v.ECDHSecretHex)
		if err != nil {
			t.Fatal(err)
		}
		tx, rx, sessionID := DeriveSessionKeys(secret,
			unb64(t, v.MobileNonce), unb64(t, v.DeviceNonce), unb64(t, v.TranscriptHash))
		if hex.EncodeToString(tx) != v.MobileTxKeyHex {
			t.Errorf("%s: mobile_tx = %x, want %s", v.Name, tx, v.MobileTxKeyHex)
		}
		if hex.EncodeToString(rx) != v.MobileRxKeyHex {
			t.Errorf("%s: mobile_rx = %x, want %s", v.Name, rx, v.MobileRxKeyHex)
		}
		if got := B64URLEncode(sessionID); got != v.SessionID {
			t.Errorf("%s: session_id = %s, want %s", v.Name, got, v.SessionID)
		}
	}
}

func TestTranscriptRejectsAppPolicyForOfficialDevices(t *testing.T) {
	_, err := BuildTranscript(TranscriptParams{
		Community: false, AuthEpoch: 1, Policy: "confirm_app",
		DeviceID: "d", NodeID: "n", MAC: "m", FirmwareVersion: "1",
		MobilePub: "a", DevicePub: "b", MobileNonce: "c", DeviceNonce: "e",
	})
	if err == nil {
		t.Fatal("expected an error for official + confirm_app")
	}
}

func TestDeviceInfoAdvertisesCommunityApp(t *testing.T) {
	v := appVector(t)
	device := makeDevice(t, v, &fakeClock{}, "")
	info := device.DeviceInfo()
	want := map[string]any{
		"device_id": v.DeviceID, "mac": v.MAC, "model": "hatch_link",
		"pairing_protocol": 5, "pairing_auth": "none",
		"pairing_auth_epoch": 0, "pairing_policy": "confirm_app",
	}
	if len(info) != len(want) {
		t.Fatalf("device_info has %d fields, want %d", len(info), len(want))
	}
	for key, wantValue := range want {
		got, ok := info.Get(key)
		if !ok || got != wantValue {
			t.Errorf("device_info[%q] = %v, want %v", key, got, wantValue)
		}
	}
}

func TestHelloProducesVectorPairingReady(t *testing.T) {
	v := appVector(t)
	device := makeDevice(t, v, &fakeClock{}, "")
	ready, err := device.HandleHello(helloFor(v))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"type": "pairing_ready", "version": 5,
		"device_id": v.DeviceID, "node_id": v.NodeID, "mac": v.MAC,
		"model": "hatch_link", "firmware_version": v.FirmwareVersion,
		"pairing_auth": "none", "pairing_auth_epoch": 0,
		"pairing_policy": "confirm_app",
		"device_pub":     v.DevicePub, "device_nonce": v.DeviceNonce,
		"transcript_hash": v.TranscriptHash, "session_id": v.SessionID,
	}
	if len(ready) != len(want) {
		t.Fatalf("pairing_ready has %d fields, want %d: %v", len(ready), len(want), ready)
	}
	for key, wantValue := range want {
		got, ok := ready.Get(key)
		if !ok || got != wantValue {
			t.Errorf("pairing_ready[%q] = %v, want %v", key, got, wantValue)
		}
	}
	if device.State() != StateWaitClientFinished {
		t.Errorf("state = %v, want wait_client_finished", device.State())
	}
}

// mobile is the phone side of the vector session, for round-trip checks.
type mobile struct {
	t         *testing.T
	tx, rx    cipher.AEAD
	sessionID string
}

func newMobile(t *testing.T, v vector) *mobile {
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
	return &mobile{t: t, tx: gcm(v.MobileTxKeyHex), rx: gcm(v.MobileRxKeyHex), sessionID: v.SessionID}
}

func (m *mobile) seal(plaintext string, counter uint64) map[string]any {
	sealed := m.tx.Seal(nil, RecordNonce(0, counter), []byte(plaintext), RecordAAD(m.sessionID, 0, counter))
	return map[string]any{
		"type":       "pairing_encrypted",
		"session_id": m.sessionID,
		"counter":    strconv.FormatUint(counter, 10),
		"ciphertext": B64URLEncode(sealed[:len(sealed)-16]),
		"tag":        B64URLEncode(sealed[len(sealed)-16:]),
	}
}

func (m *mobile) open(envelope wirejson.Obj) map[string]any {
	get := func(key string) string {
		value, ok := envelope.Get(key)
		if !ok {
			m.t.Fatalf("envelope missing %q", key)
		}
		s, _ := value.(string)
		return s
	}
	counter, err := ParseCounter(get("counter"))
	if err != nil {
		m.t.Fatal(err)
	}
	ct := unb64(m.t, get("ciphertext"))
	tag := unb64(m.t, get("tag"))
	sealed := append(append([]byte(nil), ct...), tag...)
	plaintext, err := m.rx.Open(nil, RecordNonce(1, counter), sealed, RecordAAD(m.sessionID, 1, counter))
	if err != nil {
		m.t.Fatalf("mobile open: %v", err)
	}
	decoded, err := wirejson.DecodeMap(plaintext)
	if err != nil {
		m.t.Fatal(err)
	}
	return decoded
}

func TestFullAppConfirmedHandshake(t *testing.T) {
	v := appVector(t)
	clock := &fakeClock{}
	device := makeDevice(t, v, clock, "")
	if _, err := device.HandleHello(helloFor(v)); err != nil {
		t.Fatal(err)
	}
	plaintext, err := device.Decrypt(clientFinishedRecord(v))
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != v.ClientFinishedPlaintext {
		t.Fatalf("client_finished plaintext = %q, want %q", plaintext, v.ClientFinishedPlaintext)
	}
	command, err := wirejson.DecodeMap([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	generation := device.HandleClientFinished(command)
	if generation == 0 {
		t.Fatal("handle_client_finished returned 0")
	}
	if !device.Confirmed() {
		t.Fatal("device not confirmed after client_finished")
	}

	phone := newMobile(t, v)
	envelope, ok := device.EncryptStatus("pairing_confirmed", generation)
	if !ok {
		t.Fatal("encrypt_status returned nil")
	}
	confirmed := phone.open(envelope)
	if confirmed["type"] != "status" || confirmed["status"] != "pairing_confirmed" {
		t.Fatalf("confirmed status = %v", confirmed)
	}
	if _, present := confirmed["sdk_token"]; present {
		t.Fatal("status carried an sdk_token but none was bound")
	}

	scan, err := device.Decrypt(phone.seal(`{"action":"wifi_scan"}`, 1))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := wirejson.DecodeMap([]byte(scan))
	if err != nil || decoded["action"] != "wifi_scan" {
		t.Fatalf("wifi_scan record = %q, %v", scan, err)
	}
}

func TestPairingConfirmedCarriesSDKToken(t *testing.T) {
	v := appVector(t)
	device := makeDevice(t, v, &fakeClock{}, "mgst_testtoken")
	if _, err := device.HandleHello(helloFor(v)); err != nil {
		t.Fatal(err)
	}
	plaintext, err := device.Decrypt(clientFinishedRecord(v))
	if err != nil {
		t.Fatal(err)
	}
	command, _ := wirejson.DecodeMap([]byte(plaintext))
	generation := device.HandleClientFinished(command)
	envelope, ok := device.EncryptStatus("pairing_confirmed", generation)
	if !ok {
		t.Fatal("encrypt_status returned nil")
	}
	confirmed := newMobile(t, v).open(envelope)
	if confirmed["sdk_token"] != "mgst_testtoken" {
		t.Fatalf("sdk_token = %v", confirmed["sdk_token"])
	}
}

func TestDecryptRejectsReplayAndClearsSession(t *testing.T) {
	v := appVector(t)
	device := makeDevice(t, v, &fakeClock{}, "")
	if _, err := device.HandleHello(helloFor(v)); err != nil {
		t.Fatal(err)
	}
	if _, err := device.Decrypt(clientFinishedRecord(v)); err != nil {
		t.Fatal(err)
	}
	// Replay of counter 0 must fail and clear the session.
	if _, err := device.Decrypt(clientFinishedRecord(v)); err == nil {
		t.Fatal("replayed record accepted")
	} else if perr, ok := err.(*Error); !ok || perr.Status != StatusDecrypt {
		t.Fatalf("replay error = %v", err)
	}
	if device.State() != StateIdle {
		t.Fatalf("state after replay = %v, want idle", device.State())
	}
}

func TestHelloRejectsBadVersionAndPolicy(t *testing.T) {
	v := appVector(t)
	device := makeDevice(t, v, &fakeClock{}, "")
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["version"] = json.Number("4") },
		func(m map[string]any) { m["version"] = true },
		func(m map[string]any) { m["pairing_auth"] = "fleet_ecdsa_p256_v1" },
		func(m map[string]any) { m["pairing_policy"] = "confirm_press" },
		func(m map[string]any) { m["mobile_pub"] = "AAAA" },
	} {
		hello := helloFor(v)
		mutate(hello)
		if _, err := device.HandleHello(hello); err == nil {
			t.Fatalf("hello accepted after mutation %v", hello)
		} else if perr, ok := err.(*Error); !ok || perr.Status != StatusInvalidHello {
			t.Fatalf("hello error = %v", err)
		}
	}
}

func TestSessionExpiryClearsKeys(t *testing.T) {
	v := appVector(t)
	clock := &fakeClock{}
	device := makeDevice(t, v, clock, "")
	if _, err := device.HandleHello(helloFor(v)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(ClientFinishedTimeoutS + 1)
	if _, err := device.Decrypt(clientFinishedRecord(v)); err == nil {
		t.Fatal("record accepted after the client-finished window")
	}
	if device.State() != StateIdle {
		t.Fatalf("state = %v, want idle", device.State())
	}
}
