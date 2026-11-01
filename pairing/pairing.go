// Package pairing is the device side of Muse Gadget BLE pairing, protocol
// version 5, mirroring musegadget.pairing. Community mode only:
// pairing_auth is "none" and the policy is confirm_app. The transcript, key
// schedule and record encryption match the reference exactly and are
// verified against tests/vectors/link_pairing_v5.json.
package pairing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"musegadget/wirejson"
)

const (
	Version = 5
	Model   = "hatch_link"
	Suite   = "p256-hkdf-sha256-aes-gcm-v1"

	PolicyButton = "confirm_press"
	PolicyApp    = "confirm_app"

	AuthOfficial  = "fleet_ecdsa_p256_v1"
	AuthCommunity = "none"

	ButtonConfirmTimeoutS = 60

	RecordLabel    = "hatch-link ble setup v1"
	sessionIDLabel = "hatch-link session id v1"

	ClientFinishedTimeoutS = 60
	ConfirmedTimeoutS      = 120
	ProvisioningTimeoutS   = 120

	StatusInvalidHello = "error_pairing_invalid_hello"
	StatusDecrypt      = "error_pairing_decrypt"
)

const (
	p256PointBytes    = 65
	nonceBytes        = 16
	sessionIDBytes    = 16
	tagBytes          = 16
	maxB64Chars       = 4096
	maxCiphertextB64  = 16384
	directionToDevice = 0
	directionFrom     = 1
)

// Error is a handshake failure; Status is the wire error to report.
type Error struct{ Status string }

func (e *Error) Error() string { return e.Status }

// State is the pairing session state.
type State int

const (
	StateIdle State = iota
	StateWaitClientFinished
	StateReady
	StateProvisioning
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateWaitClientFinished:
		return "wait_client_finished"
	case StateReady:
		return "ready"
	case StateProvisioning:
		return "provisioning"
	}
	return "unknown"
}

// B64URLEncode encodes unpadded base64url.
func B64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

var b64urlChars = func() [256]bool {
	var table [256]bool
	for _, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") {
		table[c] = true
	}
	return table
}()

// B64URLDecode decodes unpadded base64url, rejecting anything the firmware
// rejects: non-strings (handled by callers), empty or over-long input,
// length % 4 == 1, and characters outside the URL-safe alphabet.
func B64URLDecode(text string, maxChars int) ([]byte, error) {
	if len(text) == 0 || len(text) > maxChars {
		return nil, errors.New("invalid base64url length")
	}
	if len(text)%4 == 1 {
		return nil, errors.New("invalid base64url")
	}
	for i := 0; i < len(text); i++ {
		if !b64urlChars[text[i]] {
			return nil, errors.New("invalid base64url")
		}
	}
	return base64.RawURLEncoding.DecodeString(text)
}

// ParseCounter parses a decimal record counter (< 2^64).
func ParseCounter(text any) (uint64, error) {
	s, ok := text.(string)
	if !ok || s == "" {
		return 0, errors.New("invalid counter")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("invalid counter")
		}
	}
	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("counter overflow")
	}
	return value, nil
}

// TranscriptParams are the fields of the canonical v5 transcript.
type TranscriptParams struct {
	Community       bool
	AuthEpoch       int
	Policy          string
	DeviceID        string
	NodeID          string
	MAC             string
	FirmwareVersion string
	MobilePub       string // base64url of the raw 65-byte point
	DevicePub       string
	MobileNonce     string // base64url of 16 bytes
	DeviceNonce     string
}

// BuildTranscript builds the canonical v5 transcript; its SHA-256 is the
// transcript_hash.
func BuildTranscript(p TranscriptParams) (string, error) {
	button := p.Policy == PolicyButton
	if !button && !(p.Community && p.Policy == PolicyApp) {
		return "", fmt.Errorf("unsupported pairing policy: %q", p.Policy)
	}
	if p.Community {
		if p.AuthEpoch != 0 {
			return "", fmt.Errorf("invalid auth epoch: %d", p.AuthEpoch)
		}
	} else if p.AuthEpoch <= 0 {
		return "", fmt.Errorf("invalid auth epoch: %d", p.AuthEpoch)
	}
	for _, field := range []string{p.DeviceID, p.NodeID, p.MAC, p.FirmwareVersion,
		p.MobilePub, p.DevicePub, p.MobileNonce, p.DeviceNonce} {
		if field == "" {
			return "", errors.New("transcript fields must be non-empty")
		}
	}
	auth := AuthOfficial
	if p.Community {
		auth = AuthCommunity
	}
	confirmTimeout := 0
	if button {
		confirmTimeout = ButtonConfirmTimeoutS
	}
	lines := []string{
		fmt.Sprintf("hatch-link-pairing-v%d", Version),
		fmt.Sprintf("version=%d", Version),
		"initiator_role=mobile",
		"responder_role=link",
		"device_id=" + p.DeviceID,
		"node_id=" + p.NodeID,
		"mac=" + p.MAC,
		"model=" + Model,
		"firmware_version=" + p.FirmwareVersion,
		"selected_cipher_suite=" + Suite,
		"pairing_auth=" + auth,
		fmt.Sprintf("pairing_auth_epoch=%d", p.AuthEpoch),
		"pairing_policy=" + p.Policy,
		fmt.Sprintf("confirm_timeout_seconds=%d", confirmTimeout),
		"mobile_pub=" + p.MobilePub,
		"device_pub=" + p.DevicePub,
		"mobile_nonce=" + p.MobileNonce,
		"device_nonce=" + p.DeviceNonce,
	}
	return strings.Join(lines, "\n"), nil
}

func hkdfExpandSHA256(prk, info []byte, length int) []byte {
	var out, t []byte
	for counter := byte(1); len(out) < length; counter++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)
	return hkdfExpandSHA256(prk, info, length)
}

// DeriveSessionKeys returns (mobile_tx_key, mobile_rx_key, session_id).
// mobile_tx_key decrypts records the device receives and mobile_rx_key
// encrypts records it sends.
func DeriveSessionKeys(ecdhSecret, mobileNonce, deviceNonce, transcriptHash []byte) (tx, rx, sessionID []byte) {
	h := sha256.New()
	h.Write(mobileNonce)
	h.Write(deviceNonce)
	h.Write(transcriptHash)
	salt := h.Sum(nil)
	sessionSecret := hkdfSHA256(ecdhSecret, salt, []byte(RecordLabel), 32)
	tx = hkdfExpandSHA256(sessionSecret, []byte("mobile->device"), 32)
	rx = hkdfExpandSHA256(sessionSecret, []byte("device->mobile"), 32)
	h2 := sha256.New()
	h2.Write([]byte(sessionIDLabel))
	h2.Write(transcriptHash)
	h2.Write(ecdhSecret)
	sessionID = h2.Sum(nil)[:sessionIDBytes]
	return tx, rx, sessionID
}

// RecordNonce is the 12-byte AES-GCM nonce for a record.
func RecordNonce(direction int, counter uint64) []byte {
	nonce := make([]byte, 12)
	nonce[0] = byte(direction)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// RecordAAD is the additional authenticated data for a record.
func RecordAAD(sessionIDB64 string, direction int, counter uint64) []byte {
	arrow := "m2d"
	if direction != directionToDevice {
		arrow = "d2m"
	}
	return []byte(fmt.Sprintf("%s|%s|%s|%d", RecordLabel, sessionIDB64, arrow, counter))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Options configure a Session. The function fields exist so tests can fix
// the clock, the device key and the nonce, as the reference tests do.
type Options struct {
	NodeID          string
	DeviceID        string
	MAC             string
	FirmwareVersion string
	SDKToken        string
	Clock           func() float64 // monotonic seconds
	GenerateKey     func() (*ecdh.PrivateKey, error)
	RandomBytes     func(int) ([]byte, error)
}

// Session is one device's pairing state; safe for concurrent use. Methods
// that advance the handshake return a nonzero generation token; deferred
// work should hold on to it and check IsCurrent before acting.
type Session struct {
	nodeID      string
	deviceID    string
	mac         string
	firmware    string
	sdkToken    string
	clock       func() float64
	generateKey func() (*ecdh.PrivateKey, error)
	randomBytes func(int) ([]byte, error)

	mu           sync.Mutex
	generation   int64
	state        State
	deadline     float64
	rx, tx       cipher.AEAD
	sessionIDB64 string
	rxCounter    uint64
	txCounter    uint64
}

// NewSession creates a session in the idle state.
func NewSession(opts Options) *Session {
	s := &Session{
		nodeID:      opts.NodeID,
		deviceID:    opts.DeviceID,
		mac:         opts.MAC,
		firmware:    opts.FirmwareVersion,
		sdkToken:    opts.SDKToken,
		clock:       opts.Clock,
		generateKey: opts.GenerateKey,
		randomBytes: opts.RandomBytes,
	}
	if s.firmware == "" {
		s.firmware = "unknown"
	}
	if s.clock == nil {
		s.clock = monotonicClock()
	}
	if s.generateKey == nil {
		s.generateKey = func() (*ecdh.PrivateKey, error) {
			return ecdh.P256().GenerateKey(rand.Reader)
		}
	}
	if s.randomBytes == nil {
		s.randomBytes = func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		}
	}
	s.resetLocked()
	return s
}

func monotonicClock() func() float64 {
	start := time.Now()
	return func() float64 { return time.Since(start).Seconds() }
}

// DeviceInfo returns the pairing fields for the get_device_info response.
func (s *Session) DeviceInfo() wirejson.Obj {
	return wirejson.Obj{
		{Key: "device_id", Value: s.deviceID},
		{Key: "mac", Value: s.mac},
		{Key: "model", Value: Model},
		{Key: "pairing_protocol", Value: Version},
		{Key: "pairing_auth", Value: AuthCommunity},
		{Key: "pairing_auth_epoch", Value: 0},
		{Key: "pairing_policy", Value: PolicyApp},
	}
}

// State returns the current state, applying expiry.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	return s.state
}

// Confirmed reports whether the session is confirmed (ready/provisioning).
func (s *Session) Confirmed() bool {
	switch s.State() {
	case StateReady, StateProvisioning:
		return true
	}
	return false
}

// Generation returns the current generation token.
func (s *Session) Generation() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// IsCurrent reports whether generation is the live one.
func (s *Session) IsCurrent(generation int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return generation != 0 && generation == s.generation
}

// Reset clears the session and advances the generation.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetLocked()
}

// HandleHello starts a session from a pairing_client_hello message and
// returns the pairing_ready reply.
func (s *Session) HandleHello(message map[string]any) (wirejson.Obj, error) {
	version, versionOK := helloVersion(message["version"])
	if !versionOK || version != Version ||
		message["pairing_auth"] != AuthCommunity ||
		message["pairing_policy"] != PolicyApp {
		return nil, &Error{StatusInvalidHello}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetLocked()

	mobilePubText, _ := message["mobile_pub"].(string)
	mobileNonceText, _ := message["mobile_nonce"].(string)
	mobilePub, errPub := B64URLDecode(mobilePubText, maxB64Chars)
	mobileNonce, errNonce := B64URLDecode(mobileNonceText, maxB64Chars)
	var peer *ecdh.PublicKey
	var errPeer error
	if errPub == nil && errNonce == nil {
		if len(mobilePub) != p256PointBytes || mobilePub[0] != 0x04 || len(mobileNonce) != nonceBytes {
			errPeer = errors.New("invalid hello key material")
		} else {
			peer, errPeer = ecdh.P256().NewPublicKey(mobilePub)
		}
	}
	if errPub != nil || errNonce != nil || errPeer != nil {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}

	deviceKey, err := s.generateKey()
	if err != nil {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}
	devicePub := deviceKey.PublicKey().Bytes()
	deviceNonce, err := s.randomBytes(nonceBytes)
	if err != nil || len(deviceNonce) != nonceBytes {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}
	transcript, err := BuildTranscript(TranscriptParams{
		Community:       true,
		AuthEpoch:       0,
		Policy:          PolicyApp,
		DeviceID:        s.deviceID,
		NodeID:          s.nodeID,
		MAC:             s.mac,
		FirmwareVersion: s.firmware,
		MobilePub:       B64URLEncode(mobilePub),
		DevicePub:       B64URLEncode(devicePub),
		MobileNonce:     B64URLEncode(mobileNonce),
		DeviceNonce:     B64URLEncode(deviceNonce),
	})
	if err != nil {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}
	transcriptHash := sha256.Sum256([]byte(transcript))
	secret, err := deviceKey.ECDH(peer)
	if err != nil {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}
	rxKey, txKey, sessionID := DeriveSessionKeys(secret, mobileNonce, deviceNonce, transcriptHash[:])
	rx, err := newGCM(rxKey)
	if err != nil {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}
	tx, err := newGCM(txKey)
	if err != nil {
		s.resetLocked()
		return nil, &Error{StatusInvalidHello}
	}
	s.rx, s.tx = rx, tx
	s.sessionIDB64 = B64URLEncode(sessionID)
	s.rxCounter, s.txCounter = 0, 0
	s.state = StateWaitClientFinished
	s.deadline = s.clock() + ClientFinishedTimeoutS
	return wirejson.Obj{
		{Key: "type", Value: "pairing_ready"},
		{Key: "version", Value: Version},
		{Key: "device_id", Value: s.deviceID},
		{Key: "node_id", Value: s.nodeID},
		{Key: "mac", Value: s.mac},
		{Key: "model", Value: Model},
		{Key: "firmware_version", Value: s.firmware},
		{Key: "pairing_auth", Value: AuthCommunity},
		{Key: "pairing_auth_epoch", Value: 0},
		{Key: "pairing_policy", Value: PolicyApp},
		{Key: "device_pub", Value: B64URLEncode(devicePub)},
		{Key: "device_nonce", Value: B64URLEncode(deviceNonce)},
		{Key: "transcript_hash", Value: B64URLEncode(transcriptHash[:])},
		{Key: "session_id", Value: s.sessionIDB64},
	}, nil
}

func helloVersion(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// Decrypt opens one mobile-to-device pairing_encrypted record and returns
// its plaintext. Any failure (wrong session, skipped or replayed counter,
// bad tag, expiry) clears the session, as the firmware does.
func (s *Session) Decrypt(envelope map[string]any) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expireLocked() || s.state == StateIdle {
		s.resetLocked()
		return "", &Error{StatusDecrypt}
	}
	fail := func() (string, error) {
		s.resetLocked()
		return "", &Error{StatusDecrypt}
	}
	sessionID, _ := envelope["session_id"].(string)
	if sessionID != s.sessionIDB64 {
		return fail()
	}
	counter, err := ParseCounter(envelope["counter"])
	if err != nil || counter != s.rxCounter {
		return fail()
	}
	ciphertextText, _ := envelope["ciphertext"].(string)
	tagText, _ := envelope["tag"].(string)
	ciphertext, err := B64URLDecode(ciphertextText, maxCiphertextB64)
	if err != nil {
		return fail()
	}
	tag, err := B64URLDecode(tagText, maxB64Chars)
	if err != nil || len(tag) != tagBytes {
		return fail()
	}
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	plaintext, err := s.rx.Open(nil, RecordNonce(directionToDevice, counter), sealed,
		RecordAAD(s.sessionIDB64, directionToDevice, counter))
	if err != nil || !utf8.Valid(plaintext) {
		return fail()
	}
	s.rxCounter++
	return string(plaintext), nil
}

// HandleClientFinished confirms the session after the first decrypted
// record. The command must be exactly {"action": "pairing_client_finished"}
// and must have been the first record. Returns the new generation, or 0
// (after clearing the session) if the record is invalid.
func (s *Session) HandleClientFinished(command map[string]any) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := len(command) == 1 && command["action"] == "pairing_client_finished" &&
		!s.expireLocked() &&
		s.state == StateWaitClientFinished &&
		s.rxCounter == 1
	if !ok {
		s.resetLocked()
		return 0
	}
	s.advanceGenerationLocked()
	s.state = StateReady
	s.deadline = s.clock() + ConfirmedTimeoutS
	return s.generation
}

// MarkProvisioning enters provisioning from a confirmed session and returns
// its generation (0 when the session is not confirmed).
func (s *Session) MarkProvisioning() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.expireLocked() && s.state == StateReady {
		s.advanceGenerationLocked()
		s.state = StateProvisioning
		s.deadline = s.clock() + ProvisioningTimeoutS
	}
	if s.state == StateProvisioning {
		return s.generation
	}
	return 0
}

// ExtendProvisioning extends the provisioning window for a live generation.
func (s *Session) ExtendProvisioning(generation int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provisioningLocked(generation) {
		s.deadline = s.clock() + ProvisioningTimeoutS
		return true
	}
	return false
}

// CommitProvisioning runs commit under the pairing lock if the session is
// still valid. commit must only persist local state; no network or BLE calls.
func (s *Session) CommitProvisioning(generation int64, commit func() bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.provisioningLocked(generation) && commit()
}

// EncryptJSON seals a device-to-mobile record. It returns ok=false when
// there is no active session, or when a nonzero generation no longer
// matches (the work it belongs to is stale).
func (s *Session) EncryptJSON(plaintext string, generation int64) (wirejson.Obj, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (generation != 0 && generation != s.generation) || s.expireLocked() || s.state == StateIdle {
		return nil, false
	}
	counter := s.txCounter
	sealed := s.tx.Seal(nil, RecordNonce(directionFrom, counter), []byte(plaintext),
		RecordAAD(s.sessionIDB64, directionFrom, counter))
	s.txCounter++
	return wirejson.Obj{
		{Key: "type", Value: "pairing_encrypted"},
		{Key: "session_id", Value: s.sessionIDB64},
		{Key: "counter", Value: strconv.FormatUint(counter, 10)},
		{Key: "ciphertext", Value: B64URLEncode(sealed[:len(sealed)-tagBytes])},
		{Key: "tag", Value: B64URLEncode(sealed[len(sealed)-tagBytes:])},
	}, true
}

// EncryptStatus seals a {"type":"status",...} record, adding the SDK token
// only for the pairing_confirmed status, as the reference does.
func (s *Session) EncryptStatus(status string, generation int64) (wirejson.Obj, bool) {
	message := wirejson.Obj{{Key: "type", Value: "status"}, {Key: "status", Value: status}}
	if s.sdkToken != "" && status == "pairing_confirmed" {
		message = append(message, wirejson.Pair{Key: "sdk_token", Value: s.sdkToken})
	}
	plaintext := wirejson.MustMarshal(message)
	return s.EncryptJSON(string(plaintext), generation)
}

func (s *Session) provisioningLocked(generation int64) bool {
	return generation != 0 && generation == s.generation &&
		!s.expireLocked() && s.state == StateProvisioning
}

func (s *Session) advanceGenerationLocked() { s.generation++ }

func (s *Session) resetLocked() {
	s.advanceGenerationLocked()
	s.clearLocked()
}

func (s *Session) clearLocked() {
	s.state = StateIdle
	s.deadline = 0
	s.rx, s.tx = nil, nil
	s.sessionIDB64 = ""
	s.rxCounter, s.txCounter = 0, 0
}

func (s *Session) expireLocked() bool {
	if s.state == StateIdle || s.clock() <= s.deadline {
		return false
	}
	// Drop the keys but keep the generation, so the owner of the expired
	// session can still recognise it and close the connection.
	s.clearLocked()
	return true
}
