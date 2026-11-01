package noise

// Noise_XX_25519_AESGCM_SHA256, mirroring musegadget.noise.noise_xx.
//
// This is hand-rolled rather than built on a Noise library because the
// reference deviates from the Noise spec's AESGCM nonce layout: the IV is
// four zero bytes followed by the nonce as an 8-byte BIG-endian integer,
// where the spec (and standard libraries) use little-endian. The deviation
// is verified byte-for-byte against the Python implementation in tests.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

var protocolName = []byte("Noise_XX_25519_AESGCM_SHA256")

const (
	dhKeyLen     = 32
	aeadTagLen   = 16
	minMsg2Len   = dhKeyLen + (dhKeyLen + aeadTagLen) + aeadTagLen
	minMsg3Len   = dhKeyLen + aeadTagLen + aeadTagLen
	maxSafeNonce = (1 << 53) - 1
)

var allZeros32 = make([]byte, 32)

// The X25519 low-order public keys the reference rejects explicitly.
var x25519LowOrderPoints = [][]byte{
	make([]byte, 32),
	append([]byte{1}, make([]byte, 31)...),
	{0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A,
		0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00},
	{0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF, 0x5B,
		0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0x57},
	append(append([]byte{0xEC}, bytes.Repeat([]byte{0xFF}, 30)...), 0x7F),
	append(append([]byte{0xED}, bytes.Repeat([]byte{0xFF}, 30)...), 0x7F),
	append(append([]byte{0xEE}, bytes.Repeat([]byte{0xFF}, 30)...), 0x7F),
}

// ProtocolError is raised when a Noise handshake or transport state
// machine is violated.
type ProtocolError struct{ Message string }

func (e *ProtocolError) Error() string { return e.Message }

func protocolErrorf(format string, args ...any) *ProtocolError {
	return &ProtocolError{Message: fmt.Sprintf(format, args...)}
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hkdfNoise(chainingKey, inputKeyMaterial []byte, numOutputs int) ([][]byte, error) {
	if numOutputs != 2 && numOutputs != 3 {
		return nil, errors.New("hkdf supports 2 or 3 outputs")
	}
	tempKey := hmacSHA256(chainingKey, inputKeyMaterial)
	output1 := hmacSHA256(tempKey, []byte{0x01})
	output2 := hmacSHA256(tempKey, append(append([]byte(nil), output1...), 0x02))
	if numOutputs == 2 {
		return [][]byte{output1, output2}, nil
	}
	output3 := hmacSHA256(tempKey, append(append([]byte(nil), output2...), 0x03))
	return [][]byte{output1, output2, output3}, nil
}

// BuildNonceIV builds the 12-byte AES-GCM IV for a nonce: four zero bytes
// and the nonce as an 8-byte big-endian integer (the reference's layout).
func BuildNonceIV(nonce uint64) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint64(iv[4:], nonce)
	return iv
}

// CipherState is a Noise cipher state: AES-256-GCM with a counter nonce.
// Any failure poisons it, as in the reference.
type CipherState struct {
	mu       sync.Mutex
	gcm      cipher.AEAD
	keyed    bool
	nonce    uint64
	poisoned bool
}

// NewCipherState creates an unkeyed state (encryption is a passthrough).
func NewCipherState() *CipherState { return &CipherState{} }

func (c *CipherState) assertAlive() error {
	if c.poisoned {
		return protocolErrorf("CipherState: poisoned after prior failure")
	}
	return nil
}

// InitializeKey keys the state with a 32-byte key and resets the nonce.
func (c *CipherState) InitializeKey(key []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.assertAlive(); err != nil {
		return err
	}
	if len(key) != 32 {
		return protocolErrorf("CipherState: AES-GCM key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	c.gcm = gcm
	c.keyed = true
	c.nonce = 0
	return nil
}

// HasKey reports whether the state is keyed.
func (c *CipherState) HasKey() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keyed
}

func (c *CipherState) nextNonce() (uint64, error) {
	if c.nonce >= maxSafeNonce {
		c.poisoned = true
		return 0, protocolErrorf("CipherState: nonce exhausted")
	}
	current := c.nonce
	c.nonce++
	return current, nil
}

// EncryptWithAD encrypts with additional data; unkeyed states pass through.
func (c *CipherState) EncryptWithAD(ad, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.assertAlive(); err != nil {
		return nil, err
	}
	if !c.keyed {
		return append([]byte(nil), plaintext...), nil
	}
	nonce, err := c.nextNonce()
	if err != nil {
		return nil, err
	}
	return c.gcm.Seal(nil, BuildNonceIV(nonce), plaintext, ad), nil
}

// DecryptWithAD decrypts with additional data; unkeyed states pass through.
func (c *CipherState) DecryptWithAD(ad, ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.assertAlive(); err != nil {
		return nil, err
	}
	if !c.keyed {
		return append([]byte(nil), ciphertext...), nil
	}
	nonce, err := c.nextNonce()
	if err != nil {
		return nil, err
	}
	plaintext, err := c.gcm.Open(nil, BuildNonceIV(nonce), ciphertext, ad)
	if err != nil {
		c.poisoned = true
		return nil, protocolErrorf("CipherState: decrypt failed")
	}
	return plaintext, nil
}

type x25519KeyPair struct {
	privateKey  *ecdh.PrivateKey
	publicBytes []byte
}

// generateX25519KeyPair is replaceable in tests for deterministic keys.
var generateX25519KeyPair = func() (*x25519KeyPair, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &x25519KeyPair{privateKey: privateKey, publicBytes: privateKey.PublicKey().Bytes()}, nil
}

func x25519DH(privateKey *ecdh.PrivateKey, publicKeyBytes []byte) ([]byte, error) {
	if len(publicKeyBytes) != dhKeyLen {
		return nil, protocolErrorf("x25519: invalid public key length")
	}
	for _, lowOrder := range x25519LowOrderPoints {
		if hmac.Equal(publicKeyBytes, lowOrder) {
			return nil, protocolErrorf("x25519: rejected low-order public key")
		}
	}
	publicKey, err := ecdh.X25519().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, protocolErrorf("x25519: invalid public key")
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, protocolErrorf("x25519: DH failed")
	}
	if hmac.Equal(shared, allZeros32) {
		return nil, protocolErrorf("x25519: DH produced all-zeros output")
	}
	return shared, nil
}

type symmetricState struct {
	ck     []byte
	h      []byte
	cipher *CipherState
}

func newSymmetricState() *symmetricState {
	return &symmetricState{ck: make([]byte, 32), h: make([]byte, 32), cipher: NewCipherState()}
}

func (s *symmetricState) initialize() {
	padded := make([]byte, 32)
	copy(padded, protocolName)
	s.h = padded
	s.ck = append([]byte(nil), padded...)
	s.mixHash(nil)
}

func (s *symmetricState) mixHash(data []byte) {
	sum := sha256.Sum256(append(append([]byte(nil), s.h...), data...))
	s.h = sum[:]
}

func (s *symmetricState) mixKey(inputKeyMaterial []byte) error {
	outputs, err := hkdfNoise(s.ck, inputKeyMaterial, 2)
	if err != nil {
		return err
	}
	s.ck = outputs[0]
	s.cipher = NewCipherState()
	return s.cipher.InitializeKey(outputs[1])
}

func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := s.cipher.EncryptWithAD(s.h, plaintext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return ciphertext, nil
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.cipher.DecryptWithAD(s.h, ciphertext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return plaintext, nil
}

func (s *symmetricState) split() (*CipherState, *CipherState, error) {
	outputs, err := hkdfNoise(s.ck, nil, 2)
	if err != nil {
		return nil, nil, err
	}
	s.ck = make([]byte, 32)
	s.h = make([]byte, 32)
	c1 := NewCipherState()
	if err := c1.InitializeKey(outputs[0]); err != nil {
		return nil, nil, err
	}
	c2 := NewCipherState()
	if err := c2.InitializeKey(outputs[1]); err != nil {
		return nil, nil, err
	}
	return c1, c2, nil
}

func (s *symmetricState) handshakeHash() []byte { return append([]byte(nil), s.h...) }

// Handshake phases, mirroring the reference's _Phase values.
const (
	phaseCreated     = 0
	phaseInitialized = 1
	phaseMsg1Sent    = 2
	phaseMsg2Read    = 3
	phaseMsg3Sent    = 4
	phaseSplit       = 5
	phaseDead        = 6
)

func requirePhase(actual, expected int, method string) error {
	if actual == phaseDead {
		return protocolErrorf("NoiseXX: %s called on dead handshake", method)
	}
	if actual != expected {
		return protocolErrorf("NoiseXX: %s called in wrong phase (expected %d, got %d)", method, expected, actual)
	}
	return nil
}

// Initiator is the device side of a Noise XX handshake. Like the
// reference, it has no persistent static key: a fresh one is generated for
// message 3, since the VM bearer already authenticated the device at the
// WebSocket upgrade.
type Initiator struct {
	ss    *symmetricState
	e, s  *x25519KeyPair
	re    []byte
	rs    []byte
	phase int
}

// NewInitiator creates an initiator in the created phase.
func NewInitiator() *Initiator {
	return &Initiator{ss: newSymmetricState()}
}

// Initialize initializes the symmetric state.
func (i *Initiator) Initialize() error {
	if err := requirePhase(i.phase, phaseCreated, "initialize"); err != nil {
		return err
	}
	i.ss.initialize()
	i.phase = phaseInitialized
	return nil
}

// WriteMessage1 generates the ephemeral key and returns message 1 (the
// 32-byte ephemeral public key).
func (i *Initiator) WriteMessage1() ([]byte, error) {
	if err := requirePhase(i.phase, phaseInitialized, "write_message1"); err != nil {
		return nil, err
	}
	e, err := generateX25519KeyPair()
	if err != nil {
		i.phase = phaseDead
		return nil, err
	}
	i.e = e
	i.ss.mixHash(i.e.publicBytes)
	if _, err := i.ss.encryptAndHash(nil); err != nil {
		i.phase = phaseDead
		return nil, err
	}
	i.phase = phaseMsg1Sent
	return i.e.publicBytes, nil
}

// ReadMessage2 processes message 2 and returns its payload.
func (i *Initiator) ReadMessage2(msg []byte) ([]byte, error) {
	if err := requirePhase(i.phase, phaseMsg1Sent, "read_message2"); err != nil {
		return nil, err
	}
	if len(msg) < minMsg2Len {
		i.phase = phaseDead
		return nil, protocolErrorf("NoiseXX: message 2 too short (%d < %d)", len(msg), minMsg2Len)
	}
	fail := func(err error) ([]byte, error) {
		i.phase = phaseDead
		return nil, err
	}
	offset := 0
	i.re = append([]byte(nil), msg[offset:offset+dhKeyLen]...)
	i.ss.mixHash(i.re)
	offset += dhKeyLen

	ee, err := x25519DH(i.e.privateKey, i.re)
	if err != nil {
		return fail(err)
	}
	if err := i.ss.mixKey(ee); err != nil {
		return fail(err)
	}
	rs, err := i.ss.decryptAndHash(msg[offset : offset+dhKeyLen+aeadTagLen])
	if err != nil {
		return fail(err)
	}
	i.rs = rs
	offset += dhKeyLen + aeadTagLen

	es, err := x25519DH(i.e.privateKey, i.rs)
	if err != nil {
		return fail(err)
	}
	if err := i.ss.mixKey(es); err != nil {
		return fail(err)
	}
	payload, err := i.ss.decryptAndHash(msg[offset:])
	if err != nil {
		return fail(err)
	}
	i.phase = phaseMsg2Read
	return payload, nil
}

// WriteMessage3 generates a fresh static key and returns message 3.
func (i *Initiator) WriteMessage3() ([]byte, error) {
	if err := requirePhase(i.phase, phaseMsg2Read, "write_message3"); err != nil {
		return nil, err
	}
	fail := func(err error) ([]byte, error) {
		i.phase = phaseDead
		return nil, err
	}
	s, err := generateX25519KeyPair()
	if err != nil {
		return fail(err)
	}
	i.s = s
	encS, err := i.ss.encryptAndHash(i.s.publicBytes)
	if err != nil {
		return fail(err)
	}
	se, err := x25519DH(i.s.privateKey, i.re)
	if err != nil {
		return fail(err)
	}
	if err := i.ss.mixKey(se); err != nil {
		return fail(err)
	}
	encPayload, err := i.ss.encryptAndHash(nil)
	if err != nil {
		return fail(err)
	}
	i.phase = phaseMsg3Sent
	return append(encS, encPayload...), nil
}

// Split returns the (send, receive) transport cipher states.
func (i *Initiator) Split() (*CipherState, *CipherState, error) {
	if err := requirePhase(i.phase, phaseMsg3Sent, "split"); err != nil {
		return nil, nil, err
	}
	i.phase = phaseSplit
	c1, c2, err := i.ss.split()
	i.e, i.s, i.re, i.rs = nil, nil, nil, nil
	return c1, c2, err
}

// Destroy kills the handshake and drops key material.
func (i *Initiator) Destroy() {
	i.e, i.s, i.re, i.rs = nil, nil, nil, nil
	i.phase = phaseDead
}

// RemoteStaticPublicKey returns the responder's static key, once known.
func (i *Initiator) RemoteStaticPublicKey() []byte {
	if i.rs == nil {
		return nil
	}
	return append([]byte(nil), i.rs...)
}

// HandshakeHash returns the current handshake hash.
func (i *Initiator) HandshakeHash() []byte { return i.ss.handshakeHash() }

// Responder is the peer side of a Noise XX handshake, for protocol
// verification (tests, fake VMs).
type Responder struct {
	ss      *symmetricState
	e, s    *x25519KeyPair
	re      []byte
	payload []byte
	phase   int
}

// NewResponder creates a responder that sends payload in message 2.
func NewResponder(payload []byte) *Responder {
	return &Responder{ss: newSymmetricState(), payload: append([]byte(nil), payload...)}
}

// Initialize initializes the symmetric state.
func (r *Responder) Initialize() error {
	if err := requirePhase(r.phase, phaseCreated, "initialize"); err != nil {
		return err
	}
	r.ss.initialize()
	r.phase = phaseInitialized
	return nil
}

// ReadMessage1AndWriteMessage2 consumes message 1 and returns message 2.
func (r *Responder) ReadMessage1AndWriteMessage2(msg1 []byte) ([]byte, error) {
	if err := requirePhase(r.phase, phaseInitialized, "read_message1_and_write_message2"); err != nil {
		return nil, err
	}
	if len(msg1) < dhKeyLen {
		r.phase = phaseDead
		return nil, protocolErrorf("NoiseXX: message 1 too short (%d < %d)", len(msg1), dhKeyLen)
	}
	fail := func(err error) ([]byte, error) {
		r.phase = phaseDead
		return nil, err
	}
	r.re = append([]byte(nil), msg1[:dhKeyLen]...)
	r.ss.mixHash(r.re)
	if _, err := r.ss.decryptAndHash(msg1[dhKeyLen:]); err != nil {
		return fail(err)
	}
	e, err := generateX25519KeyPair()
	if err != nil {
		return fail(err)
	}
	r.e = e
	r.ss.mixHash(r.e.publicBytes)

	ee, err := x25519DH(r.e.privateKey, r.re)
	if err != nil {
		return fail(err)
	}
	if err := r.ss.mixKey(ee); err != nil {
		return fail(err)
	}
	s, err := generateX25519KeyPair()
	if err != nil {
		return fail(err)
	}
	r.s = s
	encS, err := r.ss.encryptAndHash(r.s.publicBytes)
	if err != nil {
		return fail(err)
	}
	es, err := x25519DH(r.s.privateKey, r.re)
	if err != nil {
		return fail(err)
	}
	if err := r.ss.mixKey(es); err != nil {
		return fail(err)
	}
	encPayload, err := r.ss.encryptAndHash(r.payload)
	if err != nil {
		return fail(err)
	}
	r.phase = phaseMsg2Read
	out := append([]byte(nil), r.e.publicBytes...)
	out = append(out, encS...)
	out = append(out, encPayload...)
	return out, nil
}

// ReadMessage3 consumes message 3.
func (r *Responder) ReadMessage3(msg3 []byte) error {
	if err := requirePhase(r.phase, phaseMsg2Read, "read_message3"); err != nil {
		return err
	}
	if len(msg3) < minMsg3Len {
		r.phase = phaseDead
		return protocolErrorf("NoiseXX: message 3 too short (%d < %d)", len(msg3), minMsg3Len)
	}
	fail := func(err error) error {
		r.phase = phaseDead
		return err
	}
	offset := 0
	rs, err := r.ss.decryptAndHash(msg3[offset : offset+dhKeyLen+aeadTagLen])
	if err != nil {
		return fail(err)
	}
	offset += dhKeyLen + aeadTagLen
	se, err := x25519DH(r.e.privateKey, rs)
	if err != nil {
		return fail(err)
	}
	if err := r.ss.mixKey(se); err != nil {
		return fail(err)
	}
	if _, err := r.ss.decryptAndHash(msg3[offset:]); err != nil {
		return fail(err)
	}
	r.phase = phaseMsg3Sent
	return nil
}

// Split returns the (send, receive) transport cipher states, in the
// reference responder's swapped order.
func (r *Responder) Split() (*CipherState, *CipherState, error) {
	if err := requirePhase(r.phase, phaseMsg3Sent, "split"); err != nil {
		return nil, nil, err
	}
	r.phase = phaseSplit
	c1, c2, err := r.ss.split()
	r.e, r.s, r.re = nil, nil, nil
	return c2, c1, err
}

// HandshakeHash returns the current handshake hash.
func (r *Responder) HandshakeHash() []byte { return r.ss.handshakeHash() }
