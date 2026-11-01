// Package mobile is the Android-facing facade for gomobile bind: a small
// surface of strings, byte slices and primitives over the musegadget
// packages, designed for the Echo Show / Android embedding described in
// the repository notes.
//
// The reference repository's android/ directory is NOT this: it is a
// sample phone app ("Muse Gadgets Test") that streams camera video to a
// gadget display over Wi-Fi (protocols/VIDEO.md). There is no gadget
// client SDK for Android upstream; this package is the client SDK's
// Android entry point.
//
// The Android side supplies the BLE GATT server (BluetoothGattServer)
// through BLEBridge; all pairing cryptography, framing and setup-command
// handling stay in Go, exactly as on Linux.
package mobile

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"musegadget/ble"
	"musegadget/config"
	"musegadget/executor"
	"musegadget/identity"
	"musegadget/service"
)

// BLEBridge is implemented by the Android app on top of
// BluetoothGattServer, using the GATT UUIDs in the ble package
// (ServiceUUID, RXCharacteristicUUID for writes, TXCharacteristicUUID for
// notifications). Start must advertise the given name and accept writes;
// each received write chunk goes to Client.OnPacket, and a disconnect to
// Client.OnDisconnected.
type BLEBridge interface {
	// Start begins advertising and serving the setup GATT service.
	Start(advertisedName string) error
	// Stop tears the GATT server and advertising down.
	Stop()
	// SendPacket notifies one framed packet to the connected app.
	SendPacket(packet []byte)
	// MTU returns the negotiated ATT MTU (23 when unknown).
	MTU() int
	// Disconnect drops the BLE connection after the delay.
	Disconnect(delayMillis int)
}

// Client is one gadget identity in one state directory.
type Client struct {
	stateDir   string
	sdkToken   string
	id         identity.Identity
	commandsIn string

	mu          sync.Mutex
	pairWrite   func(packet []byte)
	pairDisc    func()
	svc         *service.Service
	cancel      context.CancelFunc
	displayName string
}

// NewClient loads (or creates) the device identity in stateDir. The SDK
// token may be empty; a malformed one is an error.
func NewClient(stateDir, sdkToken string) (*Client, error) {
	if sdkToken != "" && !config.ValidSDKToken(sdkToken) {
		return nil, errors.New("musegadget: invalid SDK token")
	}
	id, err := identity.LoadOrCreate(stateDir)
	if err != nil {
		return nil, err
	}
	return &Client{stateDir: stateDir, sdkToken: sdkToken, id: id}, nil
}

// NodeID is the device's homelink-xxxxxx id.
func (c *Client) NodeID() string { return c.id.NodeID() }

// DeviceID is the hatch-link:<mac> id used in chat requests.
func (c *Client) DeviceID() string { return c.id.DeviceID() }

// BLEName is the advertised MuseGadgetXXXXXX name.
func (c *Client) BLEName() string { return c.id.BLEName() }

// MAC is the device's identity MAC address.
func (c *Client) MAC() string { return c.id.MAC }

// SetDisplayName sets the name shown for this device (default: hostname).
func (c *Client) SetDisplayName(name string) { c.displayName = name }

// SetCommandsDir overrides where commands.d drop-ins are loaded from
// (default: <stateDir>/commands.d, since /etc is not writable on Android).
func (c *Client) SetCommandsDir(dir string) { c.commandsIn = dir }

// commandsDir resolves the drop-in directory.
func (c *Client) commandsDir() string {
	if c.commandsIn != "" {
		return c.commandsIn
	}
	return c.stateDir + string(os.PathSeparator) + "commands.d"
}

// IsPaired reports whether a pairing record exists.
func (c *Client) IsPaired() bool {
	pairing, _ := config.LoadJSON(config.PairingFile, c.stateDir)
	return pairing != nil
}

// Unpair removes the pairing record; the identity is kept.
func (c *Client) Unpair() error {
	return config.DeleteJSON(config.PairingFile, c.stateDir)
}

// Pair opens the BLE setup window through the bridge and blocks until
// the app pairs this device ("paired"), the device was already paired
// ("already_paired"), the token is malformed ("invalid_sdk_token"), or
// the window closes ("window_closed"). Call it from a background thread.
func (c *Client) Pair(bridge BLEBridge, timeoutSeconds int) (string, error) {
	if bridge == nil {
		return "", errors.New("musegadget: a BLE bridge is required")
	}
	factory := func(name string, onWrite func([]byte), onDisconnect func()) (ble.Server, error) {
		c.mu.Lock()
		c.pairWrite = onWrite
		c.pairDisc = onDisconnect
		c.mu.Unlock()
		return &gattServer{bridge: bridge, name: name, stopped: make(chan struct{})}, nil
	}
	outcome, err := service.Pair(context.Background(), service.PairOptions{
		Identity: c.id,
		StateDir: c.stateDir,
		SDKToken: c.sdkToken,
		Timeout:  time.Duration(timeoutSeconds) * time.Second,
		Factory:  factory,
	})
	if err != nil {
		return "", err
	}
	return string(outcome), nil
}

// OnPacket delivers one received GATT write chunk to the pairing stack.
// The Android bridge calls this from its BluetoothGattServer callback.
func (c *Client) OnPacket(packet []byte) {
	c.mu.Lock()
	callback := c.pairWrite
	c.mu.Unlock()
	if callback != nil {
		callback(packet)
	}
}

// OnDisconnected tells the pairing stack the BLE link dropped.
func (c *Client) OnDisconnected() {
	c.mu.Lock()
	callback := c.pairDisc
	c.mu.Unlock()
	if callback != nil {
		callback()
	}
}

// gattServer adapts a BLEBridge to ble.Server (also the controller's
// Transport).
type gattServer struct {
	bridge  BLEBridge
	name    string
	stopped chan struct{}
	once    sync.Once
}

func (s *gattServer) SendPackets(packets [][]byte) {
	for _, packet := range packets {
		s.bridge.SendPacket(packet)
	}
}

func (s *gattServer) MTU() int {
	if mtu := s.bridge.MTU(); mtu > 0 {
		return mtu
	}
	return ble.AssumedMTU
}

func (s *gattServer) Disconnect(delay time.Duration) {
	s.bridge.Disconnect(int(delay / time.Millisecond))
}

func (s *gattServer) Run() error {
	if err := s.bridge.Start(s.name); err != nil {
		return err
	}
	<-s.stopped
	return nil
}

func (s *gattServer) Stop() {
	s.once.Do(func() {
		s.bridge.Stop()
		close(s.stopped)
	})
}

// accountForMobile resolves the account commands run as. Android has no
// /etc/passwd entry for apps, so fall back to the process identity.
func accountForMobile() executor.Account {
	if account, err := executor.CurrentAccount(); err == nil && account.Home != "" {
		return account
	}
	home, _ := os.UserHomeDir()
	name := os.Getenv("USER")
	if name == "" {
		name = "android"
	}
	return executor.Account{
		Name: name, UID: os.Getuid(), GID: os.Getgid(), Home: home,
		Groups: []uint32{uint32(os.Getgid())},
	}
}

// Start connects to the paired Muse and maintains the session,
// reconnecting as needed, until Stop is called. It blocks; call it from
// a background thread. Pair first.
func (c *Client) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	svc := &service.Service{
		Identity:    c.id,
		Executor:    executor.NewExecutor(accountForMobile(), executor.LoadCommands(c.commandsDir())),
		SDKToken:    c.sdkToken,
		DisplayName: c.displayName,
		StateDir:    c.stateDir,
	}
	c.mu.Lock()
	c.svc = svc
	c.cancel = cancel
	c.mu.Unlock()
	return svc.Run(ctx)
}

// Stop ends a running Start call.
func (c *Client) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SendUserMessage posts a message to the device's main Muse chat over
// the running session started by Start.
func (c *Client) SendUserMessage(message string) error {
	return c.SendUserMessageToSession(message, "")
}

// SendUserMessageToSession posts a message to a side chat (or the main
// chat when sessionID is empty).
func (c *Client) SendUserMessageToSession(message, sessionID string) error {
	c.mu.Lock()
	svc := c.svc
	c.mu.Unlock()
	if svc == nil {
		return errors.New("musegadget: not running; call Start first")
	}
	session := svc.CurrentSession()
	if session == nil || session.RegisteredAt() == nil {
		return errors.New("not connected to the Muse")
	}
	_, err := session.SendChat(context.Background(), message, sessionID, "")
	return err
}
