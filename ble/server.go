package ble

import (
	"errors"
	"time"
)

// GATT UUIDs of the setup service, from the reference's ble_server.py.
const (
	ServiceUUID          = "7fdd3d1c-38ea-46cf-8b46-314ecf5f240c"
	RXCharacteristicUUID = "4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01" // write / write-without-response
	TXCharacteristicUUID = "d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c" // read / notify
)

// AssumedMTU before the central negotiates a larger one.
const AssumedMTU = DefaultATTMTU

// Server is a platform BLE GATT server for the setup service. It is also
// the controller's Transport. Run blocks until Stop; the callbacks deliver
// received packets and disconnections to the setup controller.
type Server interface {
	Transport
	Run() error
	Stop()
}

// ServerFactory builds a Server advertising under the given BLE name.
type ServerFactory func(name string, onWrite func(packet []byte), onDisconnect func()) (Server, error)

// ErrUnavailable is returned by the default factory on platforms without a
// GATT server implementation in this build. On Linux the reference uses
// BlueZ over D-Bus; on Android the app supplies a ServerFactory backed by
// BluetoothGattServer and injects it instead (see the mobile package). All
// protocol logic above the transport is implemented and tested here; only
// this last platform hop is stubbed.
var ErrUnavailable = errors.New(
	"musegadget: no BLE GATT server in this build (Linux/BlueZ backend not implemented); " +
		"inject a ble.ServerFactory, e.g. the Android BluetoothGattServer backend")

// StubFactory is a ServerFactory that always reports ErrUnavailable.
func StubFactory(name string, onWrite func(packet []byte), onDisconnect func()) (Server, error) {
	return nil, ErrUnavailable
}

// CallbackTransport adapts plain callbacks (as an Android BluetoothGattServer
// bridge provides) to the Transport interface: each packet is handed to
// send one at a time, in order.
type CallbackTransport struct {
	SendPacketFunc func(packet []byte)
	MTUFunc        func() int
	DisconnectFunc func(delay time.Duration)
}

// SendPackets implements Transport.
func (t *CallbackTransport) SendPackets(packets [][]byte) {
	for _, packet := range packets {
		t.SendPacketFunc(packet)
	}
}

// MTU implements Transport.
func (t *CallbackTransport) MTU() int {
	if t.MTUFunc == nil {
		return AssumedMTU
	}
	return t.MTUFunc()
}

// Disconnect implements Transport.
func (t *CallbackTransport) Disconnect(delay time.Duration) {
	if t.DisconnectFunc != nil {
		t.DisconnectFunc(delay)
	}
}
