package mobile

import (
	"strings"
	"sync"
	"testing"
	"time"

	"musegadget/config"
)

type fakeBridge struct {
	mu      sync.Mutex
	name    string
	started bool
	stopped bool
	sent    [][]byte
}

func (b *fakeBridge) Start(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.name = name
	b.started = true
	return nil
}
func (b *fakeBridge) Stop() {
	b.mu.Lock()
	b.stopped = true
	b.mu.Unlock()
}
func (b *fakeBridge) SendPacket(packet []byte) {
	b.mu.Lock()
	b.sent = append(b.sent, append([]byte(nil), packet...))
	b.mu.Unlock()
}
func (b *fakeBridge) MTU() int           { return 200 }
func (b *fakeBridge) Disconnect(int)     {}
func (b *fakeBridge) isStarted() bool    { b.mu.Lock(); defer b.mu.Unlock(); return b.started }
func (b *fakeBridge) advertised() string { b.mu.Lock(); defer b.mu.Unlock(); return b.name }

func TestClientIdentityAndPairingState(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(client.NodeID(), "homelink-") || len(client.NodeID()) != len("homelink-")+6 {
		t.Fatalf("node id: %q", client.NodeID())
	}
	if !strings.HasPrefix(client.DeviceID(), "hatch-link:") {
		t.Fatalf("device id: %q", client.DeviceID())
	}
	if client.BLEName() != "MuseGadget"+strings.ToUpper(client.NodeID()[len("homelink-"):]) {
		t.Fatalf("ble name: %q", client.BLEName())
	}
	// Identity persists across clients.
	again, err := NewClient(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if again.MAC() != client.MAC() {
		t.Fatal("identity not persisted")
	}
	if client.IsPaired() {
		t.Fatal("paired before pairing")
	}
	if err := config.SaveJSON(config.PairingFile, map[string]any{"access_token": "x"}, dir); err != nil {
		t.Fatal(err)
	}
	if !client.IsPaired() {
		t.Fatal("not paired after record saved")
	}
	if err := client.Unpair(); err != nil {
		t.Fatal(err)
	}
	if client.IsPaired() {
		t.Fatal("still paired after unpair")
	}
	if _, err := NewClient(t.TempDir(), "bogus-token"); err == nil {
		t.Fatal("invalid SDK token accepted")
	}
	if err := client.SendUserMessage("hi"); err == nil ||
		!strings.Contains(err.Error(), "not running") {
		t.Fatalf("send before start: %v", err)
	}
}

func TestClientPairWindow(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	bridge := &fakeBridge{}
	done := make(chan struct{})
	var outcome string
	var pairErr error
	go func() {
		outcome, pairErr = client.Pair(bridge, 1)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !bridge.isStarted() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !bridge.isStarted() {
		t.Fatal("bridge never started")
	}
	if bridge.advertised() != client.BLEName() {
		t.Fatalf("advertised %q, want %q", bridge.advertised(), client.BLEName())
	}
	// Delivering packets with no controller attached must not crash.
	client.OnPacket([]byte{0xFE, 0, 1, '{'})
	client.OnDisconnected()
	<-done
	if pairErr != nil {
		t.Fatalf("pair: %v", pairErr)
	}
	if outcome != "window_closed" {
		t.Fatalf("outcome = %q", outcome)
	}
}
