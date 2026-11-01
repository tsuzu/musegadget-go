package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"musegadget/ble"
	"musegadget/config"
	"musegadget/identity"
	"musegadget/museapi"
)

func TestBackoff(t *testing.T) {
	backoff := &Backoff{}
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60}
	for i, seconds := range want {
		if got := backoff.NextDelay(); got != seconds*time.Second {
			t.Fatalf("delay %d = %v, want %ds", i, got, seconds)
		}
	}
	backoff.Floor = AuthBackoffMinS
	if got := backoff.NextDelay(); got != 60*time.Second {
		t.Fatalf("capped delay = %v", got)
	}
	backoff.Reset()
	backoff.Floor = AuthBackoffMinS
	if got := backoff.NextDelay(); got != 15*time.Second {
		t.Fatalf("floored delay = %v, want 15s", got)
	}
	backoff.Reset()
	if got := backoff.NextDelay(); got != 2*time.Second {
		t.Fatalf("reset delay = %v, want 2s", got)
	}
}

func testIdentity() identity.Identity { return identity.Identity{MAC: "02:11:22:33:44:55"} }

// -- Local socket -------------------------------------------------------------

func TestLocalSocketRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "musegadget.sock")
	svc := &Service{Identity: testIdentity()}
	listener, err := ServeLocalSocket(path, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go AcceptLocal(listener, svc.handleLocalMessage)

	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", info.Mode().Perm(), err)
	}
	// No session is running: the service's own error comes back.
	err = SendLocalMessage(path, "hello", "", nil)
	if err == nil || err.Error() != "not connected to the Muse" {
		t.Fatalf("send without session: %v", err)
	}
	// Validation errors surface verbatim.
	err = SendLocalMessage(path, "hello", "bad session!", nil)
	if err == nil || err.Error() != "session_id must be letters, digits and dashes" {
		t.Fatalf("session id validation: %v", err)
	}
	err = SendLocalMessage(path, "hello", "", &LocalImage{
		MimeType: "image/bmp", Data: []byte{1, 2, 3}, Filename: "x.bmp",
	})
	if err == nil || !strings.Contains(err.Error(), "JPEG, PNG, GIF or WebP") {
		t.Fatalf("image validation: %v", err)
	}
	// A service that is not there at all.
	err = SendLocalMessage(filepath.Join(dir, "absent.sock"), "hello", "", nil)
	if err == nil || !strings.Contains(err.Error(), "no response from the running musegadget service") {
		t.Fatalf("absent service: %v", err)
	}
}

func TestLocalSocketOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "musegadget.sock")
	svc := &Service{Identity: testIdentity()}
	listener, err := ServeLocalSocket(path, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go AcceptLocal(listener, svc.handleLocalMessage)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	big := `{"message": "` + strings.Repeat("a", MaxLocalRequest) + `"}` + "\n"
	if _, err := conn.Write([]byte(big)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 128)
	n, err := conn.Read(reply)
	if err != nil && n == 0 {
		t.Fatalf("read reply: %v", err)
	}
	if !strings.Contains(string(reply[:n]), "the request is over 4 MiB") {
		t.Fatalf("oversize reply: %q", reply[:n])
	}
}

// -- Pair ---------------------------------------------------------------------

type fakeGATTServer struct {
	mu       sync.Mutex
	sent     [][]byte
	onWrite  func([]byte)
	stopped  chan struct{}
	stopOnce sync.Once
}

func (f *fakeGATTServer) SendPackets(packets [][]byte) {
	f.mu.Lock()
	f.sent = append(f.sent, packets...)
	f.mu.Unlock()
}
func (f *fakeGATTServer) MTU() int { return 100 }
func (f *fakeGATTServer) Disconnect(time.Duration) {
	f.stopOnce.Do(func() { close(f.stopped) })
}
func (f *fakeGATTServer) Run() error {
	<-f.stopped
	return nil
}
func (f *fakeGATTServer) Stop() { f.Disconnect(0) }
func (f *fakeGATTServer) packets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.sent...)
}

type fakeNetwork struct{}

func (fakeNetwork) IsOnline() bool { return true }
func (fakeNetwork) CurrentConnectionEntry() map[string]any {
	return map[string]any{"ssid": "TestNet", "rssi": -40, "secure": false}
}

func TestPairAlreadyPairedAndInvalidToken(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity()
	if err := config.SaveJSON(config.PairingFile, map[string]any{"access_token": "x"}, dir); err != nil {
		t.Fatal(err)
	}
	outcome, err := Pair(context.Background(), PairOptions{Identity: id, StateDir: dir})
	if err != nil || outcome != PairAlreadyPaired {
		t.Fatalf("already paired: %v %v", outcome, err)
	}
	outcome, err = Pair(context.Background(), PairOptions{
		Identity: id, StateDir: dir, Force: true, SDKToken: "bogus",
	})
	if err != nil || outcome != PairInvalidToken {
		t.Fatalf("invalid token: %v %v", outcome, err)
	}
	// No BLE backend in this build: the stub factory's error surfaces.
	empty := t.TempDir()
	_, err = Pair(context.Background(), PairOptions{Identity: id, StateDir: empty})
	if !errors.Is(err, ble.ErrUnavailable) {
		t.Fatalf("stub factory error: %v", err)
	}
}

func TestPairWindowTimeout(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity()
	server := &fakeGATTServer{stopped: make(chan struct{})}
	factory := func(name string, onWrite func([]byte), onDisconnect func()) (ble.Server, error) {
		if name != id.BLEName() {
			t.Errorf("advertised name = %q, want %q", name, id.BLEName())
		}
		server.onWrite = onWrite
		return server, nil
	}
	opened := make(chan SetupWindow, 1)
	outcome, err := Pair(context.Background(), PairOptions{
		Identity: id, StateDir: dir, Timeout: 300 * time.Millisecond,
		Factory: factory, Network: fakeNetwork{},
		OnOpen: func(w SetupWindow) { opened <- w },
	})
	if err != nil || outcome != PairWindowClosed {
		t.Fatalf("pair timeout: %v %v", outcome, err)
	}
	window := <-opened
	if window.BLEName != id.BLEName() || window.HasSDKToken {
		t.Fatalf("window: %+v", window)
	}
}

// -- verifyAndSave --------------------------------------------------------------

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func stubAPI(t *testing.T, body string) {
	t.Helper()
	original := museapi.HTTPClient
	museapi.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})}
	t.Cleanup(func() { museapi.HTTPClient = original })
}

func TestVerifyAndSave(t *testing.T) {
	dir := t.TempDir()
	opts := PairOptions{Identity: testIdentity(), StateDir: dir, SDKToken: ""}
	creds := ble.Credentials{
		AccessToken: "access-1", RefreshToken: "refresh-1", Username: "user",
		APIURLV2: "https://api.example.test/v2", NoiseHost: "noise.example.test",
	}
	commit := func(save func() bool) bool { return save() }

	stubAPI(t, `{"vm_list": []}`)
	if err := verifyAndSave(context.Background(), opts, creds, commit); err == nil {
		t.Fatal("no VMs accepted")
	} else if failed, ok := err.(*ble.ProvisionFailed); !ok || failed.Status != "auth_failed" {
		t.Fatalf("no-VM failure: %v", err)
	}

	stubAPI(t, `{"vm_list": [{"vm_id": "vm1", "vm_ws_url": "wss://x", "vm_auth_token": "t"}]}`)
	if err := verifyAndSave(context.Background(), opts, creds, commit); err != nil {
		t.Fatalf("verifyAndSave: %v", err)
	}
	record, err := config.LoadJSON(config.PairingFile, dir)
	if err != nil || record == nil {
		t.Fatalf("saved record: %v %v", record, err)
	}
	if record["access_token"] != "access-1" || record["token_type"] != "device" ||
		record["api_url_v2"] != "https://api.example.test/v2" ||
		record["noise_host"] != "noise.example.test" {
		t.Fatalf("record: %v", record)
	}
	if _, hasSavedAt := record["access_token_saved_at"]; !hasSavedAt {
		t.Fatal("access_token_saved_at missing")
	}
	// A refused commit is error_storage.
	if err := verifyAndSave(context.Background(), opts, creds,
		func(func() bool) bool { return false }); err == nil {
		t.Fatal("refused commit accepted")
	} else if failed, ok := err.(*ble.ProvisionFailed); !ok || failed.Status != "error_storage" {
		t.Fatalf("commit failure: %v", err)
	}
	// Non-https API URLs are dropped, as in the reference.
	creds.APIURLV2 = "http://insecure.example.test"
	if err := verifyAndSave(context.Background(), opts, creds, commit); err != nil {
		t.Fatal(err)
	}
	record, _ = config.LoadJSON(config.PairingFile, dir)
	if record["api_url_v2"] != "" {
		t.Fatalf("http api_url_v2 kept: %v", record["api_url_v2"])
	}
}
