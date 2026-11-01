package identity

import (
	"strings"
	"testing"
)

func TestLoadOrCreateShape(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(id.MAC, ":")
	if len(parts) != 6 {
		t.Fatalf("mac: %q", id.MAC)
	}
	first, _ := parseOctet(parts[0])
	// Locally administered, unicast: the low two bits are forced to 0b10.
	if first&0x03 != 0x02 {
		t.Fatalf("first octet %02x not locally-administered unicast", first)
	}
	if id.NodeID() != "homelink-"+id.Suffix() {
		t.Fatalf("node id: %q", id.NodeID())
	}
	if id.DeviceID() != "hatch-link:"+id.MAC {
		t.Fatalf("device id: %q", id.DeviceID())
	}
	if id.BLEName() != "MuseGadget"+strings.ToUpper(id.Suffix()) {
		t.Fatalf("ble name: %q", id.BLEName())
	}
	again, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again != id {
		t.Fatal("identity changed across loads")
	}
}

func parseOctet(s string) (int, error) {
	value := 0
	for _, c := range s {
		value *= 16
		switch {
		case c >= '0' && c <= '9':
			value += int(c - '0')
		case c >= 'a' && c <= 'f':
			value += int(c-'a') + 10
		default:
			return 0, errBad
		}
	}
	return value, nil
}

var errBad = &badHex{}

type badHex struct{}

func (*badHex) Error() string { return "bad hex" }
