// Package identity mirrors musegadget.identity: a stable, random,
// locally administered MAC-shaped identity, generated once and kept across
// upgrades and unpairing.
package identity

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"

	"musegadget/config"
)

const (
	NodeIDPrefix  = "homelink-"
	BLENamePrefix = "MuseGadget"
)

var macRe = regexp.MustCompile(`\A[0-9a-f]{2}(:[0-9a-f]{2}){5}\z`)

// Identity is the device's stable identity, derived from its MAC.
type Identity struct {
	MAC string `json:"mac"`
}

// Suffix is the last six hex digits of the MAC.
func (id Identity) Suffix() string {
	flat := strings.ReplaceAll(id.MAC, ":", "")
	if len(flat) > 6 {
		return flat[len(flat)-6:]
	}
	return flat
}

// NodeID is "homelink-" plus the suffix.
func (id Identity) NodeID() string { return NodeIDPrefix + id.Suffix() }

// DeviceID is "hatch-link:" plus the MAC.
func (id Identity) DeviceID() string { return "hatch-link:" + id.MAC }

// BLEName is "MuseGadget" plus the uppercased suffix, with no separator:
// the apps compare the text after the prefix with the text after
// "homelink-" in the node id.
func (id Identity) BLEName() string { return BLENamePrefix + strings.ToUpper(id.Suffix()) }

// GenerateMAC makes a random unicast, locally administered MAC using
// randomBytes (crypto/rand by default).
func GenerateMAC(randomBytes func(int) ([]byte, error)) (string, error) {
	if randomBytes == nil {
		randomBytes = func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		}
	}
	octets, err := randomBytes(6)
	if err != nil {
		return "", err
	}
	if len(octets) != 6 {
		return "", fmt.Errorf("identity: random source returned %d bytes, want 6", len(octets))
	}
	octets = append([]byte(nil), octets...)
	octets[0] = (octets[0] & 0xFC) | 0x02
	parts := make([]string, 6)
	for i, b := range octets {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":"), nil
}

// LoadOrCreate reads identity.json from directory (the state dir when
// empty), minting and persisting a fresh identity when the stored one is
// missing or malformed. A permission error reading the stored file is
// returned rather than minting over it.
func LoadOrCreate(directory string) (Identity, error) {
	return LoadOrCreateWith(directory, nil)
}

// LoadOrCreateWith is LoadOrCreate with an injectable random source.
func LoadOrCreateWith(directory string, randomBytes func(int) ([]byte, error)) (Identity, error) {
	stored, err := config.LoadJSON(config.IdentityFile, directory)
	if err != nil {
		return Identity{}, err
	}
	if stored != nil {
		if mac, ok := stored["mac"].(string); ok && macRe.MatchString(mac) {
			return Identity{MAC: mac}, nil
		}
	}
	mac, err := GenerateMAC(randomBytes)
	if err != nil {
		return Identity{}, err
	}
	id := Identity{MAC: mac}
	if err := config.SaveJSON(config.IdentityFile, map[string]any{"mac": mac}, directory); err != nil {
		return Identity{}, err
	}
	return id, nil
}
