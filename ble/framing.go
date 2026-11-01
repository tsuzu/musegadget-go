// Package ble mirrors musegadget.ble_framing and musegadget.ble_setup: the
// chunked framing and the transport-independent BLE setup command handling.
// The GATT server itself is platform-dependent and sits behind the Server
// interface (see server.go).
package ble

import "fmt"

const (
	ChunkMagic      = 0xFE
	HeaderBytes     = 3
	MaxPacketBytes  = 160
	MaxChunks       = 255
	MaxMessageBytes = 8192
	DefaultATTMTU   = 23
)

// EncodeChunks splits data into framed packets that fit one notification
// at mtu. Every packet is 0xFE, chunk index, total chunks, then a fragment.
func EncodeChunks(data []byte, mtu int) ([][]byte, error) {
	notifyMax := MaxPacketBytes
	if mtu > 3 {
		if mtu-3 < notifyMax {
			notifyMax = mtu - 3
		}
	} else {
		notifyMax = 20
	}
	usable := notifyMax - HeaderBytes
	if usable < 1 {
		return nil, fmt.Errorf("ble: MTU %d leaves no room for a chunk", mtu)
	}
	total := (len(data) + usable - 1) / usable
	if len(data) == 0 {
		total = 1
	}
	if total > MaxChunks {
		return nil, fmt.Errorf("ble: message needs %d chunks (max %d)", total, MaxChunks)
	}
	packets := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * usable
		end := start + usable
		if end > len(data) {
			end = len(data)
		}
		packet := make([]byte, 0, HeaderBytes+end-start)
		packet = append(packet, ChunkMagic, byte(i), byte(total))
		packet = append(packet, data[start:end]...)
		packets = append(packets, packet)
	}
	return packets, nil
}

// ChunkAssembler reassembles chunked writes, strictly in order. Index 0,
// or a change in the total, starts a new message. An out-of-order chunk or
// an oversize message discards what has been collected. A packet that does
// not start with 0xFE (or is shorter than a header) is a complete,
// unchunked message.
type ChunkAssembler struct {
	maxBytes int
	buf      []byte
	total    int
	next     int
}

// NewChunkAssembler creates an assembler with the default message cap.
func NewChunkAssembler() *ChunkAssembler {
	return &ChunkAssembler{maxBytes: MaxMessageBytes}
}

// Reset discards any partial message.
func (a *ChunkAssembler) Reset() {
	a.buf = nil
	a.total = 0
	a.next = 0
}

// Feed adds one write; it returns (message, true) once a complete message
// is available.
func (a *ChunkAssembler) Feed(packet []byte) ([]byte, bool) {
	if len(packet) < HeaderBytes || packet[0] != ChunkMagic {
		return append([]byte(nil), packet...), true
	}
	index, total, fragment := int(packet[1]), int(packet[2]), packet[HeaderBytes:]
	if total == 0 {
		a.Reset()
		return nil, false
	}
	if index == 0 || total != a.total {
		a.buf = nil
		a.next = 0
		a.total = total
	}
	if index != a.next || index >= a.total {
		a.Reset()
		return nil, false
	}
	if len(a.buf)+len(fragment) > a.maxBytes {
		a.Reset()
		return nil, false
	}
	a.buf = append(a.buf, fragment...)
	a.next = index + 1
	if a.next < a.total {
		return nil, false
	}
	message := a.buf
	a.Reset()
	return message, true
}
