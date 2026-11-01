package noise

// Chunked framing inside one Noise transport message, mirroring
// musegadget.noise.framing: oversized service envelopes are split into
// NoiseTransportFrames of at most 65489 payload bytes and reassembled by
// the peer's decoder, which is poisoned by any malformed input.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

const (
	MaxChunkPayload      = 65489
	MaxPendingAssemblies = 16
	MaxTotalChunks       = 256
	MaxAssemblyBytes     = 16 * 1024 * 1024
	AssemblyTTL          = 60 * time.Second
)

// NoiseTransportFrame is one chunk of a (possibly split) service envelope.
type NoiseTransportFrame struct {
	ChunkID     int64
	ChunkIndex  uint32
	TotalChunks uint32 // decoder default 1 when the field is absent
	Payload     []byte
}

// EncodeNoiseFrame encodes one frame, omitting zero-valued fields.
func EncodeNoiseFrame(frame NoiseTransportFrame) ([]byte, error) {
	var out []byte
	var err error
	if frame.ChunkID != 0 {
		if out, err = int64Field(out, 1, frame.ChunkID); err != nil {
			return nil, err
		}
	}
	if frame.ChunkIndex != 0 {
		if out, err = uint32Field(out, 2, frame.ChunkIndex); err != nil {
			return nil, err
		}
	}
	if frame.TotalChunks != 0 {
		if out, err = uint32Field(out, 3, frame.TotalChunks); err != nil {
			return nil, err
		}
	}
	if len(frame.Payload) > 0 {
		if out, err = bytesField(out, 4, frame.Payload); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeNoiseFrame decodes one frame.
func DecodeNoiseFrame(data []byte) (NoiseTransportFrame, error) {
	frame := NoiseTransportFrame{TotalChunks: 1}
	r := &protoReader{data: data}
	for !r.done() {
		field, wt, err := r.readKey()
		if err != nil {
			return frame, err
		}
		switch field {
		case 1:
			raw, err := r.readVarintField("NoiseTransportFrame.chunk_id", wt)
			if err != nil {
				return frame, err
			}
			frame.ChunkID = decodeInt64(raw)
		case 2:
			raw, err := r.readVarintField("NoiseTransportFrame.chunk_index", wt)
			if err != nil {
				return frame, err
			}
			v, err := decodeUint32(raw)
			if err != nil {
				return frame, err
			}
			frame.ChunkIndex = v
		case 3:
			raw, err := r.readVarintField("NoiseTransportFrame.total_chunks", wt)
			if err != nil {
				return frame, err
			}
			v, err := decodeUint32(raw)
			if err != nil {
				return frame, err
			}
			frame.TotalChunks = v
		case 4:
			payload, err := r.readBytesField("NoiseTransportFrame.payload", wt)
			if err != nil {
				return frame, err
			}
			frame.Payload = payload
		default:
			if err := r.skipField(wt); err != nil {
				return frame, err
			}
		}
	}
	return frame, nil
}

func randomInt64() int64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	return int64(binary.LittleEndian.Uint64(buf[:]))
}

// EncodeNoiseFrames splits data into frames sharing one chunk id (random
// when chunkID is nil), exactly as the reference does.
func EncodeNoiseFrames(data []byte, chunkID *int64) ([][]byte, error) {
	id := randomInt64()
	if chunkID != nil {
		id = *chunkID
	}
	total := (len(data) + MaxChunkPayload - 1) / MaxChunkPayload
	if total < 1 {
		total = 1
	}
	if total > MaxTotalChunks {
		return nil, errors.New("payload too large for noise framing")
	}
	if len(data) == 0 {
		frame, err := EncodeNoiseFrame(NoiseTransportFrame{ChunkID: id, ChunkIndex: 0, TotalChunks: 1})
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil
	}
	frames := make([][]byte, 0, total)
	for index := 0; index < total; index++ {
		start := index * MaxChunkPayload
		end := start + MaxChunkPayload
		if end > len(data) {
			end = len(data)
		}
		frame, err := EncodeNoiseFrame(NoiseTransportFrame{
			ChunkID: id, ChunkIndex: uint32(index), TotalChunks: uint32(total), Payload: data[start:end],
		})
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

type assembly struct {
	chunks     map[uint32][]byte
	total      uint32
	totalBytes int
	createdAt  time.Time
}

// NoiseFrameDecoder reassembles chunked envelopes. Any error poisons it:
// every later Decode fails too.
type NoiseFrameDecoder struct {
	pending  map[int64]*assembly
	poisoned bool
	now      func() time.Time
}

// NewNoiseFrameDecoder creates a decoder.
func NewNoiseFrameDecoder() *NoiseFrameDecoder {
	return &NoiseFrameDecoder{pending: map[int64]*assembly{}, now: time.Now}
}

// Decode feeds one frame; it returns (payload, nil) when an envelope is
// complete, (nil, nil) while chunks are outstanding, and an error for any
// malformed input.
func (d *NoiseFrameDecoder) Decode(frameBytes []byte) ([]byte, error) {
	if d.poisoned {
		return nil, errors.New("NoiseFrameDecoder: poisoned after prior failure")
	}
	payload, err := d.decode(frameBytes)
	if err != nil {
		d.poisoned = true
		return nil, err
	}
	return payload, nil
}

func (d *NoiseFrameDecoder) decode(frameBytes []byte) ([]byte, error) {
	frame, err := DecodeNoiseFrame(frameBytes)
	if err != nil {
		return nil, err
	}
	if frame.TotalChunks < 1 || frame.TotalChunks > MaxTotalChunks {
		return nil, errors.New("invalid totalChunks")
	}
	if frame.ChunkIndex >= frame.TotalChunks {
		return nil, errors.New("chunkIndex out of range")
	}
	if len(frame.Payload) > MaxChunkPayload {
		return nil, errors.New("payload too large for noise frame")
	}
	d.evictExpired()
	a, ok := d.pending[frame.ChunkID]
	if !ok {
		if len(d.pending) >= MaxPendingAssemblies {
			return nil, errors.New("too many pending noise frame assemblies")
		}
		a = &assembly{chunks: map[uint32][]byte{}, total: frame.TotalChunks, createdAt: d.now()}
		d.pending[frame.ChunkID] = a
	}
	if a.total != frame.TotalChunks {
		delete(d.pending, frame.ChunkID)
		return nil, errors.New("inconsistent totalChunks for chunkId")
	}
	if _, dup := a.chunks[frame.ChunkIndex]; dup {
		delete(d.pending, frame.ChunkID)
		return nil, errors.New("duplicate chunkIndex")
	}
	a.totalBytes += len(frame.Payload)
	if a.totalBytes > MaxAssemblyBytes {
		delete(d.pending, frame.ChunkID)
		return nil, errors.New("assembly exceeded byte budget")
	}
	a.chunks[frame.ChunkIndex] = frame.Payload
	if len(a.chunks) < int(a.total) {
		return nil, nil
	}
	delete(d.pending, frame.ChunkID)
	if a.total == 1 {
		return a.chunks[0], nil
	}
	var out []byte
	for i := uint32(0); i < a.total; i++ {
		out = append(out, a.chunks[i]...)
	}
	return out, nil
}

func (d *NoiseFrameDecoder) evictExpired() {
	now := d.now()
	for id, a := range d.pending {
		if now.Sub(a.createdAt) > AssemblyTTL {
			delete(d.pending, id)
		}
	}
}
