package noise

// Protobuf-style wire encoding, mirroring musegadget.noise._proto: the
// subset of the protobuf binary format the Noise envelope uses, with the
// reference's strict field-number and varint validation.

import (
	"fmt"
	"unicode/utf8"
)

const (
	WireVarint    = 0
	WireFixed64   = 1
	WireDelimited = 2
	WireFixed32   = 5
)

const (
	maxFieldNumber        = (1 << 29) - 1
	firstReservedFieldNum = 19000
	lastReservedFieldNum  = 19999
)

// ProtoError is raised when a protobuf message is malformed.
type ProtoError struct{ Message string }

func (e *ProtoError) Error() string { return e.Message }

func protoErrorf(format string, args ...any) *ProtoError {
	return &ProtoError{Message: fmt.Sprintf(format, args...)}
}

func validFieldNumber(n int) bool {
	return n != 0 && n <= maxFieldNumber &&
		!(firstReservedFieldNum <= n && n <= lastReservedFieldNum)
}

func validWireType(wt int) bool {
	return wt == WireVarint || wt == WireFixed64 || wt == WireDelimited || wt == WireFixed32
}

func appendVarint(b []byte, value uint64) []byte {
	for {
		byteVal := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			b = append(b, byteVal|0x80)
		} else {
			return append(b, byteVal)
		}
	}
}

func appendKey(b []byte, fieldNumber, wireType int) ([]byte, error) {
	if !validFieldNumber(fieldNumber) {
		return nil, protoErrorf("invalid field number")
	}
	if !validWireType(wireType) {
		return nil, protoErrorf("invalid wire type")
	}
	return appendVarint(b, uint64(fieldNumber<<3|wireType)), nil
}

func varintField(b []byte, fieldNumber int, value uint64) ([]byte, error) {
	b, err := appendKey(b, fieldNumber, WireVarint)
	if err != nil {
		return nil, err
	}
	return appendVarint(b, value), nil
}

func int64Field(b []byte, fieldNumber int, value int64) ([]byte, error) {
	return varintField(b, fieldNumber, uint64(value))
}

func int32Field(b []byte, fieldNumber int, value int32) ([]byte, error) {
	return varintField(b, fieldNumber, uint64(int64(value)))
}

func uint32Field(b []byte, fieldNumber int, value uint32) ([]byte, error) {
	return varintField(b, fieldNumber, uint64(value))
}

func boolField(b []byte, fieldNumber int, value bool) ([]byte, error) {
	v := uint64(0)
	if value {
		v = 1
	}
	return varintField(b, fieldNumber, v)
}

func delimitedField(b []byte, fieldNumber int, payload []byte) ([]byte, error) {
	b, err := appendKey(b, fieldNumber, WireDelimited)
	if err != nil {
		return nil, err
	}
	b = appendVarint(b, uint64(len(payload)))
	return append(b, payload...), nil
}

func stringField(b []byte, fieldNumber int, value string) ([]byte, error) {
	return delimitedField(b, fieldNumber, []byte(value))
}

func bytesField(b []byte, fieldNumber int, value []byte) ([]byte, error) {
	return delimitedField(b, fieldNumber, value)
}

// decodeInt64 reinterprets a wire varint as a two's-complement int64.
func decodeInt64(value uint64) int64 { return int64(value) }

// decodeInt32 validates and converts a wire varint to int32.
func decodeInt32(value uint64) (int32, error) {
	signed := int64(value)
	if signed < -(1<<31) || signed > (1<<31)-1 {
		return 0, protoErrorf("int32 value out of range")
	}
	return int32(signed), nil
}

// decodeUint32 validates and converts a wire varint to uint32.
func decodeUint32(value uint64) (uint32, error) {
	if value > 0xFFFFFFFF {
		return 0, protoErrorf("uint32 value out of range")
	}
	return uint32(value), nil
}

// protoReader walks one message's fields.
type protoReader struct {
	data []byte
	off  int
}

func (r *protoReader) done() bool { return r.off >= len(r.data) }

func (r *protoReader) readVarint() (uint64, error) {
	var value uint64
	var shift uint
	for i := 0; i < 10; i++ {
		if r.off >= len(r.data) {
			return 0, protoErrorf("truncated varint")
		}
		b := r.data[r.off]
		r.off++
		if i == 9 && (b&0xFE) != 0 {
			return 0, protoErrorf("malformed varint")
		}
		value |= uint64(b&0x7F) << shift
		if (b & 0x80) == 0 {
			return value, nil
		}
		shift += 7
	}
	return 0, protoErrorf("malformed varint")
}

func (r *protoReader) readKey() (fieldNumber, wireType int, err error) {
	key, err := r.readVarint()
	if err != nil {
		return 0, 0, err
	}
	fieldNumber = int(key >> 3)
	wireType = int(key & 0x07)
	if !validFieldNumber(fieldNumber) {
		return 0, 0, protoErrorf("invalid field number")
	}
	if !validWireType(wireType) {
		return 0, 0, protoErrorf("invalid wire type")
	}
	return fieldNumber, wireType, nil
}

func (r *protoReader) readDelimited() ([]byte, error) {
	length, err := r.readVarint()
	if err != nil {
		return nil, err
	}
	if length > uint64(len(r.data)-r.off) {
		return nil, protoErrorf("truncated delimited field")
	}
	out := r.data[r.off : r.off+int(length)]
	r.off += int(length)
	return out, nil
}

func (r *protoReader) skipField(wireType int) error {
	switch wireType {
	case WireVarint:
		_, err := r.readVarint()
		return err
	case WireFixed64:
		if len(r.data)-r.off < 8 {
			return protoErrorf("truncated fixed64 field")
		}
		r.off += 8
		return nil
	case WireDelimited:
		_, err := r.readDelimited()
		return err
	case WireFixed32:
		if len(r.data)-r.off < 4 {
			return protoErrorf("truncated fixed32 field")
		}
		r.off += 4
		return nil
	}
	return protoErrorf("invalid wire type")
}

// readStringField reads a delimited field as a UTF-8 string.
func (r *protoReader) readStringField(name string, wireType int) (string, error) {
	if wireType != WireDelimited {
		return "", protoErrorf("%s wrong wire type", name)
	}
	raw, err := r.readDelimited()
	if err != nil {
		return "", err
	}
	return decodeString(raw)
}

// readBytesField reads a delimited field as bytes.
func (r *protoReader) readBytesField(name string, wireType int) ([]byte, error) {
	if wireType != WireDelimited {
		return nil, protoErrorf("%s wrong wire type", name)
	}
	return r.readDelimited()
}

// readVarintField reads a varint field.
func (r *protoReader) readVarintField(name string, wireType int) (uint64, error) {
	if wireType != WireVarint {
		return 0, protoErrorf("%s wrong wire type", name)
	}
	return r.readVarint()
}

func decodeString(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", protoErrorf("invalid utf-8 string")
	}
	return string(raw), nil
}
