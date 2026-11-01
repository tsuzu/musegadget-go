// Package wirejson encodes JSON the way Python's json.dumps does with
// separators=(",", ":") and ensure_ascii=True, which is what the reference
// SDK puts on the wire for control messages, chat request bodies and pairing
// record plaintexts. Object key order is preserved for values built as Obj;
// plain maps are emitted with sorted keys (JSON objects are unordered, and
// the reference's own parsers do not depend on order).
package wirejson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Pair is one key/value entry of an Obj.
type Pair struct {
	Key   string
	Value any
}

// Obj is a JSON object with deterministic, insertion-ordered keys.
type Obj []Pair

// Set appends or replaces a key, preserving first-insertion order.
func (o *Obj) Set(key string, value any) {
	for i, p := range *o {
		if p.Key == key {
			(*o)[i].Value = value
			return
		}
	}
	*o = append(*o, Pair{key, value})
}

// Get returns the value for key, if present.
func (o Obj) Get(key string) (any, bool) {
	for _, p := range o {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}

// Marshal encodes v like Python json.dumps(v, separators=(",", ":")).
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustMarshal is Marshal but panics on error; for values known to encode.
func MustMarshal(v any) []byte {
	data, err := Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// EncodedLen returns len(Marshal(v)) without building the bytes, in the
// terms the reference uses for size budgets (escaped length). It returns -1
// on encode error.
func EncodedLen(v any) int {
	data, err := Marshal(v)
	if err != nil {
		return -1
	}
	return len(data)
}

func encode(buf *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if value {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encodeString(buf, value)
	case json.Number:
		if !isValidNumber(string(value)) {
			return fmt.Errorf("wirejson: invalid number %q", string(value))
		}
		buf.WriteString(string(value))
	case json.RawMessage:
		buf.Write(value)
	case int:
		buf.WriteString(strconv.FormatInt(int64(value), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(value), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(value), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(value), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(value, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(value, 10))
	case float32:
		return encodeFloat(buf, float64(value))
	case float64:
		return encodeFloat(buf, value)
	case Obj:
		buf.WriteByte('{')
		for i, p := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, p.Key)
			buf.WriteByte(':')
			if err := encode(buf, p.Value); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case *Obj:
		if value == nil {
			buf.WriteString("null")
			return nil
		}
		return encode(buf, *value)
	case map[string]any:
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, value[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, item)
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("wirejson: unsupported type %T", v)
	}
	return nil
}

func isValidNumber(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// encodeString escapes exactly like Python's json encoder with
// ensure_ascii=True: short escapes for the usual controls, \uXXXX for
// anything outside 0x20..0x7E, surrogate pairs above the BMP.
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if b >= 0x20 && b <= 0x7E && b != '"' && b != '\\' {
				i++
				continue
			}
			if start < i {
				buf.WriteString(s[start:i])
			}
			switch b {
			case '"', '\\':
				buf.WriteByte('\\')
				buf.WriteByte(b)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			case '\b':
				buf.WriteString(`\b`)
			case '\f':
				buf.WriteString(`\f`)
			default:
				fmt.Fprintf(buf, `\u%04x`, b)
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if start < i {
			buf.WriteString(s[start:i])
		}
		if r == utf8.RuneError && size == 1 {
			buf.WriteString(`\ufffd`)
		} else if r <= 0xFFFF {
			fmt.Fprintf(buf, `\u%04x`, r)
		} else {
			r -= 0x10000
			fmt.Fprintf(buf, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		}
		i += size
		start = i
	}
	if start < len(s) {
		buf.WriteString(s[start:])
	}
	buf.WriteByte('"')
}

// encodeFloat formats like Python's repr for floats: shortest round-trip,
// fixed notation for exponents in [-4, 16), ".0" for integral fixed values,
// scientific otherwise. NaN and infinities use Python's json spellings.
func encodeFloat(buf *bytes.Buffer, f float64) error {
	switch {
	case math.IsNaN(f):
		buf.WriteString("NaN")
		return nil
	case math.IsInf(f, 1):
		buf.WriteString("Infinity")
		return nil
	case math.IsInf(f, -1):
		buf.WriteString("-Infinity")
		return nil
	}
	if f == 0 {
		if math.Signbit(f) {
			buf.WriteString("-0.0")
		} else {
			buf.WriteString("0.0")
		}
		return nil
	}
	exp := int(math.Floor(math.Log10(math.Abs(f))))
	// Guard against log10 rounding at exact powers of ten.
	if math.Abs(f) >= math.Pow(10, float64(exp+1)) {
		exp++
	} else if math.Abs(f) < math.Pow(10, float64(exp)) {
		exp--
	}
	if exp >= -4 && exp < 16 {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.ContainsAny(s, ".e") {
			s += ".0"
		}
		buf.WriteString(s)
		return nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	// Go gives "1e+20"; Python gives "1e+20" too, but Go mantissa may carry
	// a trailing ".0" ("1.0e+20") where Python writes "1e+20".
	if i := strings.IndexByte(s, 'e'); i > 0 {
		mantissa := strings.TrimSuffix(s[:i], ".0")
		buf.WriteString(mantissa + s[i:])
	} else {
		buf.WriteString(s)
	}
	return nil
}

// Decode parses JSON into any, keeping numbers as json.Number so integer
// values stay distinguishable from floats, as in Python. Like json.loads,
// it rejects trailing data after the value.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("wirejson: trailing data after JSON value")
		}
		return nil, err
	}
	return v, nil
}

// DecodeMap parses a JSON object.
func DecodeMap(data []byte) (map[string]any, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("wirejson: expected a JSON object")
	}
	return m, nil
}

// AsString returns v as a string, if it is one.
func AsString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// AsBool returns v as a bool, if it is one.
func AsBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// AsInt64 converts a JSON number (or Go integer) to int64. Float syntax and
// non-integral values are rejected, mirroring Python's isinstance(int)
// checks after json parsing.
func AsInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), true
		}
	}
	return 0, false
}

// AsFloat64 converts any JSON number to float64.
func AsFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// Number is a decoded JSON number, kept textual so integers and floats
// stay distinguishable as they are in Python.
type Number = json.Number

// Truthy mirrors Python truthiness for JSON values.
func Truthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case json.Number:
		f, err := value.Float64()
		return err == nil && f != 0
	case float64:
		return value != 0
	case float32:
		return value != 0
	case int:
		return value != 0
	case int64:
		return value != 0
	case uint64:
		return value != 0
	case map[string]any:
		return len(value) > 0
	case []any:
		return len(value) > 0
	case Obj:
		return len(value) > 0
	}
	return true
}

// AsMap returns v as a JSON object map, if it is one.
func AsMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// AsSlice returns v as a JSON array, if it is one.
func AsSlice(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}
