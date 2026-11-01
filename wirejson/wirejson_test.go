package wirejson

import (
	"strings"
	"testing"
)

func TestMarshalPythonSemantics(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{Obj{{Key: "b", Value: 1}, {Key: "a", Value: 2}}, `{"b":1,"a":2}`}, // ordered kept
		{map[string]any{"b": 1, "a": 2}, `{"a":2,"b":1}`},                  // maps sorted
		{"café", `"caf\u00e9"`},
		{"a\"b\\c\nd", `"a\"b\\c\nd"`},
		{"\x01", `"\u0001"`},
		{"😀", `"\ud83d\ude00"`}, // surrogate pair, like ensure_ascii
		{true, `true`},
		{nil, `null`},
		{int64(-3), `-3`},
		{1.5, `1.5`},
		{float64(2), `2.0`}, // Python float repr keeps .0
		{[]any{1, "x"}, `[1,"x"]`},
	}
	for _, tc := range cases {
		got, err := Marshal(tc.value)
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.value, err)
		}
		if string(got) != tc.want {
			t.Errorf("marshal %v = %s, want %s", tc.value, got, tc.want)
		}
	}
}

func TestDecodeKeepsNumberShapes(t *testing.T) {
	value, err := Decode([]byte(`{"i": 7, "f": 7.5, "s": "x", "n": null}`))
	if err != nil {
		t.Fatal(err)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("decoded %T", value)
	}
	if _, isInt := AsInt64(obj["i"]); !isInt {
		t.Fatal("integer not preserved")
	}
	if _, isFloat := AsFloat64(obj["f"]); !isFloat {
		t.Fatal("float not readable")
	}
	if _, err := Decode([]byte(`{"a":1} garbage`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestTruthy(t *testing.T) {
	for _, v := range []any{nil, false, "", Number("0"), 0, []any{}, map[string]any{}} {
		if Truthy(v) {
			t.Errorf("Truthy(%v) = true", v)
		}
	}
	for _, v := range []any{true, "x", Number("0.5"), 1, []any{1}, map[string]any{"a": 1}} {
		if !Truthy(v) {
			t.Errorf("Truthy(%v) = false", v)
		}
	}
}

func TestEncodedShapeStability(t *testing.T) {
	// Round trip through decode keeps key order for plain objects.
	raw := `{"z":1,"a":{"y":[true,null]}}`
	value, err := Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	out := string(MustMarshal(value))
	if !strings.HasPrefix(out, `{"a":`) { // decoded maps marshal sorted
		t.Fatalf("round trip: %s", out)
	}
}
