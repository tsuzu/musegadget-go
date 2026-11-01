package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSDKTokenValidation(t *testing.T) {
	valid := "mgst_" + strings.Repeat("a", 42) + "A"
	if !ValidSDKToken(valid) {
		t.Fatal("well-formed token rejected")
	}
	for _, bad := range []string{"", "mgst_short", "mgst_" + strings.Repeat("a", 42) + "B",
		"xxxx_" + strings.Repeat("a", 42) + "A"} {
		if ValidSDKToken(bad) {
			t.Fatalf("token %q accepted", bad)
		}
	}
	if hint := SDKTokenHint(valid); hint != valid[:12] {
		t.Fatalf("hint = %q", hint)
	}
	if hint := SDKTokenHint(""); hint != "none" {
		t.Fatalf("empty hint = %q", hint)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	data := map[string]any{"access_token": "x", "n": 3}
	if err := SaveJSON(PairingFile, data, dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, PairingFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pairing file mode %v, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadJSON(PairingFile, dir)
	if err != nil || loaded["access_token"] != "x" {
		t.Fatalf("loaded: %v %v", loaded, err)
	}
	if err := DeleteJSON(PairingFile, dir); err != nil {
		t.Fatal(err)
	}
	loaded, _ = LoadJSON(PairingFile, dir)
	if loaded != nil {
		t.Fatal("pairing still present after delete")
	}
	// A non-object file loads as nil, not an error.
	if err := os.WriteFile(filepath.Join(dir, PairingFile), []byte(`[1,2]`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadJSON(PairingFile, dir)
	if err != nil || loaded != nil {
		t.Fatalf("non-object load: %v %v", loaded, err)
	}
}
