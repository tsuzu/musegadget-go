package executor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"musegadget/wirejson"
)

func resultPayload(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	if result["ok"] != true {
		t.Fatalf("result not ok: %s", wirejson.MustMarshal(result))
	}
	raw := wirejson.MustMarshal(result["payload"])
	decoded, err := wirejson.DecodeMap(raw)
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	return decoded
}

func resultError(t *testing.T, result map[string]any) string {
	t.Helper()
	if result["ok"] != false {
		t.Fatalf("result not an error: %s", wirejson.MustMarshal(result))
	}
	message, _ := result["error"].(string)
	return message
}

func testExecutor(t *testing.T) *Executor {
	t.Helper()
	account := Account{Name: "tester", UID: os.Getuid(), GID: os.Getgid(), Home: t.TempDir()}
	return NewExecutor(account, nil)
}

func TestSystemRun(t *testing.T) {
	executor := testExecutor(t)
	payload := resultPayload(t, executor.Run("system.run",
		map[string]any{"command": "echo hello; echo oops >&2; exit 3"}, nil))
	if payload["stdout"] != "hello\n" || payload["stderr"] != "oops\n" {
		t.Fatalf("streams: %q / %q", payload["stdout"], payload["stderr"])
	}
	if payload["exit_code"] != wirejson.Number("3") || payload["timed_out"] != false {
		t.Fatalf("exit/timed_out: %v %v", payload["exit_code"], payload["timed_out"])
	}
	if _, hasDuration := payload["duration_ms"]; !hasDuration {
		t.Fatal("duration_ms missing")
	}
	if message := resultError(t, executor.Run("system.run", map[string]any{"command": "  "}, nil)); message != "command is required" {
		t.Fatalf("blank command error = %q", message)
	}
	if message := resultError(t, executor.Run("nope.nope", map[string]any{}, nil)); message != "unsupported command: nope.nope" {
		t.Fatalf("unknown command error = %q", message)
	}
}

func TestSystemRunTimeout(t *testing.T) {
	executor := testExecutor(t)
	payload := resultPayload(t, executor.Run("system.run",
		map[string]any{"command": "sleep 30", "timeout_ms": wirejson.Number("150")}, nil))
	if payload["timed_out"] != true {
		t.Fatalf("expected timed_out: %s", wirejson.MustMarshal(payload))
	}
}

func TestFileWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "file.bin")
	content := []byte("hello musegadget world")
	digest := sha256.Sum256(content)
	digestHex := hex.EncodeToString(digest[:])

	write := func(params map[string]any) map[string]any {
		payload, errStr := FileWrite(params)
		if errStr != "" {
			t.Fatalf("FileWrite: %s", errStr)
		}
		raw := wirejson.MustMarshal(payload)
		decoded, _ := wirejson.DecodeMap(raw)
		return decoded
	}
	// Two chunks with create_parents.
	first := write(map[string]any{
		"path": path, "offset": wirejson.Number("0"), "create_parents": true,
		"data_b64": base64.StdEncoding.EncodeToString(content[:5]),
	})
	if first["complete"] != false || first["received"] != wirejson.Number("5") {
		t.Fatalf("first chunk: %v", first)
	}
	second := write(map[string]any{
		"path": path, "offset": wirejson.Number("5"), "final": true,
		"sha256":   digestHex,
		"data_b64": base64.StdEncoding.EncodeToString(content[5:]),
	})
	if second["complete"] != true || second["size"] != wirejson.Number("22") || second["sha256"] != digestHex {
		t.Fatalf("final chunk: %v", second)
	}
	// No-overwrite now refuses.
	_, errStr := FileWrite(map[string]any{
		"path": path, "offset": wirejson.Number("0"), "final": true, "overwrite": false,
		"data_b64": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if errStr != "file exists and overwrite is false" {
		t.Fatalf("overwrite=false error = %q", errStr)
	}
	// Wrong offset mid-write.
	_, errStr = FileWrite(map[string]any{
		"path": path, "offset": wirejson.Number("3"),
		"data_b64": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if errStr != "no write in progress; start at offset 0" {
		t.Fatalf("offset error = %q", errStr)
	}

	read := func(params map[string]any) map[string]any {
		payload, errStr := FileRead(params)
		if errStr != "" {
			t.Fatalf("FileRead: %s", errStr)
		}
		raw := wirejson.MustMarshal(payload)
		decoded, _ := wirejson.DecodeMap(raw)
		return decoded
	}
	got := read(map[string]any{"path": path, "limit": wirejson.Number("10")})
	if got["eof"] != false || got["next_offset"] != wirejson.Number("10") {
		t.Fatalf("first read: %v", got)
	}
	decoded, _ := base64.StdEncoding.DecodeString(got["data_b64"].(string))
	if string(decoded) != "hello muse" {
		t.Fatalf("first read data: %q", decoded)
	}
	got = read(map[string]any{"path": path, "offset": wirejson.Number("10")})
	if got["eof"] != true {
		t.Fatalf("second read: %v", got)
	}
	decoded, _ = base64.StdEncoding.DecodeString(got["data_b64"].(string))
	if string(decoded) != "gadget world" {
		t.Fatalf("second read data: %q", decoded)
	}
	_, errStr = FileRead(map[string]any{"path": "relative/path"})
	if errStr != "path must be an absolute path" {
		t.Fatalf("relative path error = %q", errStr)
	}
}

func TestDropInCommand(t *testing.T) {
	dir := t.TempDir()
	// The reference refuses group/world-writable commands directories when
	// running as root; this environment's temp dirs are 0770.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	definition := `{
	  "description": "Echo the checked params back.",
	  "exec": ["/bin/cat"],
	  "required": {"msg": {"type": "string", "description": "Message."}},
	  "optional": {"count": {"type": "integer", "description": "Count."}},
	  "timeout_ms": 5000
	}`
	if err := os.WriteFile(filepath.Join(dir, "test.echo.json"), []byte(definition), 0o644); err != nil {
		t.Fatal(err)
	}
	broken := `{"description": "", "exec": ["relative/path"]}`
	if err := os.WriteFile(filepath.Join(dir, "test.broken.json"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	commands := LoadCommands(dir)
	if len(commands) != 1 || commands[0].Name != "test.echo" {
		t.Fatalf("loaded: %v", commands)
	}
	account := Account{Name: "tester", UID: os.Getuid(), GID: os.Getgid(), Home: t.TempDir()}
	executor := NewExecutor(account, commands)
	specs, err := executor.Specs("homelink-000001", "Test", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := specs["test.echo"]; !ok {
		t.Fatal("drop-in not in specs")
	}
	specRaw := wirejson.MustMarshal(specs["test.echo"])
	spec, _ := wirejson.DecodeMap(specRaw)
	if spec["timeout_ms"] != wirejson.Number("10000") { // 5000 + grace
		t.Fatalf("spec timeout: %v", spec["timeout_ms"])
	}
	payload := resultPayload(t, executor.Run("test.echo",
		map[string]any{"msg": "hi", "count": wirejson.Number("2"), "extra": "dropped"}, nil))
	if payload["msg"] != "hi" || payload["count"] != wirejson.Number("2") {
		t.Fatalf("echo payload: %v", payload)
	}
	if _, hasExtra := payload["extra"]; hasExtra {
		t.Fatal("undeclared param was passed through")
	}
	if message := resultError(t, executor.Run("test.echo", map[string]any{}, nil)); message != "msg is required" {
		t.Fatalf("required error = %q", message)
	}
	if message := resultError(t, executor.Run("test.echo",
		map[string]any{"msg": wirejson.Number("1")}, nil)); message != "msg must be a string" {
		t.Fatalf("type error = %q", message)
	}
	if message := resultError(t, executor.Run("test.echo",
		map[string]any{"msg": "x", "count": true}, nil)); message != "count must be an integer" {
		t.Fatalf("bool-as-int error = %q", message)
	}
}

func TestParseDropInValidation(t *testing.T) {
	if _, err := ParseDropIn("System.Run", map[string]any{}); err == nil {
		t.Fatal("uppercase name accepted")
	}
	if _, err := ParseDropIn("system.x", map[string]any{
		"description": "d", "exec": []any{"/bin/true"},
	}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved prefix: %v", err)
	}
	if _, err := ParseDropIn("ok.name", map[string]any{
		"description": "d", "exec": []any{"/bin/true"}, "bogus": 1,
	}); err == nil || !strings.Contains(err.Error(), "unknown keys: bogus") {
		t.Fatalf("unknown keys: %v", err)
	}
}

func TestClip(t *testing.T) {
	text, cut := clip([]byte(strings.Repeat("a", MaxOutputBytes+50)))
	if !cut || len(text) != MaxOutputBytes {
		t.Fatalf("ascii clip: cut=%v len=%d", cut, len(text))
	}
	text, cut = clip([]byte(strings.Repeat("あ", 40000)))
	if !cut || jsonEscapedLen(text) > MaxOutputBytes {
		t.Fatalf("unicode clip: cut=%v escaped=%d", cut, jsonEscapedLen(text))
	}
	text, cut = clip([]byte("short"))
	if cut || text != "short" {
		t.Fatalf("short clip: %q %v", text, cut)
	}
}
