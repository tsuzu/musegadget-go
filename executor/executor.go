// Package executor mirrors musegadget.executor: the commands a device
// offers its Muse (device.health, system.run, file.read, file.write) plus
// drop-in commands from a commands.d directory (see commands.go).
package executor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"musegadget/linkclient"
	"musegadget/wirejson"
)

const (
	DefaultTimeoutS = 120
	MaxTimeoutS     = 600
	KillGrace       = 2 * time.Second
	// Output bound per stream; the budget is for the wire message.
	MaxOutputBytes = 96 * 1024
	SafePath       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// Account is the account commands run as.
type Account struct {
	Name   string
	UID    int
	GID    int
	Home   string
	Groups []uint32
}

// LookupAccount resolves a user name.
func LookupAccount(name string) (Account, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return Account{}, err
	}
	return accountFromUser(entry)
}

// CurrentAccount resolves the process's own account.
func CurrentAccount() (Account, error) {
	entry, err := user.Current()
	if err != nil {
		return Account{}, err
	}
	return accountFromUser(entry)
}

func accountFromUser(entry *user.User) (Account, error) {
	uid, err := strconv.Atoi(entry.Uid)
	if err != nil {
		return Account{}, err
	}
	gid, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return Account{}, err
	}
	account := Account{Name: entry.Username, UID: uid, GID: gid, Home: entry.HomeDir}
	if groupIDs, err := entry.GroupIds(); err == nil {
		for _, g := range groupIDs {
			if n, err := strconv.Atoi(g); err == nil {
				account.Groups = append(account.Groups, uint32(n))
			}
		}
	}
	return account, nil
}

func okResult(payload any) map[string]any { return map[string]any{"ok": true, "payload": payload} }
func errorResult(message string) map[string]any {
	return map[string]any{"ok": false, "error": message}
}

// ParamSpec is one declared command parameter.
type ParamSpec struct {
	Type        string
	Description string
}

// Param is a named parameter spec, in declaration order.
type Param struct {
	Name string
	Spec ParamSpec
}

func paramsObj(params []Param) wirejson.Obj {
	obj := wirejson.Obj{}
	for _, p := range params {
		obj = append(obj, wirejson.Pair{Key: p.Name, Value: wirejson.Obj{
			{Key: "type", Value: p.Spec.Type},
			{Key: "description", Value: p.Spec.Description},
		}})
	}
	return obj
}

// CommandSpec is one entry of commands_v2.
type CommandSpec struct {
	Description string
	Required    []Param
	Optional    []Param
	TimeoutMs   *int // nil when the spec has no timeout_ms key
}

// ToObj renders the spec in the reference's key order.
func (s CommandSpec) ToObj() wirejson.Obj {
	obj := wirejson.Obj{
		{Key: "description", Value: s.Description},
		{Key: "required", Value: paramsObj(s.Required)},
		{Key: "optional", Value: paramsObj(s.Optional)},
	}
	if s.TimeoutMs != nil {
		obj = append(obj, wirejson.Pair{Key: "timeout_ms", Value: *s.TimeoutMs})
	}
	return obj
}

func intPtr(v int) *int { return &v }

var builtinSpecs = map[string]CommandSpec{
	"system.run": {
		Description: "Run a shell command on this Linux device with bash and return its " +
			"stdout, stderr and exit code. Output over 96 KiB per stream is truncated.",
		Required: []Param{
			{Name: "command", Spec: ParamSpec{Type: "string", Description: "Shell command line to run."}},
		},
		Optional: []Param{
			{Name: "cwd", Spec: ParamSpec{Type: "string", Description: "Working directory. Default: the account's home."}},
			{Name: "timeout_ms", Spec: ParamSpec{Type: "integer", Description: "Kill the command after this long. Default 120000, max 600000."}},
		},
		TimeoutMs: intPtr(MaxTimeoutS*1000 + 5000),
	},
	"file.read": {
		Description: "Read up to 64 KiB of a file, base64-encoded. Call again with next_offset until eof.",
		Required: []Param{
			{Name: "path", Spec: ParamSpec{Type: "string", Description: "Absolute path."}},
		},
		Optional: []Param{
			{Name: "offset", Spec: ParamSpec{Type: "integer", Description: "Byte offset. Default 0."}},
			{Name: "limit", Spec: ParamSpec{Type: "integer", Description: "Max bytes, up to 65536."}},
		},
	},
	"file.write": {
		Description: "Write a file in chunks of up to 64 KiB (base64). Start at offset 0, " +
			"send chunks in order, and set final=true on the last one; the file " +
			"is replaced atomically, and only if sha256 (when given) matches.",
		Required: []Param{
			{Name: "path", Spec: ParamSpec{Type: "string", Description: "Absolute destination path."}},
			{Name: "data_b64", Spec: ParamSpec{Type: "string", Description: "This chunk's bytes, base64-encoded."}},
		},
		Optional: []Param{
			{Name: "offset", Spec: ParamSpec{Type: "integer", Description: "Byte offset of this chunk. Default 0."}},
			{Name: "final", Spec: ParamSpec{Type: "boolean", Description: "True on the last chunk. Default false."}},
			{Name: "sha256", Spec: ParamSpec{Type: "string", Description: "Hex SHA-256 of the whole file, checked on the final chunk."}},
			{Name: "create_parents", Spec: ParamSpec{Type: "boolean", Description: "Create missing parent directories. Default false."}},
			{Name: "overwrite", Spec: ParamSpec{Type: "boolean", Description: "Replace an existing file. Default true."}},
		},
	},
	"device.health": {
		Description: "Device status: uptime, load, memory, disk, temperature, software version.",
	},
}

// BuiltinSpecs returns the built-in command specs (name -> spec object).
func BuiltinSpecs() map[string]any {
	specs := map[string]any{}
	for name, spec := range builtinSpecs {
		specs[name] = spec.ToObj()
	}
	return specs
}

// Executor runs the device's commands as one account.
type Executor struct {
	Account  Account
	dropIns  map[string]*DropInCommand // all valid drop-ins not shadowed by built-ins
	admitted map[string]*DropInCommand
}

// NewExecutor creates an executor; drop-ins whose name collides with a
// built-in are ignored, as in the reference.
func NewExecutor(account Account, dropIns []*DropInCommand) *Executor {
	e := &Executor{Account: account, dropIns: map[string]*DropInCommand{}}
	for _, cmd := range dropIns {
		if _, builtin := builtinSpecs[cmd.Name]; builtin {
			continue
		}
		e.dropIns[cmd.Name] = cmd
	}
	e.admitted = e.dropIns
	return e
}

// Specs returns the commands_v2 map, admitting drop-in definitions in name
// order while the actual register message (with a dummy 36-char id) stays
// within the control message budget. Built-ins are always retained;
// refused definitions are not executable either.
func (e *Executor) Specs(nodeID, displayName, version string) (map[string]any, error) {
	specs := BuiltinSpecs()
	device := linkclient.DeviceDescription{
		NodeID: nodeID, DisplayName: displayName, Version: version, Commands: specs,
	}
	fits := func() bool {
		encoded, err := linkclient.EncodeMessage(device.RegisterMessage(strings.Repeat("0", linkclient.RegisterIDBytes)))
		return err == nil && len(encoded) <= linkclient.MaxControlMessageBytes
	}
	if !fits() {
		return nil, errors.New("device metadata and built-in commands exceed the registration budget")
	}
	names := make([]string, 0, len(e.dropIns))
	for name := range e.dropIns {
		names = append(names, name)
	}
	sort.Strings(names)
	admitted := map[string]*DropInCommand{}
	for _, name := range names {
		specs[name] = e.dropIns[name].Spec()
		if fits() {
			admitted[name] = e.dropIns[name]
		} else {
			delete(specs, name)
			log.Printf("musegadget: skipping command %s: link.register would exceed %d bytes",
				name, linkclient.MaxControlMessageBytes)
		}
	}
	e.admitted = admitted
	return specs, nil
}

// Run dispatches one command and always returns a result dict.
func (e *Executor) Run(command string, params map[string]any, timeoutMs *int64) (result map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("musegadget: %s failed: %v", command, r)
			result = errorResult(fmt.Sprintf("%v", r))
		}
	}()
	switch {
	case command == "system.run":
		return e.SystemRun(params, timeoutMs)
	case command == "file.read":
		payload, errStr := FileRead(params)
		return fileOpResult(payload, errStr)
	case command == "file.write":
		payload, errStr := FileWrite(params)
		return fileOpResult(payload, errStr)
	case command == "device.health":
		return okResult(DeviceHealth())
	default:
		if dropIn, ok := e.admitted[command]; ok {
			return e.RunDropIn(dropIn, params)
		}
		return errorResult("unsupported command: " + command)
	}
}

func fileOpResult(payload wirejson.Obj, errStr string) map[string]any {
	if errStr != "" {
		return errorResult(errStr)
	}
	return okResult(payload)
}

// -- Child processes ----------------------------------------------------------

func (e *Executor) childEnv() []string {
	lang, ok := os.LookupEnv("LANG")
	if !ok {
		lang = "C.UTF-8"
	}
	return []string{
		"HOME=" + e.Account.Home,
		"USER=" + e.Account.Name,
		"LOGNAME=" + e.Account.Name,
		"PATH=" + SafePath,
		"LANG=" + lang,
	}
}

func (e *Executor) childSysProcAttr() *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if os.Geteuid() == 0 && e.Account.UID != 0 {
		attr.Credential = &syscall.Credential{
			Uid: uint32(e.Account.UID), Gid: uint32(e.Account.GID), Groups: e.Account.Groups,
		}
	}
	return attr
}

type cappedBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	room := MaxOutputBytes + 1 - len(b.buf)
	if room > 0 {
		take := room
		if take > len(p) {
			take = len(p)
		}
		b.buf = append(b.buf, p[:take]...)
	}
	b.mu.Unlock()
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...)
}

// runChild runs argv as the account in cwd with the given timeout and
// stdin. It returns stdout, stderr (each capped at MaxOutputBytes+1), the
// exit code (negative signal number when killed) and whether it timed out.
// A start failure is an error.
func (e *Executor) runChild(argv []string, cwd string, timeout time.Duration, stdin []byte) ([]byte, []byte, int, bool, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = e.childEnv()
	cmd.SysProcAttr = e.childSysProcAttr()
	var stdinBuf io.Reader
	if stdin != nil {
		stdinBuf = bytes.NewReader(stdin)
	}
	cmd.Stdin = stdinBuf
	stdout := &cappedBuffer{}
	stderr := &cappedBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, 0, false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	timedOut := false
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	select {
	case waitErr = <-done:
		timer.Stop()
	case <-timer.C:
		timedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case waitErr = <-done:
		case <-time.After(KillGrace):
			_ = cmd.Process.Kill()
			waitErr = <-done
		}
	}
	exitCode := 0
	if cmd.ProcessState != nil {
		if cmd.ProcessState.Exited() {
			exitCode = cmd.ProcessState.ExitCode()
		} else if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			exitCode = -int(status.Signal())
		} else {
			exitCode = -1
		}
	}
	_ = waitErr
	return stdout.Bytes(), stderr.Bytes(), exitCode, timedOut, nil
}

// SystemRun implements the system.run command.
func (e *Executor) SystemRun(params map[string]any, timeoutMs *int64) map[string]any {
	command, _ := params["command"].(string)
	if strings.TrimSpace(command) == "" {
		return errorResult("command is required")
	}
	var requested *int64
	if raw, present := params["timeout_ms"]; present && wirejson.Truthy(raw) {
		if value, ok := looseInt(raw); ok {
			requested = &value
		} else {
			return errorResult(fmt.Sprintf("invalid timeout_ms: %v", raw))
		}
	} else if timeoutMs != nil {
		requested = timeoutMs
	}
	timeoutS := float64(DefaultTimeoutS)
	if requested != nil {
		timeoutS = float64(*requested) / 1000
	}
	if timeoutS > MaxTimeoutS {
		timeoutS = MaxTimeoutS
	}
	cwd, _ := params["cwd"].(string)
	if cwd == "" {
		cwd = e.Account.Home
	}
	log.Printf("musegadget: system.run as %s (timeout %gs)", e.Account.Name, timeoutS)
	started := time.Now()
	stdout, stderr, exitCode, timedOut, err := e.runChild(
		[]string{"/bin/bash", "-c", command}, cwd, time.Duration(timeoutS*float64(time.Second)), nil)
	if err != nil {
		return errorResult("could not start command: " + err.Error())
	}
	out, outCut := clip(stdout)
	errText, errCut := clip(stderr)
	return okResult(wirejson.Obj{
		{Key: "stdout", Value: out},
		{Key: "stderr", Value: errText},
		{Key: "exit_code", Value: exitCode},
		{Key: "timed_out", Value: timedOut},
		{Key: "truncated", Value: outCut || errCut},
		{Key: "duration_ms", Value: int(time.Since(started).Milliseconds())},
	})
}

// RunDropIn implements a drop-in command.
func (e *Executor) RunDropIn(command *DropInCommand, params map[string]any) map[string]any {
	checked, err := command.CheckParams(params)
	if err != nil {
		return errorResult(err.Error())
	}
	request := wirejson.MustMarshal(checked)
	timeoutS := float64(command.TimeoutMs) / 1000
	log.Printf("musegadget: %s as %s (timeout %gs)", command.Name, e.Account.Name, timeoutS)
	stdout, stderr, exitCode, timedOut, err := e.runChild(
		command.Argv, e.Account.Home, time.Duration(timeoutS*float64(time.Second)), request)
	if err != nil {
		return errorResult(fmt.Sprintf("could not start %s: %v", command.Argv[0], err))
	}
	if timedOut {
		return errorResult(fmt.Sprintf("%s timed out after %s",
			command.Name, strconv.FormatFloat(timeoutS, 'g', -1, 64)))
	}
	if exitCode != 0 {
		text := strings.TrimSpace(toValidUTF8(string(stderr)))
		reason := ""
		if text != "" {
			lines := strings.Split(text, "\n")
			last := truncateRunes(strings.TrimRight(lines[len(lines)-1], "\r"), 500)
			reason = ": " + last
		}
		return errorResult(fmt.Sprintf("%s exited with %d%s", command.Name, exitCode, reason))
	}
	out, cut := clip(stdout)
	if !cut {
		if value, err := wirejson.Decode([]byte(out)); err == nil {
			if payload, ok := value.(map[string]any); ok {
				return okResult(payload)
			}
		}
		return okResult(wirejson.Obj{{Key: "output", Value: out}})
	}
	return okResult(wirejson.Obj{
		{Key: "output", Value: out},
		{Key: "truncated", Value: true},
	})
}

// looseInt converts a JSON value the way Python's int() would for the
// shapes commands carry (numbers truncate, numeric strings parse).
func looseInt(v any) (int64, bool) {
	switch value := v.(type) {
	case wirejson.Number:
		if i, err := value.Int64(); err == nil {
			return i, true
		}
		if f, err := value.Float64(); err == nil {
			return int64(f), true
		}
	case bool:
		if value {
			return 1, true
		}
		return 0, true
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			return i, true
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			return int64(f), true
		}
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		return int64(value), true
	}
	return 0, false
}

// clip decodes data as UTF-8 (replacing bad bytes) and shrinks it until
// its Python-style JSON encoding fits the output budget.
func clip(data []byte) (string, bool) {
	cut := len(data) > MaxOutputBytes
	if len(data) > MaxOutputBytes {
		data = data[:MaxOutputBytes]
	}
	text := strings.ToValidUTF8(string(data), "�")
	for jsonEscapedLen(text) > MaxOutputBytes {
		runes := []rune(text)
		text = string(runes[:len(runes)*3/4])
		cut = true
	}
	return text, cut
}

// jsonEscapedLen is the length of Python's json.dumps(text) without the
// surrounding quotes: non-ASCII costs 6 or 12 bytes per character.
func jsonEscapedLen(text string) int {
	length := 0
	for _, r := range text {
		switch {
		case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t' || r == '\b' || r == '\f':
			length += 2
		case r < 0x20 || r > 0x7E:
			if r > 0xFFFF || !utf8.ValidRune(r) {
				length += 12
			} else {
				length += 6
			}
		default:
			length++
		}
	}
	return length
}

func toValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
