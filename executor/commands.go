package executor

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"musegadget/wirejson"
)

// Port of musegadget.commands: drop-in command definitions from a
// commands.d directory. One ``<command>.json`` file defines one command:
//
//	{"description": "...", "exec": ["/path/to/program", "arg"],
//	 "required": {"name": {"type": "string", "description": "..."}},
//	 "optional": {...}, "timeout_ms": 30000}
//
// The program gets one checked JSON object on stdin and answers with text
// or a JSON object on stdout. Extensions exist to be proposed back once
// they work (see the reference AGENTS.md): definition errors fail loudly
// here so a broken file is never registered half-way.

const (
	MaxCommandNameBytes  = 64
	MaxDefinitionBytes   = 64 * 1024
	DefaultCommandTimeMs = 30000
	MaxCommandTimeMs     = 600000
	// SpecTimeoutGraceMs: the registered spec timeout carries the
	// invocation-budget grace on top of the program's own timeout, so a
	// drop-in is never advertised with a budget its caller cannot grant.
	SpecTimeoutGraceMs = 5000
)

var (
	commandNameRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	reservedPrefixes = []string{"system.", "file.", "device.", "link."}
	definitionKeys   = map[string]bool{
		"description": true, "exec": true, "required": true, "optional": true, "timeout_ms": true,
	}
	paramTypes = []string{"string", "integer", "number", "boolean", "object", "array"}
)

// InvalidCommand marks a definition that must be skipped.
type InvalidCommand struct{ Message string }

func (e *InvalidCommand) Error() string { return e.Message }

func invalidf(format string, args ...any) *InvalidCommand {
	return &InvalidCommand{Message: fmt.Sprintf(format, args...)}
}

// DropInCommand is one validated drop-in command definition.
type DropInCommand struct {
	Name        string
	Description string
	Argv        []string
	Required    []Param
	Optional    []Param
	TimeoutMs   int
}

// Spec renders the commands_v2 spec entry for this command.
func (c *DropInCommand) Spec() wirejson.Obj {
	spec := CommandSpec{
		Description: c.Description,
		Required:    c.Required,
		Optional:    c.Optional,
		TimeoutMs:   intPtr(c.TimeoutMs + SpecTimeoutGraceMs),
	}
	return spec.ToObj()
}

func (c *DropInCommand) paramSpecs() []Param {
	merged := append([]Param{}, c.Required...)
	return append(merged, c.Optional...)
}

// CheckParams validates invoke params against the declared spec and
// returns the checked object, keys in required-then-optional order.
func (c *DropInCommand) CheckParams(params map[string]any) (wirejson.Obj, error) {
	for _, param := range c.Required {
		if _, present := params[param.Name]; !present {
			return nil, errors.New(param.Name + " is required")
		}
	}
	checked := wirejson.Obj{}
	for _, param := range c.paramSpecs() {
		value, present := params[param.Name]
		if !present {
			continue
		}
		if !paramTypeMatches(param.Spec.Type, value) {
			article := "a"
			if strings.ContainsRune("aeiou", rune(param.Spec.Type[0])) {
				article = "an"
			}
			return nil, fmt.Errorf("%s must be %s %s", param.Name, article, param.Spec.Type)
		}
		checked = append(checked, wirejson.Pair{Key: param.Name, Value: value})
	}
	return checked, nil
}

func paramTypeMatches(paramType string, value any) bool {
	switch paramType {
	case "string":
		_, ok := value.(string)
		return ok
	case "integer":
		number, ok := value.(wirejson.Number)
		if !ok {
			return false
		}
		_, err := number.Int64()
		return err == nil
	case "number":
		_, ok := value.(wirejson.Number)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	}
	return false
}

// ParseDropIn validates one definition object.
func ParseDropIn(name string, data map[string]any) (*DropInCommand, error) {
	if len(name) > MaxCommandNameBytes || !commandNameRe.MatchString(name) {
		return nil, invalidf("the file name must be the command name, like sensors.read.json " +
			"(lowercase words joined by dots)")
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return nil, invalidf("names starting with %s are reserved", strings.Join(reservedPrefixes, ", "))
		}
	}
	var unknown []string
	for key := range data {
		if !definitionKeys[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, invalidf("unknown keys: %s", strings.Join(unknown, ", "))
	}
	description, _ := data["description"].(string)
	if strings.TrimSpace(description) == "" {
		return nil, invalidf("description is required")
	}
	argv, err := parseArgv(data["exec"])
	if err != nil {
		return nil, err
	}
	required, err := parseParams(data, "required")
	if err != nil {
		return nil, err
	}
	optional, err := parseParams(data, "optional")
	if err != nil {
		return nil, err
	}
	both := overlapNames(required, optional)
	if len(both) > 0 {
		return nil, invalidf("both required and optional: %s", strings.Join(both, ", "))
	}
	timeoutMs := DefaultCommandTimeMs
	if raw, present := data["timeout_ms"]; present {
		number, ok := raw.(wirejson.Number)
		value, intErr := number.Int64()
		if !ok || intErr != nil || value < 1 || value > MaxCommandTimeMs {
			return nil, invalidf("timeout_ms must be an integer from 1 to %d", MaxCommandTimeMs)
		}
		timeoutMs = int(value)
	}
	return &DropInCommand{
		Name: name, Description: description, Argv: argv,
		Required: required, Optional: optional, TimeoutMs: timeoutMs,
	}, nil
}

func parseArgv(raw any) ([]string, error) {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, invalidf("exec must be a list of strings: the program and its arguments")
	}
	argv := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, invalidf("exec must be a list of strings: the program and its arguments")
		}
		argv = append(argv, text)
	}
	if !filepath.IsAbs(argv[0]) {
		return nil, invalidf("exec must start with the program's absolute path")
	}
	return argv, nil
}

func parseParams(data map[string]any, key string) ([]Param, error) {
	raw, present := data[key]
	if !present {
		return nil, nil
	}
	specs, ok := raw.(map[string]any)
	if !ok {
		return nil, invalidf("%s must be an object of parameter specs", key)
	}
	names := make([]string, 0, len(specs))
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)
	params := make([]Param, 0, len(specs))
	for _, name := range names {
		entry, ok := specs[name].(map[string]any)
		if !ok || len(entry) != 2 {
			return nil, paramsError(key, name)
		}
		typeRaw, hasType := entry["type"]
		descRaw, hasDesc := entry["description"]
		paramType, typeOK := typeRaw.(string)
		_, descOK := descRaw.(string)
		validType := false
		for _, t := range paramTypes {
			if paramType == t {
				validType = true
			}
		}
		if !hasType || !hasDesc || !typeOK || !descOK || !validType {
			return nil, paramsError(key, name)
		}
		params = append(params, Param{
			Name: name,
			Spec: ParamSpec{Type: paramType, Description: descRaw.(string)},
		})
	}
	return params, nil
}

func paramsError(key, name string) error {
	return invalidf("%s.%s must be {\"type\": ..., \"description\": ...} with type one of %s",
		key, name, strings.Join(paramTypes, ", "))
}

func overlapNames(required, optional []Param) []string {
	optionalSet := map[string]bool{}
	for _, p := range optional {
		optionalSet[p.Name] = true
	}
	var both []string
	for _, p := range required {
		if optionalSet[p.Name] {
			both = append(both, p.Name)
		}
	}
	sort.Strings(both)
	return both
}

// LoadCommands loads every valid definition in the directory; invalid
// files are logged and skipped so one bad file never breaks the rest.
func LoadCommands(directory string) []*DropInCommand {
	dir, err := os.Open(directory)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("musegadget: cannot list commands directory %s: %v", directory, err)
		}
		return nil
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return nil
	}
	if os.Geteuid() == 0 && !rootOwnedOnly(info) {
		log.Printf("musegadget: commands directory %s must be owned by root and not group- or world-writable; ignoring it",
			directory)
		return nil
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil
	}
	sort.Strings(names)
	var commands []*DropInCommand
	for _, filename := range names {
		if !strings.HasSuffix(filename, ".json") {
			continue
		}
		command, err := loadCommandFile(dir, filename)
		if err != nil {
			var invalid *InvalidCommand
			if errors.As(err, &invalid) {
				log.Printf("musegadget: ignoring command file %s: %s", filename, invalid.Message)
				continue
			}
			log.Printf("musegadget: ignoring command file %s: %v", filename, err)
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func rootOwnedOnly(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

func loadCommandFile(dir *os.File, filename string) (*DropInCommand, error) {
	file, err := os.OpenFile(filepath.Join(dir.Name(), filename),
		os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return nil, invalidf("can't read it: %s", errno.Error())
		}
		return nil, invalidf("can't read it: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, invalidf("not a regular file")
	}
	if os.Geteuid() == 0 && !rootOwnedOnly(info) {
		return nil, invalidf("must be owned by root and writable only by root")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxDefinitionBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxDefinitionBytes {
		return nil, invalidf("larger than %d bytes", MaxDefinitionBytes)
	}
	value, err := wirejson.Decode(raw)
	if err != nil {
		return nil, invalidf("not valid JSON: %v", err)
	}
	data, ok := value.(map[string]any)
	if !ok {
		return nil, invalidf("the file must hold a JSON object")
	}
	name := strings.TrimSuffix(filename, ".json")
	return ParseDropIn(name, data)
}
