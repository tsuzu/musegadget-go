// Package config mirrors musegadget.config: persistent device state in a
// state directory (identity.json, pairing.json, sdk_token), written
// atomically with owner-only permissions.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	StateDirEnv    = "MUSEGADGET_STATE_DIR"
	SocketEnv      = "MUSEGADGET_SOCKET"
	CommandsDirEnv = "MUSEGADGET_COMMANDS_DIR"
	SDKTokenEnv    = "MUSEGADGET_SDK_TOKEN"

	DefaultSocket      = "/run/musegadget/musegadget.sock"
	DefaultStateDir    = "/var/lib/musegadget"
	DefaultCommandsDir = "/etc/musegadget/commands.d"

	IdentityFile = "identity.json"
	PairingFile  = "pairing.json"
	SDKTokenFile = "sdk_token"
)

// mgst_ plus 43 canonical base64url characters, as issued by gadgets.muse.ai.
var sdkTokenRe = regexp.MustCompile(`\Amgst_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\z`)

// StateDir is $MUSEGADGET_STATE_DIR or /var/lib/musegadget.
func StateDir() string {
	if dir := os.Getenv(StateDirEnv); dir != "" {
		return dir
	}
	return DefaultStateDir
}

// SocketPath is $MUSEGADGET_SOCKET or /run/musegadget/musegadget.sock.
func SocketPath() string {
	if path := os.Getenv(SocketEnv); path != "" {
		return path
	}
	return DefaultSocket
}

// CommandsDir is $MUSEGADGET_COMMANDS_DIR or /etc/musegadget/commands.d.
func CommandsDir() string {
	if dir := os.Getenv(CommandsDirEnv); dir != "" {
		return dir
	}
	return DefaultCommandsDir
}

func resolveDir(directory string) string {
	if directory != "" {
		return directory
	}
	return StateDir()
}

// SDKToken returns the SDK token from $MUSEGADGET_SDK_TOKEN or the state
// dir's sdk_token file, or "" when there is none. It returns an error for a
// token that gadgets.muse.ai could not have issued.
func SDKToken(directory string) (string, error) {
	token := os.Getenv(SDKTokenEnv)
	if token == "" {
		data, err := os.ReadFile(filepath.Join(resolveDir(directory), SDKTokenFile))
		if err != nil {
			return "", nil
		}
		token = string(data)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", nil
	}
	if !sdkTokenRe.MatchString(token) {
		return "", errors.New("the SDK token is not valid; copy it again from gadgets.muse.ai")
	}
	return token, nil
}

// SDKTokenHint is the part of an SDK token gadgets.muse.ai shows, or "none".
func SDKTokenHint(token string) string {
	if token == "" {
		return "none"
	}
	if len(token) > 12 {
		return token[:12]
	}
	return token
}

// ValidSDKToken reports whether token has the issued shape.
func ValidSDKToken(token string) bool {
	return sdkTokenRe.MatchString(token)
}

// LoadJSON reads a JSON object from the state dir. A missing or corrupt file
// yields (nil, nil); a permission error is returned, since minting fresh
// state over an unreadable file would silently orphan the real one.
func LoadJSON(name string, directory string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(resolveDir(directory), name))
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, err
		}
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, nil
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, nil
	}
	return obj, nil
}

// SaveJSON atomically writes data as indented JSON, readable only by the
// owner. A crash leaves either the old file or the new one.
func SaveJSON(name string, data map[string]any, directory string) error {
	dir := resolveDir(directory)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(encoded); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// DeleteJSON removes a state file, ignoring a missing one.
func DeleteJSON(name string, directory string) error {
	err := os.Remove(filepath.Join(resolveDir(directory), name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}
