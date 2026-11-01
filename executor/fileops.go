package executor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"musegadget/wirejson"
)

// Port of musegadget.fileops: chunked file transfer with a .musegadget-
// partial staging file. The reference runs these in a child process as the
// command account; this port runs them in-process (the Go service binary
// is the one holding the account's rights in the Go deployment).

const (
	FileChunkBytes = 64 * 1024
	maxReadBytes   = 64 * 1024
	copyBuffer     = 1024 * 1024
)

func paramIntOr(request map[string]any, key string, defaultValue int64) (int64, string) {
	value, present := request[key]
	if !present || !wirejson.Truthy(value) {
		return defaultValue, ""
	}
	if n, ok := looseInt(value); ok {
		return n, ""
	}
	return 0, fmt.Sprintf("invalid %s value: %v", key, value)
}

func requireAbsolutePath(request map[string]any) (string, string) {
	raw := request["path"]
	path, _ := raw.(string)
	if path == "" || !filepath.IsAbs(path) {
		return "", "path must be an absolute path"
	}
	return path, ""
}

func partialPath(target string) string {
	dir := filepath.Dir(target)
	name := filepath.Base(target)
	return filepath.Join(dir, "."+name+".musegadget-partial")
}

// FileRead implements the file.read operation.
func FileRead(request map[string]any) (wirejson.Obj, string) {
	path, errStr := requireAbsolutePath(request)
	if errStr != "" {
		return nil, errStr
	}
	offset, errStr := paramIntOr(request, "offset", 0)
	if errStr != "" {
		return nil, errStr
	}
	limit, errStr := paramIntOr(request, "limit", maxReadBytes)
	if errStr != "" {
		return nil, errStr
	}
	if limit > maxReadBytes {
		limit = maxReadBytes
	}
	if offset < 0 || limit <= 0 {
		return nil, "offset must be >= 0 and limit > 0"
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err.Error()
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err.Error()
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err.Error()
	}
	// Read one byte past the limit so eof is unambiguous (procfs reports
	// size 0 for files that do have content).
	buffer := make([]byte, limit+1)
	read, err := io.ReadFull(file, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err.Error()
	}
	data := buffer[:read]
	eof := int64(len(data)) <= limit
	if !eof {
		data = data[:limit]
	}
	return wirejson.Obj{
		{Key: "path", Value: path},
		{Key: "size", Value: info.Size()},
		{Key: "offset", Value: offset},
		{Key: "next_offset", Value: offset + int64(len(data))},
		{Key: "eof", Value: eof},
		{Key: "data_b64", Value: base64.StdEncoding.EncodeToString(data)},
	}, ""
}

// FileWrite implements the file.write operation.
func FileWrite(request map[string]any) (wirejson.Obj, string) {
	path, errStr := requireAbsolutePath(request)
	if errStr != "" {
		return nil, errStr
	}
	offset, errStr := paramIntOr(request, "offset", 0)
	if errStr != "" {
		return nil, errStr
	}
	rawB64, _ := request["data_b64"].(string)
	data, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, err.Error()
	}
	if len(data) > FileChunkBytes {
		return nil, fmt.Sprintf("chunk larger than %d bytes", FileChunkBytes)
	}
	partial := partialPath(path)
	var file *os.File
	if offset == 0 {
		if wirejson.Truthy(request["create_parents"]) {
			if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
				return nil, err.Error()
			}
		}
		file, err = os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err.Error()
		}
		// The staged file may be resumed by a later chunk, so it must
		// never be group- or world-readable whatever the umask.
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			return nil, err.Error()
		}
	} else {
		file, err = os.OpenFile(partial, os.O_WRONLY, 0)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, "no write in progress; start at offset 0"
			}
			return nil, err.Error()
		}
	}
	written, errStr := appendChunk(file, data, offset)
	if errStr != "" {
		return nil, errStr
	}
	if !wirejson.Truthy(request["final"]) {
		return wirejson.Obj{
			{Key: "path", Value: path},
			{Key: "received", Value: written},
			{Key: "complete", Value: false},
		}, ""
	}
	digest, err := hashFile(partial)
	if err != nil {
		return nil, err.Error()
	}
	if expected, ok := request["sha256"].(string); ok && expected != "" &&
		strings.ToLower(expected) != digest {
		_ = os.Remove(partial)
		return nil, "sha256 mismatch; write discarded"
	}
	mode := os.FileMode(0o644) &^ currentUmask()
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(partial, mode); err != nil {
		return nil, err.Error()
	}
	overwriteValue, overwritePresent := request["overwrite"]
	if !overwritePresent || wirejson.Truthy(overwriteValue) {
		if err := os.Rename(partial, path); err != nil {
			return nil, err.Error()
		}
	} else if errStr := publishNoOverwrite(partial, path); errStr != "" {
		return nil, errStr
	}
	return wirejson.Obj{
		{Key: "path", Value: path},
		{Key: "size", Value: written},
		{Key: "sha256", Value: digest},
		{Key: "complete", Value: true},
	}, ""
}

func appendChunk(file *os.File, data []byte, offset int64) (int64, string) {
	defer file.Close()
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err.Error()
	}
	if offset != size {
		return 0, fmt.Sprintf("expected offset %d, got %d", size, offset)
	}
	if _, err := file.Write(data); err != nil {
		return 0, err.Error()
	}
	end, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err.Error()
	}
	return end, ""
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.CopyBuffer(digest, file, make([]byte, copyBuffer)); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

var (
	umaskOnce  sync.Once
	umaskValue os.FileMode
)

func currentUmask() os.FileMode {
	umaskOnce.Do(func() {
		mask := syscall.Umask(0)
		syscall.Umask(mask)
		umaskValue = os.FileMode(mask)
	})
	return umaskValue
}

// publishNoOverwrite installs the staged file without ever replacing an
// existing destination.
func publishNoOverwrite(partial, path string) string {
	defer os.Remove(partial)
	err := os.Link(partial, path)
	if err == nil {
		return ""
	}
	if errors.Is(err, os.ErrExist) {
		return "file exists and overwrite is false"
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		errno, ok := linkErr.Err.(syscall.Errno)
		if ok && (errno == syscall.EPERM || errno == syscall.EMLINK ||
			errno == syscall.ENOSYS || errno == syscall.EOPNOTSUPP) {
			return publishWithoutLink(partial, path)
		}
	}
	return err.Error()
}

func publishWithoutLink(partial, path string) string {
	reserved, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "file exists and overwrite is false"
		}
		return err.Error()
	}
	info, statErr := reserved.Stat()
	_ = reserved.Close()
	if statErr != nil {
		return statErr.Error()
	}
	if err := os.Rename(partial, path); err != nil {
		// Drop our reservation only if it is still the file we created.
		if current, lerr := os.Lstat(path); lerr == nil {
			cst, cok := current.Sys().(*syscall.Stat_t)
			rst, rok := info.Sys().(*syscall.Stat_t)
			if cok && rok && cst.Dev == rst.Dev && cst.Ino == rst.Ino {
				_ = os.Remove(path)
			}
		}
		return err.Error()
	}
	return ""
}
