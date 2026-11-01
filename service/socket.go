package service

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"musegadget/linkclient"
	"musegadget/wirejson"
)

// MaxLocalRequest bounds one local-socket request line (4 MiB).
const MaxLocalRequest = 4 << 20

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// LocalHandler answers one local-socket request object.
type LocalHandler func(request map[string]any) map[string]any

// ServeLocalSocket binds the unix socket: parent dir 0755, file 0660,
// owned root:account-group when privileged, as in the reference.
func ServeLocalSocket(path string, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 {
		_ = os.Chown(path, 0, gid)
	}
	_ = os.Chmod(path, 0o660)
	return listener, nil
}

// AcceptLocal serves connections until the listener is closed.
func AcceptLocal(listener net.Listener, handler LocalHandler) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go serveLocalConn(conn, handler)
	}
}

func serveLocalConn(conn net.Conn, handler LocalHandler) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(socketReadTimeout))
	reader := bufio.NewReader(conn)
	// Read one line, bounded; an over-limit line gets an error reply and
	// is then drained to its newline, mirroring the reference.
	line, overLimit, err := readBoundedLine(reader, MaxLocalRequest)
	if err != nil && len(line) == 0 && !overLimit {
		return
	}
	var reply map[string]any
	if overLimit {
		reply = map[string]any{"ok": false, "error": "the request is over 4 MiB"}
		// Drain the rest of the line, unless the bounded read already
		// consumed its terminating newline.
		if len(line) == 0 || line[len(line)-1] != '\n' {
			drainLine(reader)
		}
	} else {
		reply = handleLocalLine(line, handler)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(socketReadTimeout))
	_, _ = conn.Write(append(wirejson.MustMarshal(reply), '\n'))
}

func readBoundedLine(reader *bufio.Reader, limit int) ([]byte, bool, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		line = append(line, fragment...)
		if len(line) > limit {
			return line, true, nil
		}
		switch {
		case err == nil:
			return line, false, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return line, false, err
		}
	}
}

func drainLine(reader *bufio.Reader) {
	for {
		_, err := reader.ReadSlice('\n')
		if err == nil || !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

func handleLocalLine(line []byte, handler LocalHandler) map[string]any {
	request, err := wirejson.DecodeMap(line)
	if err != nil {
		return map[string]any{"ok": false, "error": `expected {"message": "..."}`}
	}
	return handler(request)
}

// handleLocalMessage validates one request and forwards it to the
// current session (the reference's _send_local).
func (s *Service) handleLocalMessage(request map[string]any) map[string]any {
	fail := func(message string) map[string]any {
		return map[string]any{"ok": false, "error": message}
	}
	message, _ := request["message"].(string)
	if message == "" {
		return fail(`expected {"message": "..."}`)
	}
	var sessionID string
	if raw, present := request["session_id"]; present && raw != nil {
		text, _ := raw.(string)
		if !sessionIDRe.MatchString(text) {
			return fail("session_id must be letters, digits and dashes")
		}
		sessionID = text
	}
	type imageData struct {
		mimeType string
		data     []byte
		filename string
	}
	var image *imageData
	if raw, present := request["image"]; present && raw != nil {
		obj, ok := raw.(map[string]any)
		if !ok || len(obj) != 3 {
			return fail("image must be {mime_type, data_base64, filename}")
		}
		mimeType, okMime := obj["mime_type"].(string)
		dataB64, okData := obj["data_base64"].(string)
		filename, okName := obj["filename"].(string)
		if !okMime || !okData || !okName {
			return fail("image must be {mime_type, data_base64, filename}")
		}
		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			return fail("image data_base64 is not valid base64")
		}
		if err := linkclient.CheckImage(data, mimeType); err != nil {
			return fail(err.Error())
		}
		image = &imageData{mimeType: mimeType, data: data, filename: filename}
	}
	session := s.CurrentSession()
	if session == nil || session.RegisteredAt() == nil {
		return fail("not connected to the Muse")
	}
	ctx := context.Background()
	var err error
	if image != nil {
		_, err = session.SendImage(ctx, image.data, image.mimeType, sessionID, "", image.filename, "")
	} else {
		_, err = session.SendChat(ctx, message, sessionID, "")
	}
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"ok": true}
}

// LocalImage is an image attachment for SendLocalMessage.
type LocalImage struct {
	MimeType string
	Data     []byte
	Filename string
}

// SendLocalMessage delivers one message through a running service's
// local socket (what `musegadget send-user-msg` uses).
func SendLocalMessage(socketPath, message, sessionID string, image *LocalImage) error {
	request := wirejson.Obj{{Key: "message", Value: message}}
	if sessionID != "" {
		request = append(request, wirejson.Pair{Key: "session_id", Value: sessionID})
	}
	if image != nil {
		request = append(request, wirejson.Pair{Key: "image", Value: wirejson.Obj{
			{Key: "mime_type", Value: image.MimeType},
			{Key: "data_base64", Value: base64.StdEncoding.EncodeToString(image.Data)},
			{Key: "filename", Value: image.Filename},
		}})
	}
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("no response from the running musegadget service: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(90 * time.Second))
	if _, err := conn.Write(append(wirejson.MustMarshal(request), '\n')); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		if errors.Is(err, io.EOF) {
			return errors.New("no response from the running musegadget service")
		}
		return err
	}
	reply, err := wirejson.DecodeMap(line)
	if err != nil {
		return errors.New("no response from the running musegadget service")
	}
	if ok, _ := reply["ok"].(bool); ok {
		return nil
	}
	if message, _ := reply["error"].(string); message != "" {
		return errors.New(message)
	}
	return errors.New("the running musegadget service reported an error")
}
