// Command musegadget is the Go port of the reference CLI: pair, run,
// send-user-msg, info and unpair subcommands. (The reference's voice-call
// and doctor subcommands are out of scope for the minimal client.)
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"musegadget"
	"musegadget/config"
	"musegadget/executor"
	"musegadget/identity"
	"musegadget/linkclient"
	"musegadget/service"
	"musegadget/wirejson"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: musegadget <pair|run|send-user-msg|info|unpair> [flags]")
		return 2
	}
	switch args[0] {
	case "pair":
		return cmdPair(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "send-user-msg":
		return cmdSendUserMsg(args[1:])
	case "info":
		return cmdInfo(args[1:])
	case "unpair":
		return cmdUnpair(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", args[0])
		return 2
	}
}

// sdkToken returns the configured SDK token, or "" (logging why a
// malformed one is being ignored, as the reference does).
func sdkToken() string {
	token, err := config.SDKToken("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "musegadget: running without an SDK token: %v\n", err)
		return ""
	}
	return token
}

func loadIdentity() (identity.Identity, error) {
	return identity.LoadOrCreate(config.StateDir())
}

func cmdPair(args []string) int {
	flags := flag.NewFlagSet("pair", flag.ContinueOnError)
	timeout := flags.Int("timeout", service.DefaultSetupWindowS, "setup window, seconds")
	force := flags.Bool("force", false, "pair again even when already paired")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	id, err := loadIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	token := sdkToken()
	outcome, err := service.Pair(context.Background(), service.PairOptions{
		Identity: id,
		SDKToken: token,
		Timeout:  time.Duration(*timeout) * time.Second,
		Force:    *force,
		OnOpen: func(window service.SetupWindow) {
			if !window.HasSDKToken {
				fmt.Fprintln(os.Stderr, "No SDK token yet. Get one at gadgets.muse.ai and run "+
					"`bash install.sh --sdk-token mgst_…`; gadgets without one will stop pairing.")
			}
			fmt.Printf("Setup open for %d minutes. In the Muse app, add a device\n", window.TimeoutS/60)
			fmt.Printf("and choose %s.\n", window.BLEName)
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	switch outcome {
	case service.PairPaired:
		fmt.Println("Paired.")
		return 0
	case service.PairAlreadyPaired:
		fmt.Fprintln(os.Stderr, "Already paired. Run `musegadget unpair` first, or pass --force.")
	case service.PairInvalidToken:
		fmt.Fprintln(os.Stderr, "Can't pair: the SDK token is not valid; copy it again from gadgets.muse.ai.")
	case service.PairWindowClosed:
		fmt.Fprintln(os.Stderr, "Setup window closed without pairing.")
	}
	return 1
}

func cmdRun(args []string) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	runAs := flags.String("run-as", "", "account whose permissions commands get (required as root)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	var account executor.Account
	var err error
	if os.Geteuid() == 0 {
		if *runAs == "" {
			fmt.Fprintln(os.Stderr, "Pass --run-as ACCOUNT (the account whose permissions commands get).")
			return 1
		}
		account, err = executor.LookupAccount(*runAs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Account '%s' does not exist. Create it, or pass --run-as.\n", *runAs)
			return 1
		}
	} else {
		account, err = executor.CurrentAccount()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	id, err := loadIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("musegadget: musegadget %s: commands run as %s\n", musegadget.Version, account.Name)
	svc := &service.Service{
		Identity: id,
		Executor: executor.NewExecutor(account, executor.LoadCommands(config.CommandsDir())),
		SDKToken: sdkToken(),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := svc.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

var imageTypes = map[string]string{
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
	".gif": "image/gif", ".webp": "image/webp",
}

func commas(n int64) string {
	text := fmt.Sprintf("%d", n)
	var parts []string
	for len(text) > 3 {
		parts = append([]string{text[len(text)-3:]}, parts...)
		text = text[:len(text)-3]
	}
	return strings.Join(append([]string{text}, parts...), ",")
}

// readImageArg validates and reads a --image file the way the reference
// CLI does, printing the reason and returning nil on failure.
func readImageArg(path string) *service.LocalImage {
	name := filepath.Base(path)
	mimeType, ok := imageTypes[strings.ToLower(filepath.Ext(path))]
	if !ok {
		fmt.Fprintf(os.Stderr, "%s is not a JPEG, PNG, GIF or WebP image\n", name)
		return nil
	}
	tooBig := fmt.Sprintf("images must be 2 MiB (%s bytes) or less", commas(linkclient.MaxImageBytes))
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", path, err)
		return nil
	}
	if !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "%s is not a regular file\n", name)
		return nil
	}
	if info.Size() > linkclient.MaxImageBytes {
		fmt.Fprintf(os.Stderr, "%s is %s bytes; %s\n", name, commas(info.Size()), tooBig)
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", path, err)
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, linkclient.MaxImageBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", path, err)
		return nil
	}
	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "%s is empty\n", name)
		return nil
	}
	if int64(len(data)) > linkclient.MaxImageBytes {
		fmt.Fprintf(os.Stderr, "%s is over the limit; %s\n", name, tooBig)
		return nil
	}
	return &service.LocalImage{MimeType: mimeType, Data: data, Filename: name}
}

func cmdSendUserMsg(args []string) int {
	flags := flag.NewFlagSet("send-user-msg", flag.ContinueOnError)
	sessionID := flags.String("session-id", "", "side chat session id")
	imagePath := flags.String("image", "", "attach an image file")
	// Flags may come after the message words in the reference (argparse
	// accepts them anywhere); stdlib flag stops at the first non-flag, so
	// parse in two passes.
	var words []string
	rest := args
	for {
		if err := flags.Parse(rest); err != nil {
			return 2
		}
		remaining := flags.Args()
		if len(remaining) == 0 {
			break
		}
		words = append(words, remaining[0])
		rest = remaining[1:]
		if len(rest) == 0 {
			break
		}
	}
	var message string
	if len(words) == 1 && words[0] == "-" {
		data, _ := io.ReadAll(os.Stdin)
		message = string(data)
	} else {
		message = strings.Join(words, " ")
	}
	request := wirejson.Obj{{Key: "message", Value: message}}
	if *sessionID != "" {
		request = append(request, wirejson.Pair{Key: "session_id", Value: *sessionID})
	}
	if *imagePath != "" {
		image := readImageArg(*imagePath)
		if image == nil {
			return 1
		}
		request = append(request, wirejson.Pair{Key: "image", Value: wirejson.Obj{
			{Key: "mime_type", Value: image.MimeType},
			{Key: "data_base64", Value: base64.StdEncoding.EncodeToString(image.Data)},
			{Key: "filename", Value: image.Filename},
		}})
	}
	reply, err := localRoundTrip(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not reach the musegadget service: %v\n", err)
		return 1
	}
	if ok, _ := reply["ok"].(bool); !ok {
		reason, _ := reply["error"].(string)
		if reason == "" {
			reason = string(wirejson.MustMarshal(reply))
		}
		fmt.Fprintf(os.Stderr, "Not delivered: %s\n", reason)
		return 1
	}
	fmt.Println("Sent to your Muse.")
	return 0
}

// localRoundTrip sends one request line to the running service and reads
// its reply line (90s), mirroring cmd_send_user_msg's socket handling.
func localRoundTrip(request wirejson.Obj) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", config.SocketPath(), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(90 * time.Second))
	if _, err := conn.Write(append(wirejson.MustMarshal(request), '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	reply, err := wirejson.DecodeMap(line)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func cmdInfo(args []string) int {
	id, err := loadIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pairing, _ := config.LoadJSON(config.PairingFile, config.StateDir())
	hint := "not valid"
	if token, tokenErr := config.SDKToken(""); tokenErr == nil {
		hint = config.SDKTokenHint(token)
	}
	fmt.Printf("version:   %s\n", musegadget.Version)
	fmt.Printf("node id:   %s\n", id.NodeID())
	fmt.Printf("BLE name:  %s\n", id.BLEName())
	fmt.Printf("SDK token: %s\n", hint)
	if pairing == nil {
		fmt.Println("paired:    no")
		return 0
	}
	pairedWith, hasHint := pairing["sdk_token_hint"].(string)
	if hasHint && pairedWith != hint {
		fmt.Printf("paired:    yes, with SDK token %s; run `musegadget pair --force` to use this one\n", pairedWith)
	} else {
		fmt.Println("paired:    yes")
	}
	return 0
}

func cmdUnpair(args []string) int {
	_ = config.DeleteJSON(config.PairingFile, config.StateDir())
	fmt.Println("Pairing removed. The device identity is kept.")
	return 0
}
