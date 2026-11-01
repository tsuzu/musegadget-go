package service

import (
	"context"
	"log"
	"strings"
	"time"

	"musegadget"
	"musegadget/ble"
	"musegadget/config"
	"musegadget/identity"
	"musegadget/museapi"
	"musegadget/pairing"
)

// Port of musegadget.pair: open a BLE setup window until the app pairs
// this device or the window times out.

const (
	// DefaultSetupWindowS is the default pair window, in seconds.
	DefaultSetupWindowS = 600
	// BLEShutdownDelay after a completed setup, so the app receives the
	// final status before the GATT server goes away.
	BLEShutdownDelay = 1500 * time.Millisecond
)

// PairOutcome is how a pair attempt ended.
type PairOutcome string

const (
	PairPaired        PairOutcome = "paired"
	PairAlreadyPaired PairOutcome = "already_paired"
	PairInvalidToken  PairOutcome = "invalid_sdk_token"
	PairWindowClosed  PairOutcome = "window_closed"
)

// SetupWindow tells the user how to pair while the window is open.
type SetupWindow struct {
	BLEName     string
	TimeoutS    int
	HasSDKToken bool
}

// PairOptions configures one Pair call.
type PairOptions struct {
	Identity identity.Identity
	StateDir string // defaults to config.StateDir()
	SDKToken string
	Timeout  time.Duration // defaults to 600s
	Force    bool
	// Factory builds the platform GATT server; nil uses ble.StubFactory
	// (pairing itself is platform-independent and fully implemented).
	Factory ble.ServerFactory
	// Network supplies connectivity; nil uses NetworkChecker.
	Network ble.Network
	// OnOpen is called once with the setup window before advertising
	// starts; nil logs it.
	OnOpen func(SetupWindow)
	// Now supplies wall-clock time; nil uses time.Now.
	Now func() time.Time
}

func (o *PairOptions) stateDir() string {
	if o.StateDir != "" {
		return o.StateDir
	}
	return config.StateDir()
}

func (o *PairOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Pair opens the setup window. It returns PairPaired once the app has
// provisioned this device, or PairWindowClosed when the window expires
// (or ctx is cancelled) first.
func Pair(ctx context.Context, opts PairOptions) (PairOutcome, error) {
	stateDir := opts.stateDir()
	if !opts.Force {
		if existing, _ := config.LoadJSON(config.PairingFile, stateDir); existing != nil {
			return PairAlreadyPaired, nil
		}
	}
	if opts.SDKToken != "" && !config.ValidSDKToken(opts.SDKToken) {
		return PairInvalidToken, nil
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultSetupWindowS * time.Second
	}
	network := opts.Network
	if network == nil {
		network = NetworkChecker{}
	}
	factory := opts.Factory
	if factory == nil {
		factory = ble.StubFactory
	}

	session := pairing.NewSession(pairing.Options{
		NodeID:          opts.Identity.NodeID(),
		DeviceID:        opts.Identity.DeviceID(),
		MAC:             opts.Identity.MAC,
		FirmwareVersion: musegadget.Version,
		SDKToken:        opts.SDKToken,
	})
	provision := func(creds ble.Credentials, commit func(func() bool) bool) error {
		return verifyAndSave(ctx, opts, creds, commit)
	}
	completed := make(chan struct{})
	var controller *ble.Controller
	server, err := factory(opts.Identity.BLEName(),
		func(packet []byte) {
			if controller != nil {
				controller.OnWrite(packet)
			}
		},
		func() {
			if controller != nil {
				controller.OnDisconnect()
			}
		})
	if err != nil {
		return "", err
	}
	controller = ble.NewController(session, opts.Identity, musegadget.Version,
		server, network, provision, func() { close(completed) })

	window := SetupWindow{
		BLEName:     opts.Identity.BLEName(),
		TimeoutS:    int(timeout / time.Second),
		HasSDKToken: opts.SDKToken != "",
	}
	if opts.OnOpen != nil {
		opts.OnOpen(window)
	} else {
		log.Printf("musegadget: pairing window open for %ds; connect to %s in the Muse app",
			window.TimeoutS, window.BLEName)
	}

	controller.Start()
	runErr := make(chan error, 1)
	go func() { runErr <- server.Run() }()
	defer func() {
		controller.Stop()
		server.Stop()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-completed:
		// Give the final status time to reach the app before the server
		// goes away.
		if !sleep(ctx, BLEShutdownDelay) && ctx.Err() != nil {
			return PairWindowClosed, nil
		}
		return PairPaired, nil
	case <-timer.C:
		return PairWindowClosed, nil
	case <-ctx.Done():
		return PairWindowClosed, nil
	case err := <-runErr:
		if err != nil {
			return "", err
		}
		return PairWindowClosed, nil
	}
}

// verifyAndSave checks provisioned credentials against the API (the
// account must have a Muse VM) and persists the pairing record through
// the controller's commit lock.
func verifyAndSave(ctx context.Context, opts PairOptions, creds ble.Credentials,
	commit func(func() bool) bool) error {
	apiURL := ""
	if strings.HasPrefix(creds.APIURL, "https://") {
		apiURL = creds.APIURL
	}
	apiURLV2 := ""
	if strings.HasPrefix(creds.APIURLV2, "https://") {
		apiURLV2 = creds.APIURLV2
	}
	vms, _ := museapi.FetchVMsWithStatus(ctx, creds.AccessToken, museapi.APIRoot(apiURLV2))
	if len(vms) == 0 {
		return &ble.ProvisionFailed{Status: "auth_failed"}
	}
	record := map[string]any{
		"access_token":          creds.AccessToken,
		"refresh_token":         creds.RefreshToken,
		"token_type":            "device",
		"username":              creds.Username,
		"api_url":               apiURL,
		"api_url_v2":            apiURLV2,
		"noise_host":            creds.NoiseHost,
		"access_token_saved_at": opts.now().Unix(),
		"sdk_token_hint":        config.SDKTokenHint(opts.SDKToken),
	}
	saved := commit(func() bool {
		return config.SaveJSON(config.PairingFile, record, opts.stateDir()) == nil
	})
	if !saved {
		return &ble.ProvisionFailed{Status: "error_storage"}
	}
	return nil
}
