// Package service mirrors musegadget.service: the reconnecting supervisor
// that keeps a link session to the paired Muse, rotates the device token,
// and serves the local message socket. Pairing orchestration (pair.py)
// lives in pair.go; the network check (network.py) in network.go.
package service

import (
	"context"
	"log"
	"math"
	"os"
	"sync"
	"time"

	"musegadget"
	"musegadget/config"
	"musegadget/executor"
	"musegadget/identity"
	"musegadget/linkclient"
	"musegadget/museapi"
	"musegadget/wirejson"
)

const (
	DefaultNoiseHost  = "hatch.metaaivm.com"
	BackoffBaseS      = 2.0
	BackoffMaxS       = 60.0
	AuthBackoffMinS   = 15.0
	HealthySessionS   = 30.0
	UnpairedPollS     = 30.0
	TokenRefreshAgeS  = 3 * 3600
	TokenRetryS       = 300.0
	socketReadTimeout = 10 * time.Second
)

// Backoff is the reconnect delay state: 2s doubling to a 60s ceiling,
// with a floor (for token-level failures).
type Backoff struct {
	Failures int
	Floor    float64
}

// NextDelay returns the next delay and counts the failure.
func (b *Backoff) NextDelay() time.Duration {
	// The delay saturates at the max after a handful of failures, so cap
	// the exponent: 2**failures stops converting to a float at 1024.
	exponent := b.Failures
	if exponent > 16 {
		exponent = 16
	}
	delay := math.Min(BackoffBaseS*math.Pow(2, float64(exponent)), BackoffMaxS)
	b.Failures++
	if delay < b.Floor {
		delay = b.Floor
	}
	return time.Duration(delay * float64(time.Second))
}

// Reset clears the backoff after a healthy session.
func (b *Backoff) Reset() {
	b.Failures = 0
	b.Floor = 0
}

// Service supervises the connection to the paired Muse.
type Service struct {
	Identity    identity.Identity
	Executor    *executor.Executor
	SDKToken    string
	DisplayName string // defaults to the hostname
	StateDir    string // defaults to config.StateDir()

	// SessionFactory builds a session for one VM; nil uses linkclient.
	SessionFactory func(noiseHost, vmID, vmAuthToken string, device linkclient.DeviceDescription,
		runCommand linkclient.RunCommandFunc, opts ...linkclient.Option) (*linkclient.Session, error)
	// Now supplies wall-clock time for token ages; nil uses time.Now.
	Now func() time.Time

	invokeSlots          chan struct{}
	lastRefreshAttempt   time.Time
	sdkTokenChangeWarned bool
	currentMu            sync.Mutex
	current              *linkclient.Session
}

func (s *Service) stateDir() string {
	if s.StateDir != "" {
		return s.StateDir
	}
	return config.StateDir()
}

func (s *Service) displayName() string {
	if s.DisplayName != "" {
		return s.DisplayName
	}
	hostname, _ := os.Hostname()
	return hostname
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) slots() chan struct{} {
	if s.invokeSlots == nil {
		s.invokeSlots = make(chan struct{}, linkclient.MaxConcurrentInvokes)
	}
	return s.invokeSlots
}

// sleep waits, returning false when ctx is done.
func sleep(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func strValue(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return value
}

func intValue(m map[string]any, key string) int64 {
	value, ok := wirejson.AsInt64(m[key])
	if !ok {
		return 0
	}
	return value
}

// Describe builds the device description registered with each session.
func (s *Service) Describe() (linkclient.DeviceDescription, error) {
	specs, err := s.Executor.Specs(s.Identity.NodeID(), s.displayName(), musegadget.Version)
	if err != nil {
		return linkclient.DeviceDescription{}, err
	}
	return linkclient.DeviceDescription{
		NodeID:      s.Identity.NodeID(),
		DisplayName: s.displayName(),
		Version:     musegadget.Version,
		Commands:    specs,
	}, nil
}

// CurrentSession returns the running session, if any.
func (s *Service) CurrentSession() *linkclient.Session {
	s.currentMu.Lock()
	defer s.currentMu.Unlock()
	return s.current
}

func (s *Service) setCurrent(session *linkclient.Session) {
	s.currentMu.Lock()
	s.current = session
	s.currentMu.Unlock()
}

// Run supervises sessions until ctx is cancelled. It also serves the
// local message socket; a socket that cannot be bound fails the run, as
// in the reference.
func (s *Service) Run(ctx context.Context) error {
	listener, err := ServeLocalSocket(config.SocketPath(), localSocketGID(s.Executor))
	if err != nil {
		return err
	}
	defer listener.Close()
	go AcceptLocal(listener, s.handleLocalMessage)

	backoff := &Backoff{}
	tokenRejected := false
	for ctx.Err() == nil {
		pairing, _ := config.LoadJSON(config.PairingFile, s.stateDir())
		if pairing == nil {
			log.Printf("musegadget: not paired; run `musegadget pair` to set up")
			if !sleep(ctx, UnpairedPollS*time.Second) {
				return nil
			}
			continue
		}
		s.warnIfSDKTokenChanged(pairing)
		pairing = s.maybeRefresh(ctx, pairing, false)
		if pairing == nil {
			if !sleep(ctx, TokenRetryS*time.Second) {
				return nil
			}
			continue
		}

		api := museapi.APIRoot(strValue(pairing, "api_url_v2"))
		vms, status := museapi.FetchVMsWithStatus(ctx, strValue(pairing, "access_token"), api)
		if status != nil && *status == 401 {
			log.Printf("musegadget: device token rejected by the API; refreshing")
			if s.maybeRefresh(ctx, pairing, true) == nil {
				if !sleep(ctx, TokenRetryS*time.Second) {
					return nil
				}
			} else if tokenRejected {
				// Allow one immediate retry with the first refreshed
				// token; repeated rejection must not spin through
				// successful refreshes.
				backoff.Floor = AuthBackoffMinS
				if !sleep(ctx, backoff.NextDelay()) {
					return nil
				}
			}
			tokenRejected = true
			continue
		}
		tokenRejected = false
		vm := pickVM(vms)
		if vm == nil {
			if !sleep(ctx, backoff.NextDelay()) {
				return nil
			}
			continue
		}

		outcome, lasted := s.runSession(ctx, *vm, pairing)
		if outcome == linkclient.OutcomeStopped {
			return nil
		}
		if outcome == linkclient.OutcomeUnpaired {
			_ = config.DeleteJSON(config.PairingFile, s.stateDir())
			log.Printf("musegadget: pairing removed; run `musegadget pair` to set up again")
			continue
		}
		if lasted >= HealthySessionS*time.Second {
			backoff.Reset()
		}
		if outcome == linkclient.OutcomeAuthRejected || outcome == linkclient.OutcomeForbidden {
			backoff.Floor = AuthBackoffMinS
		}
		delay := backoff.NextDelay()
		log.Printf("musegadget: reconnecting in %.0fs", delay.Seconds())
		if !sleep(ctx, delay) {
			return nil
		}
	}
	return nil
}

func pickVM(vms []museapi.VM) *museapi.VM {
	for i := range vms {
		if vms[i].IsDefault {
			return &vms[i]
		}
	}
	if len(vms) > 0 {
		return &vms[0]
	}
	return nil
}

func (s *Service) runSession(ctx context.Context, vm museapi.VM, pairing map[string]any) (linkclient.Outcome, time.Duration) {
	device, err := s.Describe()
	if err != nil {
		log.Printf("musegadget: session failed: %v", err)
		return linkclient.OutcomeClosed, 0
	}
	factory := s.SessionFactory
	if factory == nil {
		factory = linkclient.NewSession
	}
	noiseHost := strValue(pairing, "noise_host")
	if noiseHost == "" {
		noiseHost = DefaultNoiseHost
	}
	vmID := vm.ID
	if vmID == "" {
		vmID = vm.Name
	}
	session, err := factory(noiseHost, vmID, vm.AuthToken, device,
		s.Executor.Run, linkclient.WithInvokeSlots(s.slots()))
	if err != nil {
		log.Printf("musegadget: session failed: %v", err)
		return linkclient.OutcomeClosed, 0
	}
	name := vm.Name
	if name == "" {
		name = vm.ID
	}
	log.Printf("musegadget: connecting to %s", name)
	started := time.Now()
	s.setCurrent(session)
	outcome, runErr := session.Run(ctx)
	s.setCurrent(nil)
	if ctx.Err() != nil {
		outcome = linkclient.OutcomeStopped
	} else if runErr != nil && outcome == linkclient.OutcomeClosed {
		log.Printf("musegadget: session failed: %v", runErr)
	}
	lasted := time.Duration(0)
	if registeredAt := session.RegisteredAt(); registeredAt != nil {
		lasted = time.Since(*registeredAt)
	}
	log.Printf("musegadget: session ended: %s after %.0fs", outcome, time.Since(started).Seconds())
	return outcome, lasted
}

func (s *Service) warnIfSDKTokenChanged(pairing map[string]any) {
	paired, present := pairing["sdk_token_hint"]
	if s.sdkTokenChangeWarned || !present || paired == nil {
		return
	}
	pairedHint, _ := paired.(string)
	if pairedHint != config.SDKTokenHint(s.SDKToken) {
		s.sdkTokenChangeWarned = true
		log.Printf("musegadget: paired with SDK token %s, not this one; run `musegadget pair --force` to use it",
			pairedHint)
	}
}

// maybeRefresh rotates the tokens when due, returning the record to use,
// or nil when the current token should not be used yet. The pairing file
// is removed when the pairing itself has been revoked.
func (s *Service) maybeRefresh(ctx context.Context, pairing map[string]any, force bool) map[string]any {
	age := s.now().Unix() - intValue(pairing, "access_token_saved_at")
	if !force && age < TokenRefreshAgeS {
		return pairing
	}
	if !force && time.Since(s.lastRefreshAttempt) < TokenRetryS*time.Second {
		return pairing
	}
	s.lastRefreshAttempt = time.Now()
	tokens, status := museapi.RefreshDeviceToken(ctx, strValue(pairing, "refresh_token"),
		s.Identity.NodeID(), museapi.APIRoot(strValue(pairing, "api_url_v2")), s.SDKToken)
	if tokens != nil {
		merged := map[string]any{}
		for key, value := range pairing {
			merged[key] = value
		}
		merged["access_token"] = tokens["access_token"]
		merged["refresh_token"] = tokens["refresh_token"]
		merged["access_token_saved_at"] = s.now().Unix()
		if err := config.SaveJSON(config.PairingFile, merged, s.stateDir()); err != nil {
			log.Printf("musegadget: could not save rotated token: %v", err)
		}
		log.Printf("musegadget: device token rotated")
		return merged
	}
	if status != nil && *status == 401 {
		_ = config.DeleteJSON(config.PairingFile, s.stateDir())
		log.Printf("musegadget: pairing revoked; run `musegadget pair` to set up again")
		return nil
	}
	// Transient failure: keep using the current token while it still
	// works, except on a forced refresh after a 401.
	if force {
		return nil
	}
	return pairing
}

func localSocketGID(e *executor.Executor) int {
	if e != nil {
		return e.Account.GID
	}
	return -1
}
