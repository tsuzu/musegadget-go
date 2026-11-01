// Package museapi mirrors musegadget.muse_api: the client for the Muse
// device API (leased VM lookup and device token rotation).
package museapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"musegadget"
)

const (
	APIBase     = "https://api.muse.ai"
	FetchPath   = "/fetch_vms"
	RefreshPath = "/device_token/refresh"
)

// HTTPClient performs API requests; tests may replace it.
var HTTPClient = &http.Client{Timeout: 15 * time.Second}

// APIRoot returns the URL API paths are appended to: apiURLV2, or the Muse
// API. api_url (v1) is ignored, as in the reference.
func APIRoot(apiURLV2 string) string {
	if apiURLV2 == "" {
		apiURLV2 = APIBase
	}
	return strings.TrimRight(apiURLV2, "/")
}

// UserAgent mirrors the reference's User-Agent, with the Go runtime in
// place of the Python one: "musegadget/<version> (<details>) Go/<version>".
func UserAgent() string {
	var details []string
	if raw, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		model := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", ""))
		if model != "" {
			details = append(details, model)
		}
	}
	system, machine := runtime.GOOS, runtime.GOARCH
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		system = charsToString(uts.Sysname[:])
		machine = charsToString(uts.Machine[:])
	}
	details = append(details, strings.TrimSpace(system+" "+machine))
	return "musegadget/" + musegadget.Version + " (" + strings.Join(details, "; ") +
		") Go/" + strings.TrimPrefix(runtime.Version(), "go")
}

func charsToString(chars []int8) string {
	b := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// VM is one leased VM entry from fetch_vms.
type VM struct {
	URL       string // vm_ws_url, falling back to vm_url
	AuthToken string
	Name      string
	ID        string
	IsDefault bool
}

func statusPtr(status int) *int { return &status }

func getString(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func truthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case float64:
		return value != 0
	}
	return true
}

// FetchVMsWithStatus returns the leased VMs for the device token, plus the
// HTTP status if one arrived (nil status = transport failure, worth
// retrying). A 401 means the device token was rejected.
func FetchVMsWithStatus(ctx context.Context, accessToken, root string) ([]VM, *int) {
	if root == "" {
		root = APIRoot("")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, root+FetchPath, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-API-Version", "1.0.0")
	req.Header.Set("User-Agent", UserAgent())
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	if status < 200 || status >= 300 {
		io.Copy(io.Discard, resp.Body)
		return nil, statusPtr(status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil || data == nil {
		// A non-object body parses to null / another type in the reference
		// and yields no VMs with the status; undecodable JSON yields a nil
		// status. The distinction barely matters to callers, which treat
		// both as "no VMs, not a 401".
		if err != nil {
			return nil, nil
		}
		return nil, statusPtr(status)
	}
	if truthy(data["error_title"]) || truthy(data["backend_error_code"]) {
		return nil, statusPtr(status)
	}
	vmList, ok := data["vm_list"].([]any)
	if !ok {
		return nil, statusPtr(status)
	}
	vms := []VM{}
	for _, raw := range vmList {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		vmURL := getString(entry, "vm_ws_url")
		if vmURL == "" {
			vmURL = getString(entry, "vm_url")
		}
		token := getString(entry, "vm_auth_token")
		if vmURL != "" && token != "" {
			vms = append(vms, VM{
				URL:       vmURL,
				AuthToken: token,
				Name:      getString(entry, "vm_name"),
				ID:        getString(entry, "vm_id"),
				IsDefault: truthy(entry["default"]),
			})
		}
	}
	return vms, statusPtr(status)
}

// RefreshDeviceToken rotates the device token pair with the refresh token.
// It returns (tokens, status): tokens is nil on failure, and status is the
// HTTP status that ended the attempt, or nil for a transport failure. A 401
// means the pairing is gone. The access token is never presented.
func RefreshDeviceToken(ctx context.Context, refreshToken, deviceID, root, sdkToken string) (map[string]any, *int) {
	if root == "" {
		root = APIRoot("")
	}
	rawRefresh := refreshToken
	if idx := strings.LastIndex(rawRefresh, ":"); idx >= 0 {
		rawRefresh = rawRefresh[idx+1:]
	}
	tokens, err := postRefresh(ctx, "Bearer hatch_refresh:"+rawRefresh, deviceID, root, sdkToken)
	if err != nil {
		var httpErr *httpStatusError
		if errors.As(err, &httpErr) {
			return nil, statusPtr(httpErr.status)
		}
		return nil, nil
	}
	return tokens, statusPtr(200)
}

type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string { return http.StatusText(e.status) }

func postRefresh(ctx context.Context, authHeader, deviceID, root, sdkToken string) (map[string]any, error) {
	body := map[string]any{"device_id": deviceID}
	if sdkToken != "" {
		body["sdk_token"] = sdkToken
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, root+RefreshPath, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent())
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return nil, &httpStatusError{status: resp.StatusCode}
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil || data == nil {
		if err != nil {
			return nil, err
		}
		return nil, nil
	}
	if payload, ok := data["payload"].(map[string]any); ok {
		data = payload
	}
	if getString(data, "access_token") != "" && getString(data, "refresh_token") != "" {
		return data, nil
	}
	return nil, nil
}
