package service

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NetworkChecker implements ble.Network the way musegadget.network does:
// online means api.muse.ai:443 accepts a TCP connection (5s), and the
// current-connection entry comes from NetworkManager (nmcli) when it can
// name the active SSID. wpa_cli probing from the reference is not ported;
// the fallback label covers systems without nmcli.
type NetworkChecker struct{}

// IsOnline reports whether api.muse.ai:443 is reachable.
func (NetworkChecker) IsOnline() bool {
	conn, err := net.DialTimeout("tcp", "api.muse.ai:443", 5*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// CurrentConnectionEntry returns the wifi_scan entry for the live
// connection, or nil while offline.
func (n NetworkChecker) CurrentConnectionEntry() map[string]any {
	if !n.IsOnline() {
		return nil
	}
	ssid := CurrentSSID()
	if ssid == "" {
		ssid = "Use current connection"
	}
	return map[string]any{"ssid": ssid, "rssi": -40, "secure": false}
}

// CurrentSSID asks nmcli for the active Wi-Fi SSID ("" when unknown).
func CurrentSSID() string {
	out, err := exec.Command("nmcli", "-t", "-f", "ACTIVE,SSID",
		"device", "wifi", "list", "--rescan", "no").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		active, ssid, found := strings.Cut(line, ":")
		if found && active == "yes" && ssid != "" {
			return unescapeNMCLI(ssid)
		}
	}
	return ""
}

// unescapeNMCLI reverses nmcli's terse-mode escaping (\: and \\), also
// accepting the \xNN form wpa_cli's printf encoding uses.
func unescapeNMCLI(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' || i+1 >= len(text) {
			out.WriteByte(text[i])
			continue
		}
		next := text[i+1]
		if next == 'x' && i+3 < len(text) {
			if value, err := strconv.ParseUint(text[i+2:i+4], 16, 8); err == nil {
				out.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		out.WriteByte(next)
		i++
	}
	return out.String()
}
