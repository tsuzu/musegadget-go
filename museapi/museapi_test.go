package museapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIRoot(t *testing.T) {
	if got := APIRoot(""); got != "https://api.muse.ai" {
		t.Errorf("APIRoot(\"\") = %s", got)
	}
	if got := APIRoot("https://example.test/"); got != "https://example.test" {
		t.Errorf("APIRoot trailing slash = %s", got)
	}
}

func TestUserAgentShape(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "musegadget/0.1.0 (") || !strings.Contains(ua, ") Go/") {
		t.Errorf("UserAgent = %q", ua)
	}
}

func TestFetchVMs(t *testing.T) {
	var gotAuth, gotVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("X-API-Version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vm_list":[
			{"vm_url":"wss://a","vm_auth_token":"t1","vm_name":"A","vm_id":"1"},
			{"vm_ws_url":"wss://b","vm_url":"wss://b2","vm_auth_token":"t2","vm_name":"B","vm_id":"2","default":true},
			{"vm_url":"wss://c"},
			{"vm_auth_token":"t4"},
			"junk"
		]}`))
	}))
	defer server.Close()

	vms, status := FetchVMsWithStatus(context.Background(), "tok", server.URL)
	if status == nil || *status != 200 {
		t.Fatalf("status = %v", status)
	}
	if gotAuth != "Bearer tok" || gotVersion != "1.0.0" {
		t.Fatalf("headers: %q %q", gotAuth, gotVersion)
	}
	if len(vms) != 2 {
		t.Fatalf("vms = %+v", vms)
	}
	if vms[0].URL != "wss://a" || vms[0].IsDefault {
		t.Errorf("vm0 = %+v", vms[0])
	}
	if vms[1].URL != "wss://b" || !vms[1].IsDefault || vms[1].ID != "2" {
		t.Errorf("vm1 = %+v", vms[1])
	}
}

func TestFetchVMsErrorShapes(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantStatus int
	}{
		{"unauthorized", 401, ``, 401},
		{"error body", 200, `{"error_title":"nope","vm_list":[]}`, 200},
		{"missing vm_list", 200, `{}`, 200},
		{"server error", 500, ``, 500},
	}
	for _, tc := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		vms, status := FetchVMsWithStatus(context.Background(), "tok", server.URL)
		server.Close()
		if len(vms) != 0 {
			t.Errorf("%s: vms = %+v", tc.name, vms)
		}
		if status == nil || *status != tc.wantStatus {
			t.Errorf("%s: status = %v, want %d", tc.name, status, tc.wantStatus)
		}
	}
	// Undecodable JSON on a 200 yields a nil status, as in the reference.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()
	if _, status := FetchVMsWithStatus(context.Background(), "tok", server.URL); status != nil {
		t.Errorf("bad JSON status = %v, want nil", *status)
	}
}

func TestRefreshDeviceToken(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"payload":{"access_token":"na","refresh_token":"nr","extra":1}}`))
	}))
	defer server.Close()

	tokens, status := RefreshDeviceToken(context.Background(), "hatch_refresh:raw123", "homelink-000001", server.URL, "mgst_x")
	if status == nil || *status != 200 {
		t.Fatalf("status = %v", status)
	}
	if gotAuth != "Bearer hatch_refresh:raw123" {
		t.Fatalf("auth = %q (prefix must not double)", gotAuth)
	}
	if gotBody["device_id"] != "homelink-000001" || gotBody["sdk_token"] != "mgst_x" {
		t.Fatalf("body = %v", gotBody)
	}
	if tokens["access_token"] != "na" || tokens["refresh_token"] != "nr" {
		t.Fatalf("tokens = %v", tokens)
	}

	// A bare refresh token gets the prefix.
	tokens, _ = RefreshDeviceToken(context.Background(), "bare", "id", server.URL, "")
	if gotAuth != "Bearer hatch_refresh:bare" {
		t.Fatalf("auth = %q", gotAuth)
	}
	_ = tokens
}

func TestRefreshUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer server.Close()
	tokens, status := RefreshDeviceToken(context.Background(), "x", "id", server.URL, "")
	if tokens != nil || status == nil || *status != 401 {
		t.Fatalf("tokens=%v status=%v", tokens, status)
	}
}
