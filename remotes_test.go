package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The proxy carries the panel's own credentials to other servers' traffic
// history, so its boundaries are checked here: what is forwarded, what is not.
func TestRemoteProxy(t *testing.T) {
	var got *http.Request
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		if _, pw, _ := r.BasicAuth(); pw != "remote-pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: authCookieName, Value: "remote-session"})
		w.Write([]byte(`{"ok":true}`))
	}))
	defer remote.Close()

	env := map[string]string{"WGFLOW_REMOTE_PASSWORD_OLD_VPN": "remote-pw"}
	remotes, err := parseRemotes([]string{"old-vpn=" + remote.URL, "bad=" + remote.URL}, "nl3", "panel-pw", func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	s := &webServer{name: "nl3", remotes: remotes}
	mux := http.NewServeMux()
	s.routes(mux)
	panel := newPasswordAuth("panel-pw", "").wrap(mux)

	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.SetBasicAuth("x", "panel-pw")
		req.AddCookie(&http.Cookie{Name: "other", Value: "browser-secret"})
		rec := httptest.NewRecorder()
		panel.ServeHTTP(rec, req)
		return rec
	}

	rec := do("GET", "/s/old-vpn/api/clients?since=15m")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("proxied GET: %d %s", rec.Code, rec.Body)
	}
	if got.URL.Path != "/api/clients" || got.URL.RawQuery != "since=15m" {
		t.Fatalf("remote saw %s?%s", got.URL.Path, got.URL.RawQuery)
	}
	if got.Header.Get("Cookie") != "" {
		t.Fatalf("browser cookies leaked to the remote: %q", got.Header.Get("Cookie"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Value == "remote-session" {
			t.Fatal("remote session cookie reached the browser")
		}
	}

	// The fallback password (the panel's own) is wrong for this remote: a 502,
	// not a 401 that would bounce the browser to the panel login.
	if rec := do("GET", "/s/bad/api/system"); rec.Code != http.StatusBadGateway {
		t.Fatalf("remote 401: got %d", rec.Code)
	}
	for path, want := range map[string]int{
		"/s/old-vpn/":           http.StatusNotFound, // the UI is never proxied
		"/s/old-vpn/index.html": http.StatusNotFound,
		"/s/nope/api/system":    http.StatusNotFound,
	} {
		if rec := do("GET", path); rec.Code != want {
			t.Errorf("%s: got %d, want %d", path, rec.Code, want)
		}
	}
	if rec := do("POST", "/s/old-vpn/api/clients"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: got %d", rec.Code)
	}

	// Without the panel login nothing is proxied.
	req := httptest.NewRequest("GET", "/s/old-vpn/api/clients", nil)
	rec = httptest.NewRecorder()
	panel.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated proxy: got %d", rec.Code)
	}

	rec = do("GET", "/api/servers")
	var list apiServers
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Servers) != 3 || !list.Servers[0].Local || list.Servers[1].Name != "old-vpn" {
		t.Fatalf("/api/servers: %s", rec.Body)
	}
}

func TestParseRemotesRejects(t *testing.T) {
	none := func(string) string { return "" }
	for _, spec := range []string{"noequals", "UP=http://h:1", "x=ftp://h", "x=http://u:p@h:1", "nl3=http://h:1"} {
		if _, err := parseRemotes([]string{spec}, "nl3", "pw", none); err == nil {
			t.Errorf("%q accepted", spec)
		}
	}
	if _, err := parseRemotes([]string{"a=http://h:1"}, "nl3", "", none); err == nil {
		t.Error("remote without any password accepted")
	}
}
