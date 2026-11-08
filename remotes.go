package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// One panel for several loggers. Each VPS keeps its own logs and its own
// `wgflow web`; the panel the operator opens lists them (`--remote`) and proxies
// the read-only API of the selected one under /s/<name>/api/…. Data never moves
// between servers, and a VPS that is unreachable from the operator's network
// (one-way IP bans) is still shown as long as the panel's host can reach it.

var remoteNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type remoteServer struct {
	name   string
	target *url.URL
	proxy  *httputil.ReverseProxy
}

// remoteFlags collects repeated --remote name=URL values.
type remoteFlags []string

func (f *remoteFlags) String() string     { return strings.Join(*f, ",") }
func (f *remoteFlags) Set(v string) error { *f = append(*f, v); return nil }

// remotePasswordEnv is the per-remote override: WGFLOW_REMOTE_PASSWORD_<NAME>,
// with the name upper-cased and dashes turned into underscores.
func remotePasswordEnv(name string) string {
	return "WGFLOW_REMOTE_PASSWORD_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// parseRemotes turns --remote values into proxies. The password for a remote is
// WGFLOW_REMOTE_PASSWORD_<NAME>, then WGFLOW_REMOTE_PASSWORD, then the panel's
// own login password (the usual setup: one password on every server).
func parseRemotes(specs []string, localName, localPassword string, getenv func(string) string) ([]*remoteServer, error) {
	seen := map[string]bool{localName: true}
	var out []*remoteServer
	for _, spec := range specs {
		name, raw, ok := strings.Cut(spec, "=")
		name = strings.TrimSpace(name)
		if !ok || !remoteNameRe.MatchString(name) {
			return nil, fmt.Errorf("--remote %q: want name=URL, name of a-z, 0-9 and dashes", spec)
		}
		if seen[name] {
			return nil, fmt.Errorf("--remote %q: name %q is already used", spec, name)
		}
		seen[name] = true
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("--remote %q: want an http(s)://host[:port] URL without credentials", spec)
		}
		u.Path = strings.TrimRight(u.Path, "/")
		password := getenv(remotePasswordEnv(name))
		if password == "" {
			password = getenv("WGFLOW_REMOTE_PASSWORD")
		}
		if password == "" {
			password = localPassword
		}
		if password == "" {
			return nil, fmt.Errorf("--remote %s: no password (set %s or WGFLOW_REMOTE_PASSWORD)", name, remotePasswordEnv(name))
		}
		out = append(out, newRemoteServer(name, u, password))
	}
	return out, nil
}

var errRemoteLoginRejected = errors.New("remote rejected the login")

func newRemoteServer(name string, target *url.URL, password string) *remoteServer {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.Proxy = nil
	rs := &remoteServer{name: name, target: target}
	rs.proxy = &httputil.ReverseProxy{
		Transport: transport,
		// SSE (/api/stats/stream) must reach the browser event by event.
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			rest := pr.In.URL.Path[len("/s/"+name):]
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = target.Path + rest
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = target.Host
			// Nothing of the operator's browser session goes to another server:
			// it authenticates as the panel, with that server's password.
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Referer")
			pr.Out.Header.Del("Origin")
			pr.Out.SetBasicAuth("wgflow", password)
		},
		ModifyResponse: func(resp *http.Response) error {
			// The remote answers a Basic login with its own session cookie; on the
			// panel's origin that cookie would be meaningless or, worse, clash.
			resp.Header.Del("Set-Cookie")
			if resp.StatusCode == http.StatusUnauthorized {
				// Passing 401 through would send the browser to the panel's login
				// page in a loop, though the panel login is fine.
				return errRemoteLoginRejected
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			msg := fmt.Sprintf("server %s unreachable: %v", name, err)
			if errors.Is(err, errRemoteLoginRejected) {
				msg = fmt.Sprintf("server %s rejected the panel's password", name)
			}
			writeJSONError(w, http.StatusBadGateway, msg)
		},
	}
	return rs
}

type apiServer struct {
	Name  string `json:"name"`
	Local bool   `json:"local"`
}

type apiServers struct {
	Servers []apiServer `json:"servers"`
}

func (s *webServer) handleServers(w http.ResponseWriter, r *http.Request) {
	out := apiServers{Servers: []apiServer{{Name: s.name, Local: true}}}
	for _, rs := range s.remotes {
		out.Servers = append(out.Servers, apiServer{Name: rs.name})
	}
	writeJSON(w, out)
}

// handleRemote serves /s/<name>/api/… from the named remote. Only the read-only
// API is proxied: the UI itself always comes from this panel.
func (s *webServer) handleRemote(w http.ResponseWriter, r *http.Request) {
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/s/"), "/")
	var rs *remoteServer
	for _, c := range s.remotes {
		if c.name == name {
			rs = c
			break
		}
	}
	if rs == nil {
		writeJSONError(w, http.StatusNotFound, "unknown server")
		return
	}
	if !strings.HasPrefix("/"+rest, "/api/") || strings.Contains(rest, "..") {
		writeJSONError(w, http.StatusNotFound, "only /api/ is served for other servers")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rs.proxy.ServeHTTP(w, r)
}

// defaultServerName labels this panel's own logger in the server switcher.
func defaultServerName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "local"
	}
	h, _, _ = strings.Cut(strings.ToLower(h), ".")
	if !remoteNameRe.MatchString(h) {
		return "local"
	}
	return h
}
