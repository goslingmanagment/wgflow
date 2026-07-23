package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	authCookieName        = "wgflow_session"
	authSessionLifetime   = 365 * 24 * time.Hour
	authSessionRenewAfter = 30 * 24 * time.Hour
	maxLoginBodyBytes     = 8 << 10
)

// passwordAuth replaces the browser-owned Basic Auth prompt with a tiny
// password-only login page and a stateless, signed cookie. The signing key is
// derived from the configured password, so sessions survive process restarts
// but are invalidated immediately when the password changes.
type passwordAuth struct {
	passwordHash [sha256.Size]byte
	signingKey   [sha256.Size]byte
	cookieDomain string
	now          func() time.Time
}

func newPasswordAuth(password, cookieDomain string) *passwordAuth {
	passwordHash := sha256.Sum256([]byte(password))
	signingKey := sha256.Sum256(append([]byte("wgflow session cookie v1\x00"), []byte(password)...))
	return &passwordAuth{
		passwordHash: passwordHash,
		signingKey:   signingKey,
		cookieDomain: strings.TrimSpace(cookieDomain),
		now:          time.Now,
	}
}

func (a *passwordAuth) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			a.handleLogin(w, r)
			return
		case "/logout":
			a.handleLogout(w, r)
			return
		}

		expires, viaBasic, ok := a.authenticate(r)
		if ok {
			// This also migrates browsers that still remember the old Basic Auth
			// credentials: one successful request silently gives them the durable
			// session cookie before browser-owned credentials disappear again.
			if viaBasic || expires.Sub(a.now()) <= authSessionRenewAfter {
				a.setSessionCookie(w, r)
			}
			next.ServeHTTP(w, r)
			return
		}

		noStore(w)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// Deliberately omit WWW-Authenticate. Sending it is what makes browsers
			// open the unreliable native username/password prompt.
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		nextURL := safeNext(r.URL.RequestURI())
		http.Redirect(w, r, "/login?next="+url.QueryEscape(nextURL), http.StatusSeeOther)
	})
}

func (a *passwordAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		nextURL := safeNext(r.URL.Query().Get("next"))
		expires, viaBasic, ok := a.authenticate(r)
		if ok {
			if viaBasic || expires.Sub(a.now()) <= authSessionRenewAfter {
				a.setSessionCookie(w, r)
			}
			noStore(w)
			http.Redirect(w, r, nextURL, http.StatusSeeOther)
			return
		}
		a.renderLogin(w, r, http.StatusOK, nextURL, "")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		if err := r.ParseForm(); err != nil {
			a.renderLogin(w, r, http.StatusBadRequest, "/", "Не получилось прочитать форму. Попробуй ещё раз.")
			return
		}
		nextURL := safeNext(r.PostForm.Get("next"))
		gotHash := sha256.Sum256([]byte(r.PostForm.Get("password")))
		if subtle.ConstantTimeCompare(gotHash[:], a.passwordHash[:]) != 1 {
			a.renderLogin(w, r, http.StatusUnauthorized, nextURL, "Пароль не подошёл.")
			return
		}
		a.setSessionCookie(w, r)
		noStore(w)
		http.Redirect(w, r, nextURL, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		noStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *passwordAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		noStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		Domain:   a.cookieDomain,
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	noStore(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// authenticate accepts the durable session cookie and keeps pre-emptive Basic
// Auth working for curl/scripts. Invalid Basic credentials never trigger a
// browser challenge.
func (a *passwordAuth) authenticate(r *http.Request) (expires time.Time, viaBasic, ok bool) {
	if cookie, err := r.Cookie(authCookieName); err == nil {
		if expires, ok := a.validSession(cookie.Value); ok {
			return expires, false, true
		}
	}
	if _, password, hasBasic := r.BasicAuth(); hasBasic {
		gotHash := sha256.Sum256([]byte(password))
		if subtle.ConstantTimeCompare(gotHash[:], a.passwordHash[:]) == 1 {
			return time.Time{}, true, true
		}
	}
	return time.Time{}, false, false
}

func (a *passwordAuth) setSessionCookie(w http.ResponseWriter, r *http.Request) {
	now := a.now()
	expires := now.Add(authSessionLifetime).UTC().Truncate(time.Second)
	payload := "v1." + strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, a.signingKey[:])
	_, _ = mac.Write([]byte(payload))
	token := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		Domain:   a.cookieDomain,
		Expires:  expires,
		MaxAge:   int(authSessionLifetime / time.Second),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *passwordAuth) validSession(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return time.Time{}, false
	}
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	payload := parts[0] + "." + parts[1]
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return time.Time{}, false
	}
	wantMAC := hmac.New(sha256.New, a.signingKey[:])
	_, _ = wantMAC.Write([]byte(payload))
	if !hmac.Equal(gotMAC, wantMAC.Sum(nil)) {
		return time.Time{}, false
	}
	expires := time.Unix(expiresUnix, 0)
	if !expires.After(a.now()) {
		return time.Time{}, false
	}
	return expires, true
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// TLS is commonly terminated by a reverse proxy on the same machine. Use
	// only the first value; proxies append their own hop to this header.
	forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(forwarded, "https")
}

func safeNext(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, `\`) {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	return raw
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

type loginPageData struct {
	Next  string
	Error string
}

func (a *passwordAuth) renderLogin(w http.ResponseWriter, r *http.Request, status int, nextURL, errorMessage string) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = loginTemplate.Execute(w, loginPageData{Next: safeNext(nextURL), Error: errorMessage})
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#0d1117">
  <title>Вход · wgflow</title>
  <style>
    * { box-sizing: border-box; }
    html, body { min-height: 100%; }
    body {
      margin: 0;
      min-height: 100vh;
      min-height: 100dvh;
      display: grid;
      place-items: center;
      padding: 24px;
      background:
        radial-gradient(700px 420px at 50% 15%, rgba(68,147,248,.10), transparent 70%),
        #0d1117;
      color: #e6edf3;
      font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
      -webkit-text-size-adjust: 100%;
    }
    .card {
      width: min(100%, 380px);
      padding: 30px;
      border: 1px solid rgba(255,255,255,.09);
      border-radius: 18px;
      background: rgba(21,27,35,.96);
      box-shadow: 0 24px 80px rgba(0,0,0,.32);
    }
    .mark {
      width: 42px;
      height: 42px;
      display: grid;
      place-items: center;
      margin-bottom: 24px;
      border-radius: 12px;
      background: #e06a3f;
      color: white;
      font-size: 22px;
      font-weight: 700;
    }
    h1 {
      margin: 0 0 6px;
      font: 500 30px/1.1 "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
      letter-spacing: -.02em;
    }
    h1 span { color: #e06a3f; }
    p { margin: 0 0 22px; color: #9aa7b4; }
    label {
      display: block;
      margin: 0 0 8px;
      color: #9aa7b4;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: .06em;
      text-transform: uppercase;
    }
    input {
      width: 100%;
      height: 48px;
      border: 1px solid rgba(255,255,255,.16);
      border-radius: 10px;
      padding: 0 14px;
      outline: none;
      background: #0d1117;
      color: #e6edf3;
      font: 16px ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      transition: border-color .15s, box-shadow .15s;
    }
    input:focus {
      border-color: #4493f8;
      box-shadow: 0 0 0 3px rgba(68,147,248,.16);
    }
    button {
      width: 100%;
      height: 46px;
      margin-top: 12px;
      border: 0;
      border-radius: 10px;
      background: #4493f8;
      color: white;
      font: 600 14px ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      cursor: pointer;
      touch-action: manipulation;
    }
    button:hover { background: #58a1fa; }
    button:active { transform: translateY(1px); }
    .error {
      margin: 0 0 12px;
      padding: 10px 12px;
      border: 1px solid rgba(248,81,73,.35);
      border-radius: 9px;
      background: rgba(248,81,73,.10);
      color: #ff938d;
      font-size: 13px;
    }
    .hint { margin: 16px 0 0; color: #6b7785; font-size: 12px; text-align: center; }
    @media (max-width: 480px) {
      body { padding: 16px; place-items: center; }
      .card { padding: 25px 22px; border-radius: 15px; }
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="mark" aria-hidden="true">↗</div>
    <h1>wgflow<span>.</span></h1>
    <p>Введи пароль — и готово.</p>
    <form action="/login" method="post">
      <input type="hidden" name="next" value="{{.Next}}">
      <input type="text" name="username" value="wgflow" autocomplete="username" hidden>
      {{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
      <label for="password">Пароль</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required maxlength="4096">
      <button type="submit">Войти</button>
    </form>
    <div class="hint">Вход сохранится на этом устройстве</div>
  </main>
</body>
</html>`))
