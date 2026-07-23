package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fixedPasswordAuth(password, domain string, now time.Time) *passwordAuth {
	auth := newPasswordAuth(password, domain)
	auth.now = func() time.Time { return now }
	return auth
}

func authTestNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func submitLogin(handler http.Handler, password, next string) *httptest.ResponseRecorder {
	form := url.Values{"password": {password}, "next": {next}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == authCookieName {
			return cookie
		}
	}
	t.Fatal("response did not set the session cookie")
	return nil
}

func TestPasswordAuthUsesLoginPageWithoutBrowserChallenge(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	handler := fixedPasswordAuth("secret", "", now).wrap(authTestNext())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/clients?since=15m", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("browser status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got := rec.Header().Get("Location"); got != "/login?next=%2Fclients%3Fsince%3D15m" {
		t.Errorf("redirect = %q", got)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q; native Basic Auth prompt must stay disabled", got)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?next=%2Freports", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("login page status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `type="password"`) || !strings.Contains(body, `value="/reports"`) {
		t.Errorf("login page is missing the password field or return path")
	}
	if !strings.Contains(body, `name="username" value="wgflow" autocomplete="username" hidden`) {
		t.Error("login page is missing the hidden username hint used by password managers")
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/system", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("API status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("API WWW-Authenticate = %q; browser prompt must stay disabled", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("API Cache-Control = %q, want no-store", got)
	}
}

func TestPasswordLoginCreatesDurableRestartSafeSession(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	auth := fixedPasswordAuth("secret", "", now)
	handler := auth.wrap(authTestNext())

	rec := submitLogin(handler, "secret", "/reports?since=24h")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want %d; body=%s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/reports?since=24h" {
		t.Errorf("post-login redirect = %q", got)
	}
	cookie := sessionCookie(t, rec)
	if cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags = path:%q httpOnly:%t sameSite:%v", cookie.Path, cookie.HttpOnly, cookie.SameSite)
	}
	if cookie.MaxAge != int(authSessionLifetime/time.Second) {
		t.Errorf("cookie MaxAge = %d, want %d", cookie.MaxAge, int(authSessionLifetime/time.Second))
	}
	if want := now.Add(authSessionLifetime); !cookie.Expires.Equal(want) {
		t.Errorf("cookie expiry = %v, want %v", cookie.Expires, want)
	}
	if strings.Contains(cookie.Value, "secret") {
		t.Error("session cookie contains the password")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cookie-authenticated status = %d, want 204", rec.Code)
	}

	// A fresh handler models a process restart. The cookie remains valid because
	// its signing key is deterministically derived from the same password.
	restarted := fixedPasswordAuth("secret", "", now.Add(90*24*time.Hour)).wrap(authTestNext())
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	restarted.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status after restart = %d, want 204", rec.Code)
	}

	changedPassword := fixedPasswordAuth("new-secret", "", now.Add(90*24*time.Hour)).wrap(authTestNext())
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	changedPassword.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status after password change = %d, want login redirect", rec.Code)
	}
}

func TestPasswordLoginRejectsWrongPasswordAndUnsafeReturnURL(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	handler := fixedPasswordAuth("secret", "", now).wrap(authTestNext())

	rec := submitLogin(handler, "wrong", "https://evil.example/steal")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Пароль не подошёл.") {
		t.Errorf("wrong-password page does not explain the error")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("wrong password unexpectedly set a cookie")
	}

	rec = submitLogin(handler, "secret", "//evil.example/steal")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("safe login status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Errorf("unsafe post-login redirect = %q, want /", got)
	}
}

func TestPasswordAuthRejectsExpiredAndTamperedCookies(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	auth := fixedPasswordAuth("secret", "", now)
	rec := submitLogin(auth.wrap(authTestNext()), "secret", "/")
	cookie := sessionCookie(t, rec)

	expired := fixedPasswordAuth("secret", "", now.Add(authSessionLifetime+time.Second)).wrap(authTestNext())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	expired.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expired-cookie status = %d, want login redirect", rec.Code)
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("unexpected session token format %q", cookie.Value)
	}
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	tampered := *cookie
	tampered.Value = strings.Join(parts, ".")
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&tampered)
	rec = httptest.NewRecorder()
	auth.wrap(authTestNext()).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("tampered-cookie status = %d, want login redirect", rec.Code)
	}
}

func TestPasswordAuthKeepsPreemptiveBasicAuthForCompatibility(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	handler := fixedPasswordAuth("secret", "", now).wrap(authTestNext())

	req := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	req.SetBasicAuth("anything", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid Basic Auth status = %d, want 204", rec.Code)
	}
	sessionCookie(t, rec) // successful legacy auth must migrate to a cookie

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("anything", "wrong")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("invalid Basic Auth status = %d, want login redirect", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("invalid Basic Auth emitted a browser challenge: %q", got)
	}
}

func TestPasswordAuthRenewsOldSessionAndSupportsSharedSecureCookie(t *testing.T) {
	issuedAt := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	auth := fixedPasswordAuth("secret", ".example.com", issuedAt)
	loginReq := httptest.NewRequest(http.MethodPost, "https://vpn.example.com/login", strings.NewReader(url.Values{
		"password": {"secret"},
		"next":     {"/"},
	}.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	auth.wrap(authTestNext()).ServeHTTP(rec, loginReq)
	cookie := sessionCookie(t, rec)
	if cookie.Domain != "example.com" || !cookie.Secure {
		t.Errorf("shared cookie domain=%q secure=%t", cookie.Domain, cookie.Secure)
	}

	auth.now = func() time.Time { return cookie.Expires.Add(-authSessionRenewAfter + time.Hour) }
	req := httptest.NewRequest(http.MethodGet, "https://vpn-personal.example.com/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	auth.wrap(authTestNext()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("old-session status = %d, want 204", rec.Code)
	}
	renewed := sessionCookie(t, rec)
	if !renewed.Expires.After(cookie.Expires) {
		t.Errorf("renewed expiry = %v, want after %v", renewed.Expires, cookie.Expires)
	}
}

func TestPasswordAuthLogoutClearsSession(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	handler := fixedPasswordAuth("secret", "", now).wrap(authTestNext())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("logout = status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := sessionCookie(t, rec)
	if cookie.MaxAge != -1 || cookie.Value != "" {
		t.Errorf("clearing cookie = MaxAge %d value %q", cookie.MaxAge, cookie.Value)
	}
}

func TestSafeNext(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/reports?since=24h#/detail", "/reports?since=24h#/detail"},
		{"https://evil.example", "/"},
		{"//evil.example", "/"},
		{`/\evil`, "/"},
		{"clients", "/"},
	} {
		if got := safeNext(tc.in); got != tc.want {
			t.Errorf("safeNext(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
