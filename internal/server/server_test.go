// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/itsbrody/clear-wicket/internal/auth"
	"github.com/itsbrody/clear-wicket/internal/config"
	"github.com/itsbrody/clear-wicket/internal/store"
	"github.com/pquerna/otp/totp"
)

func testServer(t *testing.T) (*httptest.Server, *config.Config, *store.FSStore) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		CookieDomain: ".test.local",
		CookieSecret: []byte("test-secret-32-bytes-long-xxxxx!"),
		SessionTTL:   24 * time.Hour,
		AuthHost:     "auth.test.local",
		DataDir:      dir,
		TOTPSkew:     1,
		ListenAddr:   ":0",
	}
	srv := New(cfg, st)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, cfg, st
}

func setupComplete(t *testing.T, st *store.FSStore) *store.User {
	t.Helper()
	key, _ := auth.GenerateSecret("Test", "admin")
	_, hashes, _ := auth.GenerateBackupCodes(auth.BackupCodeCount)
	user := &store.User{
		ID:          "admin",
		TOTPSecret:  key.Secret(),
		BackupCodes: hashes,
		CreatedAt:   time.Now(),
	}
	st.CreateUser(user)
	st.MarkSetupComplete()
	return user
}

func TestHealth(t *testing.T) {
	ts, _, _ := testServer(t)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestAuth_NoSession(t *testing.T) {
	ts, _, st := testServer(t)
	setupComplete(t, st)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("expected redirect to login, got %s", loc)
	}
}

func TestAuth_JSONClient(t *testing.T) {
	ts, _, st := testServer(t)
	setupComplete(t, st)

	req, _ := http.NewRequest("GET", ts.URL+"/auth", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuth_ValidSession(t *testing.T) {
	ts, cfg, st := testServer(t)
	user := setupComplete(t, st)

	sessionID, _ := auth.GenerateSessionID()
	sess := &store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	st.CreateSession(sess)

	cookie := auth.NewSessionCookie(sessionID, cfg.CookieSecret, cfg.CookieDomain, cfg.SessionTTL, true)

	req, _ := http.NewRequest("GET", ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Remote-User") != "admin" {
		t.Errorf("expected Remote-User: admin, got %s", resp.Header.Get("Remote-User"))
	}
}

func TestLogin_RedirectsToSetup(t *testing.T) {
	ts, _, _ := testServer(t)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/setup" {
		t.Errorf("expected redirect to /setup, got %s", loc)
	}
}

func TestSetup_LockedAfterComplete(t *testing.T) {
	ts, _, st := testServer(t)
	setupComplete(t, st)

	resp, err := http.Get(ts.URL + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	ts, cfg, st := testServer(t)
	user := setupComplete(t, st)

	sessionID, _ := auth.GenerateSessionID()
	sess := &store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	st.CreateSession(sess)

	cookie := auth.NewSessionCookie(sessionID, cfg.CookieSecret, cfg.CookieDomain, cfg.SessionTTL, true)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("GET", ts.URL+"/logout", nil)
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}

	if _, err := st.GetSession(sessionID); err == nil {
		t.Error("session should be deleted after logout")
	}
}

func TestSetupFlow_ShowsQR(t *testing.T) {
	ts, _, _ := testServer(t)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(ts.URL + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "data:image/png;base64,") {
		t.Error("setup page should contain QR code")
	}
}

func TestRateLimit(t *testing.T) {
	ts, _, st := testServer(t)
	setupComplete(t, st)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	for i := 0; i < 6; i++ {
		loginResp, _ := client.Get(ts.URL + "/login")
		loginBody, _ := io.ReadAll(loginResp.Body)
		loginResp.Body.Close()

		csrfCookie := getCookieValue(loginResp.Cookies(), csrfCookieName)
		csrfToken := extractCSRFToken(string(loginBody))

		form := url.Values{
			"code":       {"000000"},
			"csrf_token": {csrfToken},
			"rd":         {"https://app.test.local/"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
		resp, _ := client.Do(req)
		resp.Body.Close()
	}

	// Next attempt should be rate limited
	loginResp, _ := client.Get(ts.URL + "/login")
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	csrfCookie := getCookieValue(loginResp.Cookies(), csrfCookieName)
	csrfToken := extractCSRFToken(string(loginBody))

	form := url.Values{
		"code":       {"000000"},
		"csrf_token": {csrfToken},
		"rd":         {"https://app.test.local/"},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
	resp, _ := client.Do(req)
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	decodedLoc, _ := url.QueryUnescape(loc)
	if !strings.Contains(decodedLoc, "retry=") {
		t.Errorf("expected rate limit with retry parameter, got redirect to: %s", decodedLoc)
	}
}

func TestRateLimit_ConcurrentFailures(t *testing.T) {
	ts, _, st := testServer(t)
	setupComplete(t, st)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	const attempts = 10
	var wg sync.WaitGroup
	wg.Add(attempts)

	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			loginResp, _ := client.Get(ts.URL + "/login")
			loginBody, _ := io.ReadAll(loginResp.Body)
			loginResp.Body.Close()

			csrfCookie := getCookieValue(loginResp.Cookies(), csrfCookieName)
			csrfToken := extractCSRFToken(string(loginBody))

			form := url.Values{
				"code":       {"000000"},
				"csrf_token": {csrfToken},
				"rd":         {"https://app.test.local/"},
			}
			req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Forwarded-For", "10.0.0.1")
			req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
			resp, _ := client.Do(req)
			resp.Body.Close()
		}()
	}
	wg.Wait()

	entry, err := st.GetRateEntry("10.0.0.1")
	if err != nil {
		t.Fatalf("GetRateEntry: %v", err)
	}
	if entry.Failures != attempts {
		t.Errorf("expected %d failures, got %d (lost updates from concurrent requests)", attempts, entry.Failures)
	}
}

func TestBackupCode_ConcurrentConsumption(t *testing.T) {
	ts, cfg, st := testServer(t)
	user := setupComplete(t, st)

	plaintexts, hashes, _ := auth.GenerateBackupCodes(5)
	user.BackupCodes = hashes
	st.UpdateUser(user)

	sessionID, _ := auth.GenerateSessionID()
	sess := &store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	st.CreateSession(sess)
	_ = cfg

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	successes := make(chan bool, 10)
	var wg sync.WaitGroup

	code := plaintexts[0]
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			loginResp, _ := client.Get(ts.URL + "/login?mode=backup")
			loginBody, _ := io.ReadAll(loginResp.Body)
			loginResp.Body.Close()

			csrfCookie := getCookieValue(loginResp.Cookies(), csrfCookieName)
			csrfToken := extractCSRFToken(string(loginBody))

			form := url.Values{
				"code":       {code},
				"mode":       {"backup"},
				"csrf_token": {csrfToken},
				"rd":         {"https://app.test.local/"},
			}
			req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Forwarded-For", "10.0.0.2")
			req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
			resp, _ := client.Do(req)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			isSuccess := resp.StatusCode == 200 && strings.Contains(string(body), "Backup")
			successes <- isSuccess
		}()
	}
	wg.Wait()
	close(successes)

	successCount := 0
	for s := range successes {
		if s {
			successCount++
		}
	}

	if successCount > 1 {
		t.Errorf("backup code was consumed %d times, expected at most 1 (race condition)", successCount)
	}
}

func TestOpenRedirectProtection(t *testing.T) {
	ts, _, st := testServer(t)
	user := setupComplete(t, st)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	loginResp, _ := client.Get(ts.URL + "/login")
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	csrfCookie := getCookieValue(loginResp.Cookies(), csrfCookieName)
	csrfToken := extractCSRFToken(string(loginBody))

	code, _ := totp.GenerateCode(user.TOTPSecret, time.Now())

	form := url.Values{
		"code":       {code},
		"csrf_token": {csrfToken},
		"rd":         {"https://evil.com/steal"},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "evil.com") {
		t.Errorf("open redirect not blocked: %s", loc)
	}
	if loc != "/status" {
		t.Errorf("expected redirect to /status, got %s", loc)
	}
}

func TestCSRF_Rejection(t *testing.T) {
	ts, _, st := testServer(t)
	setupComplete(t, st)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// POST without any CSRF token
	form := url.Values{
		"code": {"123456"},
		"rd":   {"https://app.test.local/"},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.QueryUnescape(resp.Header.Get("Location"))
	if !strings.Contains(loc, "CSRF") {
		t.Errorf("expected CSRF rejection, got redirect to: %s", loc)
	}

	// POST with wrong CSRF token (valid cookie but mismatched form token)
	loginResp, _ := client.Get(ts.URL + "/login")
	loginResp.Body.Close()
	csrfCookie := getCookieValue(loginResp.Cookies(), csrfCookieName)

	form.Set("csrf_token", "wrong-token-value")
	req, _ = http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ = url.QueryUnescape(resp.Header.Get("Location"))
	if !strings.Contains(loc, "CSRF") {
		t.Errorf("expected CSRF rejection for wrong token, got redirect to: %s", loc)
	}
}

func extractCSRFToken(html string) string {
	idx := strings.Index(html, `name="csrf_token" value="`)
	if idx == -1 {
		return ""
	}
	start := idx + len(`name="csrf_token" value="`)
	end := strings.Index(html[start:], `"`)
	if end == -1 {
		return ""
	}
	return html[start : start+end]
}

func getCookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
