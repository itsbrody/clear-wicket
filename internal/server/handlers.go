// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/itsbrody/clear-wicket/internal/auth"
	"github.com/itsbrody/clear-wicket/internal/store"
	qrcode "github.com/skip2/go-qrcode"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	complete, _ := s.store.IsSetupComplete()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","setup_complete":%t}`, complete)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	sessionID, err := s.getSessionIDFromCookie(r)
	if err != nil {
		s.authFail(w, r)
		return
	}

	sess, err := s.store.GetSession(sessionID)
	if err != nil || time.Now().After(sess.ExpiresAt) {
		s.authFail(w, r)
		return
	}

	w.Header().Set("Remote-User", sess.UserID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authFail(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	rd := auth.BuildRedirectURL(proto, host, uri)

	target := fmt.Sprintf("https://%s/login?rd=%s", s.cfg.AuthHost, url.QueryEscape(rd))
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	complete, _ := s.store.IsSetupComplete()
	if !complete {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	csrfToken, csrfCookie := s.generateCSRF()
	http.SetCookie(w, csrfCookie)

	rd := r.URL.Query().Get("rd")
	backupMode := r.URL.Query().Get("mode") == "backup"

	data := map[string]any{
		"CSRFToken":  csrfToken,
		"Redirect":   rd,
		"BackupMode": backupMode,
		"Error":      r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "login.html", data)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if !s.validateCSRF(r) {
		s.loginError(w, r, "Ungültiges CSRF-Token. Bitte erneut versuchen.")
		return
	}

	ip := clientIP(r)
	code := strings.TrimSpace(r.FormValue("code"))
	rd := r.FormValue("rd")
	isBackup := r.FormValue("mode") == "backup"

	rateEntry, _ := s.store.GetRateEntry(ip)
	result := auth.CheckRateLimit(rateEntry, isBackup)
	if !result.Allowed {
		s.loginError(w, r, fmt.Sprintf("Zu viele Fehlversuche. Bitte in %d Sekunden erneut versuchen.", int(result.RetryAfter.Seconds())+1))
		return
	}

	users, err := s.store.ListUsers()
	if err != nil || len(users) == 0 {
		s.loginError(w, r, "Kein Benutzer konfiguriert.")
		return
	}
	user := users[0]

	if isBackup {
		s.handleBackupCodeLogin(w, r, &user, code, rd, ip)
		return
	}

	totpResult := auth.ValidateTOTP(user.TOTPSecret, code, s.cfg.TOTPSkew, user.LastTOTPStep)
	if !totpResult.Valid {
		s.recordLoginFailure(ip, isBackup)
		log.Printf("TOTP login failed ip=%s", ip)
		s.loginError(w, r, "Ungültiger Code.")
		return
	}

	user.LastTOTPStep = totpResult.Step
	s.store.UpdateUser(&user)
	s.store.ClearRateEntry(ip)
	log.Printf("TOTP login success ip=%s user=%s", ip, user.ID)

	s.createSessionAndRedirect(w, r, &user, rd)
}

func (s *Server) handleBackupCodeLogin(w http.ResponseWriter, r *http.Request, user *store.User, code, rd, ip string) {
	idx := auth.VerifyBackupCode(code, user.BackupCodes)
	if idx == -1 {
		s.recordLoginFailure(ip, true)
		log.Printf("Backup code login failed ip=%s", ip)
		s.loginError(w, r, "Ungültiger Backup-Code.")
		return
	}

	user.BackupCodes[idx] = ""
	s.store.UpdateUser(user)
	s.store.ClearRateEntry(ip)
	log.Printf("Backup code login success ip=%s user=%s", ip, user.ID)

	remaining := countRemainingCodes(user.BackupCodes)

	sessionID, err := auth.GenerateSessionID()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	sess := &store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.cfg.SessionTTL),
		IP:        ip,
	}
	s.store.CreateSession(sess)
	http.SetCookie(w, auth.NewSessionCookie(sessionID, s.cfg.CookieSecret, s.cfg.CookieDomain, s.cfg.SessionTTL, !s.cfg.InsecureCookie))

	if !auth.ValidateRedirectURL(rd, s.cfg.CookieDomain) {
		rd = "/"
	}

	data := map[string]any{
		"Remaining":  remaining,
		"IsLastCode": remaining == 0,
		"Redirect":   rd,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "backup_warning.html", data)
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	complete, _ := s.store.IsSetupComplete()
	if complete {
		http.NotFound(w, r)
		return
	}

	// Reuse pending secret on page refresh instead of generating a new one
	secret, err := s.store.GetPendingSecret()
	if err != nil {
		key, err := auth.GenerateSecret("Clear Wicket", "admin")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		secret = key.Secret()
		if err := s.store.SetPendingSecret(secret); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	otpauthURL := fmt.Sprintf("otpauth://totp/Clear%%20Wicket:admin?secret=%s&issuer=Clear%%20Wicket&algorithm=SHA1&digits=6&period=30", secret)
	qrPNG, err := qrcode.Encode(otpauthURL, qrcode.Medium, 200)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	csrfToken, csrfCookie := s.generateCSRF()
	http.SetCookie(w, csrfCookie)

	data := map[string]any{
		"QRCode":    base64.StdEncoding.EncodeToString(qrPNG),
		"Secret":    secret,
		"CSRFToken": csrfToken,
		"Error":     r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "setup.html", data)
}

func (s *Server) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	complete, _ := s.store.IsSetupComplete()
	if complete {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if !s.validateCSRF(r) {
		http.Redirect(w, r, "/setup?error="+url.QueryEscape("Ungültiges CSRF-Token"), http.StatusFound)
		return
	}

	secret, err := s.store.GetPendingSecret()
	if err != nil {
		http.Redirect(w, r, "/setup?error="+url.QueryEscape("Kein ausstehender Setup-Vorgang. Bitte erneut starten."), http.StatusFound)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	result := auth.ValidateTOTP(secret, code, s.cfg.TOTPSkew, 0)
	if !result.Valid {
		http.Redirect(w, r, "/setup?error="+url.QueryEscape("Ungültiger Code. Bitte erneut versuchen."), http.StatusFound)
		return
	}

	user := &store.User{
		ID:           "admin",
		TOTPSecret:   secret,
		LastTOTPStep: result.Step,
		CreatedAt:    time.Now(),
	}

	plaintexts, hashes, err := auth.GenerateBackupCodes(auth.BackupCodeCount)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	user.BackupCodes = hashes

	if err := s.store.CreateUser(user); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	csrfToken, csrfCookie := s.generateCSRF()
	http.SetCookie(w, csrfCookie)

	codesText := url.PathEscape(strings.Join(plaintexts, "\n"))
	data := map[string]any{
		"Codes":         plaintexts,
		"CodesText":     codesText,
		"CSRFToken":     csrfToken,
		"ConfirmAction": "/setup/confirm",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "setup_backup.html", data)
}

func (s *Server) handleSetupConfirmBackups(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Ungültiges CSRF-Token", http.StatusForbidden)
		return
	}

	if err := s.store.MarkSetupComplete(); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.store.ClearPendingSecret()

	log.Println("Setup completed")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleRegenerateBackupCodesPage(w http.ResponseWriter, r *http.Request) {
	sessionID, err := s.getSessionIDFromCookie(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sess, err := s.store.GetSession(sessionID)
	if err != nil || time.Now().After(sess.ExpiresAt) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = sess

	csrfToken, csrfCookie := s.generateCSRF()
	http.SetCookie(w, csrfCookie)

	data := map[string]any{
		"CSRFToken": csrfToken,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "regenerate_confirm.html", data)
}

func (s *Server) handleRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	sessionID, err := s.getSessionIDFromCookie(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sess, err := s.store.GetSession(sessionID)
	if err != nil || time.Now().After(sess.ExpiresAt) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Ungültiges CSRF-Token", http.StatusForbidden)
		return
	}

	user, err := s.store.GetUser(sess.UserID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	plaintexts, hashes, err := auth.GenerateBackupCodes(auth.BackupCodeCount)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	user.BackupCodes = hashes
	if err := s.store.UpdateUser(user); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Backup codes regenerated user=%s ip=%s", user.ID, clientIP(r))

	csrfToken, csrfCookie := s.generateCSRF()
	http.SetCookie(w, csrfCookie)

	codesText := url.PathEscape(strings.Join(plaintexts, "\n"))
	data := map[string]any{
		"Codes":         plaintexts,
		"CodesText":     codesText,
		"CSRFToken":     csrfToken,
		"ConfirmAction": "/login",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "setup_backup.html", data)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	sessionID, err := s.getSessionIDFromCookie(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sess, err := s.store.GetSession(sessionID)
	if err != nil || time.Now().After(sess.ExpiresAt) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := map[string]any{
		"UserID": sess.UserID,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "status.html", data)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := s.getSessionIDFromCookie(r)
	if err == nil {
		s.store.DeleteSession(sessionID)
	}
	http.SetCookie(w, auth.ClearSessionCookie(s.cfg.CookieDomain, !s.cfg.InsecureCookie))
	http.Redirect(w, r, "/login", http.StatusFound)
}

// --- helpers ---

func (s *Server) getSessionIDFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return "", err
	}
	return auth.ParseSessionCookie(cookie.Value, s.cfg.CookieSecret)
}

func (s *Server) createSessionAndRedirect(w http.ResponseWriter, r *http.Request, user *store.User, rd string) {
	sessionID, err := auth.GenerateSessionID()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	sess := &store.Session{
		ID:        sessionID,
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.cfg.SessionTTL),
		IP:        clientIP(r),
	}
	if err := s.store.CreateSession(sess); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, auth.NewSessionCookie(sessionID, s.cfg.CookieSecret, s.cfg.CookieDomain, s.cfg.SessionTTL, !s.cfg.InsecureCookie))

	if !auth.ValidateRedirectURL(rd, s.cfg.CookieDomain) {
		rd = "/status"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *Server) loginError(w http.ResponseWriter, r *http.Request, msg string) {
	rd := r.FormValue("rd")
	mode := r.FormValue("mode")
	target := fmt.Sprintf("/login?error=%s&rd=%s", url.QueryEscape(msg), url.QueryEscape(rd))
	if mode == "backup" {
		target += "&mode=backup"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) recordLoginFailure(ip string, isBackup bool) {
	entry, err := s.store.GetRateEntry(ip)
	if err != nil && errors.Is(err, store.ErrNotFound) {
		entry = &store.RateEntry{IP: ip}
	} else if err != nil {
		return
	}
	entry = auth.RecordFailure(entry, isBackup)
	s.store.SetRateEntry(entry)
}

const csrfCookieName = "clear_wicket_csrf"

func (s *Server) generateCSRF() (string, *http.Cookie) {
	token, _ := auth.GenerateCSRFToken()
	signed := auth.SignCSRFToken(token, s.cfg.CookieSecret)
	cookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   600,
	}
	return token, cookie
}

func (s *Server) validateCSRF(r *http.Request) bool {
	submitted := r.FormValue("csrf_token")
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	stored, err := auth.VerifyCSRFCookie(cookie.Value, s.cfg.CookieSecret)
	if err != nil {
		return false
	}
	return auth.ValidateCSRFToken(submitted, stored)
}

func countRemainingCodes(codes []string) int {
	count := 0
	for _, c := range codes {
		if c != "" {
			count++
		}
	}
	return count
}
