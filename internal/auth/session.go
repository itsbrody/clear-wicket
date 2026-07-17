// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	SessionCookieName = "clear_wicket_session"
	sessionIDBytes    = 32
)

func GenerateSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func NewSessionCookie(sessionID string, secret []byte, domain string, ttl time.Duration) *http.Cookie {
	value := signValue(sessionID, secret)
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

func ParseSessionCookie(cookieValue string, secret []byte) (string, error) {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid cookie format")
	}

	sessionID, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid cookie encoding")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid signature encoding")
	}

	expected := computeHMAC(sessionID, secret)
	if !hmac.Equal(sig, expected) {
		return "", errors.New("invalid signature")
	}

	return string(sessionID), nil
}

func ClearSessionCookie(domain string) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func signValue(sessionID string, secret []byte) string {
	id := []byte(sessionID)
	sig := computeHMAC(id, secret)
	return base64.RawURLEncoding.EncodeToString(id) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func computeHMAC(data, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil)
}
