// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"testing"
	"time"
)

func TestSessionCookie_RoundTrip(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-xxxxx!")
	sessionID, err := GenerateSessionID()
	if err != nil {
		t.Fatal(err)
	}

	cookie := NewSessionCookie(sessionID, secret, ".example.com", 24*time.Hour)

	parsed, err := ParseSessionCookie(cookie.Value, secret)
	if err != nil {
		t.Fatalf("ParseSessionCookie: %v", err)
	}
	if parsed != sessionID {
		t.Errorf("expected %s, got %s", sessionID, parsed)
	}
}

func TestSessionCookie_TamperedSignature(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-xxxxx!")
	sessionID, _ := GenerateSessionID()

	cookie := NewSessionCookie(sessionID, secret, ".example.com", 24*time.Hour)

	// Tamper with last character
	tampered := cookie.Value[:len(cookie.Value)-1] + "X"
	if _, err := ParseSessionCookie(tampered, secret); err == nil {
		t.Error("tampered cookie should be rejected")
	}
}

func TestSessionCookie_WrongSecret(t *testing.T) {
	secret1 := []byte("secret-one-32-bytes-long-xxxxxx!")
	secret2 := []byte("secret-two-32-bytes-long-xxxxxx!")
	sessionID, _ := GenerateSessionID()

	cookie := NewSessionCookie(sessionID, secret1, ".example.com", 24*time.Hour)

	if _, err := ParseSessionCookie(cookie.Value, secret2); err == nil {
		t.Error("cookie signed with different secret should be rejected")
	}
}

func TestSessionCookie_InvalidFormat(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-xxxxx!")

	if _, err := ParseSessionCookie("nodotshere", secret); err == nil {
		t.Error("missing dot should be rejected")
	}
	if _, err := ParseSessionCookie("", secret); err == nil {
		t.Error("empty string should be rejected")
	}
}

func TestSessionCookie_Properties(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-xxxxx!")
	sessionID, _ := GenerateSessionID()

	cookie := NewSessionCookie(sessionID, secret, ".example.com", 24*time.Hour)

	if !cookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("cookie should be Secure")
	}
	if cookie.SameSite != 2 { // http.SameSiteLaxMode
		t.Errorf("expected SameSite=Lax, got %d", cookie.SameSite)
	}
	if cookie.Domain != ".example.com" {
		t.Errorf("expected domain .example.com, got %s", cookie.Domain)
	}
}

func TestGenerateSessionID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if ids[id] {
			t.Fatalf("duplicate session ID: %s", id)
		}
		ids[id] = true
	}
}

func TestClearSessionCookie(t *testing.T) {
	cookie := ClearSessionCookie(".example.com")
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", cookie.MaxAge)
	}
	if cookie.Value != "" {
		t.Error("cleared cookie should have empty value")
	}
}
