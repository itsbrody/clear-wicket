// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func TestLoad_RequiredFields(t *testing.T) {
	if _, err := Load(); err == nil {
		t.Fatal("expected error when COOKIE_DOMAIN is missing")
	}

	setEnv(t, "COOKIE_DOMAIN", ".example.com")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when AUTH_HOST is missing")
	}
}

func TestLoad_Defaults(t *testing.T) {
	setEnv(t, "COOKIE_DOMAIN", ".example.com")
	setEnv(t, "AUTH_HOST", "auth.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.SessionTTL.Hours() != 24 {
		t.Errorf("expected 24h session TTL, got %v", cfg.SessionTTL)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("expected ./data, got %s", cfg.DataDir)
	}
	if cfg.TOTPSkew != 1 {
		t.Errorf("expected skew 1, got %d", cfg.TOTPSkew)
	}
	if cfg.ListenAddr != ":4181" {
		t.Errorf("expected :4181, got %s", cfg.ListenAddr)
	}
}

func TestLoad_CustomValues(t *testing.T) {
	setEnv(t, "COOKIE_DOMAIN", ".test.com")
	setEnv(t, "AUTH_HOST", "auth.test.com")
	setEnv(t, "SESSION_TTL", "12h")
	setEnv(t, "DATA_DIR", "/tmp/test-data")
	setEnv(t, "TOTP_SKEW", "2")
	setEnv(t, "TOTP_SECRET", "JBSWY3DPEHPK3PXP")
	setEnv(t, "LISTEN_ADDR", ":8080")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.SessionTTL.Hours() != 12 {
		t.Errorf("expected 12h, got %v", cfg.SessionTTL)
	}
	if cfg.DataDir != "/tmp/test-data" {
		t.Errorf("expected /tmp/test-data, got %s", cfg.DataDir)
	}
	if cfg.TOTPSkew != 2 {
		t.Errorf("expected skew 2, got %d", cfg.TOTPSkew)
	}
	if cfg.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected TOTP secret, got %s", cfg.TOTPSecret)
	}
}

func TestLoad_InvalidSessionTTL(t *testing.T) {
	setEnv(t, "COOKIE_DOMAIN", ".example.com")
	setEnv(t, "AUTH_HOST", "auth.example.com")
	setEnv(t, "SESSION_TTL", "notaduration")

	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid SESSION_TTL")
	}
}

func TestEnsureCookieSecret_GenerateAndPersist(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{DataDir: dir}

	if err := cfg.EnsureCookieSecret(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.CookieSecret) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(cfg.CookieSecret))
	}

	data, err := os.ReadFile(filepath.Join(dir, "cookie_secret"))
	if err != nil {
		t.Fatalf("secret file not written: %v", err)
	}
	if len(data) != 32 {
		t.Fatalf("expected 32 bytes on disk, got %d", len(data))
	}

	// Second call should read from file
	cfg2 := &Config{DataDir: dir}
	if err := cfg2.EnsureCookieSecret(); err != nil {
		t.Fatalf("unexpected error on reload: %v", err)
	}
	if string(cfg2.CookieSecret) != string(cfg.CookieSecret) {
		t.Error("secret changed on reload")
	}
}

func TestEnsureCookieSecret_FromEnv(t *testing.T) {
	setEnv(t, "COOKIE_SECRET", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	cfg := &Config{DataDir: t.TempDir()}
	if err := cfg.EnsureCookieSecret(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CookieSecret) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(cfg.CookieSecret))
	}
}
