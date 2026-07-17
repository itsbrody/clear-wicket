// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	CookieDomain string
	CookieSecret []byte
	SessionTTL   time.Duration
	AuthHost     string
	DataDir      string
	TOTPSkew     uint
	TOTPSecret   string
	ListenAddr   string
}

func Load() (*Config, error) {
	cfg := &Config{
		SessionTTL: 24 * time.Hour,
		DataDir:    "./data",
		TOTPSkew:   1,
		ListenAddr: ":4181",
	}

	cfg.CookieDomain = os.Getenv("COOKIE_DOMAIN")
	if cfg.CookieDomain == "" {
		return nil, errors.New("COOKIE_DOMAIN is required")
	}

	cfg.AuthHost = os.Getenv("AUTH_HOST")
	if cfg.AuthHost == "" {
		return nil, errors.New("AUTH_HOST is required")
	}

	if v := os.Getenv("SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid SESSION_TTL: %w", err)
		}
		cfg.SessionTTL = d
	}

	if v := os.Getenv("DATA_DIR"); v != "" {
		cfg.DataDir = v
	}

	if v := os.Getenv("TOTP_SKEW"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid TOTP_SKEW: %w", err)
		}
		cfg.TOTPSkew = uint(n)
	}

	cfg.TOTPSecret = os.Getenv("TOTP_SECRET")
	cfg.ListenAddr = envOrDefault("LISTEN_ADDR", cfg.ListenAddr)

	return cfg, nil
}

func (c *Config) EnsureCookieSecret() error {
	if v := os.Getenv("COOKIE_SECRET"); v != "" {
		b, err := hex.DecodeString(v)
		if err != nil {
			return fmt.Errorf("invalid COOKIE_SECRET (must be hex): %w", err)
		}
		c.CookieSecret = b
		return nil
	}

	path := filepath.Join(c.DataDir, "cookie_secret")
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		c.CookieSecret = data
		return nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generating cookie secret: %w", err)
	}

	if err := os.MkdirAll(c.DataDir, 0700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}
	if err := os.WriteFile(path, secret, 0600); err != nil {
		return fmt.Errorf("persisting cookie secret: %w", err)
	}

	c.CookieSecret = secret
	return nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
