// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	CookieDomain   string
	CookieSecret   []byte
	SessionTTL     time.Duration
	AuthHost       string
	DataDir        string
	TOTPSkew       uint
	TOTPSecret     string
	ListenAddr     string
	InsecureCookie bool
	// FrameAncestors lists the origins allowed to embed Clear Wicket in a
	// frame. Empty means no embedding (X-Frame-Options: DENY).
	FrameAncestors []string
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
	cfg.InsecureCookie = os.Getenv("INSECURE_COOKIE") == "true"

	if v, ok := os.LookupEnv("FRAME_ANCESTORS"); ok && v != "" {
		origins, err := parseFrameAncestors(v)
		if err != nil {
			return nil, fmt.Errorf("invalid FRAME_ANCESTORS: %w", err)
		}
		cfg.FrameAncestors = origins
	}

	return cfg, nil
}

// parseFrameAncestors accepts a whitespace-separated list of 'self' and
// https://host[:port] origins. Wildcards, other schemes, paths and anything
// else are rejected so that a typo cannot silently open embedding wide.
func parseFrameAncestors(v string) ([]string, error) {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return nil, errors.New("no origins given")
	}
	for _, f := range fields {
		if f == "'self'" {
			continue
		}
		if err := validateOrigin(f); err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
	}
	return fields, nil
}

func validateOrigin(o string) error {
	if !strings.HasPrefix(o, "https://") {
		return errors.New("must be 'self' or an https://host[:port] origin")
	}
	u, err := url.Parse(o)
	if err != nil {
		return err
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(o, "?") || strings.HasSuffix(o, "#") {
		return errors.New("must not contain credentials, path, query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("host is missing")
	}
	for _, c := range host {
		ok := c == '.' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return errors.New("host contains invalid characters (wildcards are not supported)")
		}
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return errors.New("invalid port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("invalid port")
	}
	return nil
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
