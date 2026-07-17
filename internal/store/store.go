// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package store

import "time"

type User struct {
	ID           string   `json:"id"`
	TOTPSecret   string   `json:"totp_secret"`
	BackupCodes  []string `json:"backup_codes"`
	LastTOTPStep int64    `json:"last_totp_step"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
}

type RateEntry struct {
	IP          string    `json:"ip"`
	Failures    int       `json:"failures"`
	LastFail    time.Time `json:"last_fail"`
	LockedUntil time.Time `json:"locked_until"`
}

type Store interface {
	ListUsers() ([]User, error)
	GetUser(id string) (*User, error)
	CreateUser(u *User) error
	UpdateUser(u *User) error

	CreateSession(s *Session) error
	GetSession(id string) (*Session, error)
	DeleteSession(id string) error
	DeleteExpiredSessions() error

	GetRateEntry(ip string) (*RateEntry, error)
	SetRateEntry(r *RateEntry) error
	ClearRateEntry(ip string) error

	IsSetupComplete() (bool, error)
	MarkSetupComplete() error
}
