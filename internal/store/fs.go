// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")

type FSStore struct {
	dir string
	mu  sync.RWMutex
}

func NewFSStore(dir string) (*FSStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &FSStore{dir: dir}, nil
}

func (s *FSStore) ListUsers() ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listUsersLocked()
}

func (s *FSStore) GetUser(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users, err := s.listUsersLocked()
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].ID == id {
			return &users[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *FSStore) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var users []User
	_ = s.readJSON("users.json", &users)
	users = append(users, *u)
	return s.writeJSON("users.json", users)
}

func (s *FSStore) UpdateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var users []User
	if err := s.readJSON("users.json", &users); err != nil {
		return err
	}
	for i := range users {
		if users[i].ID == u.ID {
			users[i] = *u
			return s.writeJSON("users.json", users)
		}
	}
	return ErrNotFound
}

func (s *FSStore) CreateSession(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions []Session
	_ = s.readJSON("sessions.json", &sessions)
	sessions = append(sessions, *sess)
	return s.writeJSON("sessions.json", sessions)
}

func (s *FSStore) GetSession(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var sessions []Session
	if err := s.readJSON("sessions.json", &sessions); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	for i := range sessions {
		if sessions[i].ID == id {
			return &sessions[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *FSStore) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions []Session
	if err := s.readJSON("sessions.json", &sessions); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	filtered := make([]Session, 0, len(sessions))
	for _, sess := range sessions {
		if sess.ID != id {
			filtered = append(filtered, sess)
		}
	}
	return s.writeJSON("sessions.json", filtered)
}

func (s *FSStore) DeleteExpiredSessions() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions []Session
	if err := s.readJSON("sessions.json", &sessions); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	now := time.Now()
	filtered := make([]Session, 0, len(sessions))
	for _, sess := range sessions {
		if sess.ExpiresAt.After(now) {
			filtered = append(filtered, sess)
		}
	}
	return s.writeJSON("sessions.json", filtered)
}

func (s *FSStore) GetRateEntry(ip string) (*RateEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var entries []RateEntry
	if err := s.readJSON("ratelimit.json", &entries); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	for i := range entries {
		if entries[i].IP == ip {
			return &entries[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *FSStore) SetRateEntry(r *RateEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var entries []RateEntry
	_ = s.readJSON("ratelimit.json", &entries)
	found := false
	for i := range entries {
		if entries[i].IP == r.IP {
			entries[i] = *r
			found = true
			break
		}
	}
	if !found {
		entries = append(entries, *r)
	}
	return s.writeJSON("ratelimit.json", entries)
}

func (s *FSStore) ClearRateEntry(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var entries []RateEntry
	if err := s.readJSON("ratelimit.json", &entries); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	filtered := make([]RateEntry, 0, len(entries))
	for _, e := range entries {
		if e.IP != ip {
			filtered = append(filtered, e)
		}
	}
	return s.writeJSON("ratelimit.json", filtered)
}

func (s *FSStore) IsSetupComplete() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := os.Stat(filepath.Join(s.dir, "setup_complete"))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *FSStore) MarkSetupComplete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(filepath.Join(s.dir, "setup_complete"), []byte{}, 0600)
}

func (s *FSStore) GetPendingSecret() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(filepath.Join(s.dir, "pending_secret"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	return string(data), nil
}

func (s *FSStore) SetPendingSecret(secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(filepath.Join(s.dir, "pending_secret"), []byte(secret), 0600)
}

func (s *FSStore) ClearPendingSecret() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, "pending_secret"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FSStore) listUsersLocked() ([]User, error) {
	var users []User
	if err := s.readJSON("users.json", &users); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return users, nil
}

func (s *FSStore) readJSON(name string, v any) error {
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (s *FSStore) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, name))
}
