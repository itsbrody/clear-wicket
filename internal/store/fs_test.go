// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package store

import (
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *FSStore {
	t.Helper()
	s, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	return s
}

func TestUserCRUD(t *testing.T) {
	s := newTestStore(t)

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected 0 users, got %d", len(users))
	}

	u := &User{
		ID:         "user-1",
		TOTPSecret: "JBSWY3DPEHPK3PXP",
		CreatedAt:  time.Now(),
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUser("user-1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected secret JBSWY3DPEHPK3PXP, got %s", got.TOTPSecret)
	}

	got.BackupCodes = []string{"hash1", "hash2"}
	if err := s.UpdateUser(got); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	updated, err := s.GetUser("user-1")
	if err != nil {
		t.Fatalf("GetUser after update: %v", err)
	}
	if len(updated.BackupCodes) != 2 {
		t.Errorf("expected 2 backup codes, got %d", len(updated.BackupCodes))
	}

	if _, err := s.GetUser("nonexistent"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSessionCRUD(t *testing.T) {
	s := newTestStore(t)

	sess := &Session{
		ID:        "sess-1",
		UserID:    "user-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IP:        "192.168.1.1",
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := s.GetSession("sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", got.UserID)
	}

	if err := s.DeleteSession("sess-1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.GetSession("sess-1"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := newTestStore(t)

	expired := &Session{
		ID:        "expired",
		UserID:    "user-1",
		CreatedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour),
	}
	valid := &Session{
		ID:        "valid",
		UserID:    "user-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	s.CreateSession(expired)
	s.CreateSession(valid)

	if err := s.DeleteExpiredSessions(); err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}

	if _, err := s.GetSession("expired"); err != ErrNotFound {
		t.Error("expired session should be deleted")
	}
	if _, err := s.GetSession("valid"); err != nil {
		t.Error("valid session should still exist")
	}
}

func TestRateEntryCRUD(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.GetRateEntry("1.2.3.4"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	entry := &RateEntry{
		IP:       "1.2.3.4",
		Failures: 3,
		LastFail: time.Now(),
	}
	if err := s.SetRateEntry(entry); err != nil {
		t.Fatalf("SetRateEntry: %v", err)
	}

	got, err := s.GetRateEntry("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRateEntry: %v", err)
	}
	if got.Failures != 3 {
		t.Errorf("expected 3 failures, got %d", got.Failures)
	}

	// Update existing
	entry.Failures = 5
	if err := s.SetRateEntry(entry); err != nil {
		t.Fatalf("SetRateEntry update: %v", err)
	}
	got, _ = s.GetRateEntry("1.2.3.4")
	if got.Failures != 5 {
		t.Errorf("expected 5 failures after update, got %d", got.Failures)
	}

	if err := s.ClearRateEntry("1.2.3.4"); err != nil {
		t.Fatalf("ClearRateEntry: %v", err)
	}
	if _, err := s.GetRateEntry("1.2.3.4"); err != ErrNotFound {
		t.Error("expected ErrNotFound after clear")
	}
}

func TestUpdateRateEntry_Atomic(t *testing.T) {
	s := newTestStore(t)
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s.UpdateRateEntry("1.2.3.4", func(e *RateEntry) *RateEntry {
				e.Failures++
				return e
			})
		}()
	}
	wg.Wait()

	got, err := s.GetRateEntry("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRateEntry: %v", err)
	}
	if got.Failures != goroutines {
		t.Errorf("expected %d failures, got %d (lost updates)", goroutines, got.Failures)
	}
}

func TestUpdateRateEntry_CreatesIfMissing(t *testing.T) {
	s := newTestStore(t)

	err := s.UpdateRateEntry("10.0.0.1", func(e *RateEntry) *RateEntry {
		e.Failures = 1
		e.LastFail = time.Now()
		return e
	})
	if err != nil {
		t.Fatalf("UpdateRateEntry: %v", err)
	}

	got, err := s.GetRateEntry("10.0.0.1")
	if err != nil {
		t.Fatalf("GetRateEntry: %v", err)
	}
	if got.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", got.Failures)
	}
}

func TestModifyUser_Atomic(t *testing.T) {
	s := newTestStore(t)

	u := &User{
		ID:          "user-1",
		TOTPSecret:  "JBSWY3DPEHPK3PXP",
		BackupCodes: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
		CreatedAt:   time.Now(),
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const goroutines = 10
	results := make(chan int, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			consumed := 0
			err := s.ModifyUser("user-1", func(user *User) error {
				for j, code := range user.BackupCodes {
					if code != "" {
						user.BackupCodes[j] = ""
						consumed = 1
						return nil
					}
				}
				return ErrNotFound
			})
			if err == nil {
				results <- consumed
			}
		}()
	}
	wg.Wait()
	close(results)

	totalConsumed := 0
	for c := range results {
		totalConsumed += c
	}

	got, _ := s.GetUser("user-1")
	remainingCodes := 0
	for _, code := range got.BackupCodes {
		if code != "" {
			remainingCodes++
		}
	}

	if totalConsumed+remainingCodes != 10 {
		t.Errorf("consumed (%d) + remaining (%d) should equal 10 (lost or duplicated updates)", totalConsumed, remainingCodes)
	}
}

func TestModifyUser_NotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.ModifyUser("nonexistent", func(u *User) error {
		return nil
	})
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSetupComplete(t *testing.T) {
	s := newTestStore(t)

	done, err := s.IsSetupComplete()
	if err != nil {
		t.Fatalf("IsSetupComplete: %v", err)
	}
	if done {
		t.Error("expected setup not complete initially")
	}

	if err := s.MarkSetupComplete(); err != nil {
		t.Fatalf("MarkSetupComplete: %v", err)
	}

	done, err = s.IsSetupComplete()
	if err != nil {
		t.Fatalf("IsSetupComplete: %v", err)
	}
	if !done {
		t.Error("expected setup complete after marking")
	}
}
