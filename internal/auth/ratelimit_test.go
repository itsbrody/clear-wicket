// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"testing"
	"time"

	"github.com/itsbrody/clear-wicket/internal/store"
)

func TestCheckRateLimit_NilEntry(t *testing.T) {
	result := CheckRateLimit(nil, false)
	if !result.Allowed {
		t.Error("nil entry should be allowed")
	}
}

func TestCheckRateLimit_BelowThreshold(t *testing.T) {
	entry := &store.RateEntry{Failures: 4}
	result := CheckRateLimit(entry, false)
	if !result.Allowed {
		t.Error("below TOTP threshold should be allowed")
	}
}

func TestCheckRateLimit_TOTPThreshold(t *testing.T) {
	entry := &store.RateEntry{
		Failures:    5,
		LockedUntil: time.Now().Add(10 * time.Second),
	}
	result := CheckRateLimit(entry, false)
	if result.Allowed {
		t.Error("at TOTP threshold with active lock should be blocked")
	}
	if result.RetryAfter <= 0 {
		t.Error("RetryAfter should be positive")
	}
}

func TestCheckRateLimit_BackupCodeLowerThreshold(t *testing.T) {
	entry := &store.RateEntry{
		Failures:    3,
		LockedUntil: time.Now().Add(10 * time.Second),
	}
	result := CheckRateLimit(entry, true)
	if result.Allowed {
		t.Error("at backup code threshold with active lock should be blocked")
	}
}

func TestCheckRateLimit_ExpiredLock(t *testing.T) {
	entry := &store.RateEntry{
		Failures:    10,
		LockedUntil: time.Now().Add(-1 * time.Second),
	}
	result := CheckRateLimit(entry, false)
	if !result.Allowed {
		t.Error("expired lock should allow retry")
	}
}

func TestRecordFailure_ExponentialBackoff(t *testing.T) {
	entry := &store.RateEntry{IP: "1.2.3.4"}

	// Build up to threshold
	for i := 0; i < 5; i++ {
		entry = RecordFailure(entry, false)
	}

	if entry.Failures != 5 {
		t.Fatalf("expected 5 failures, got %d", entry.Failures)
	}
	if entry.LockedUntil.IsZero() {
		t.Fatal("expected lock after threshold")
	}

	// 6th failure should increase backoff
	firstLock := entry.LockedUntil
	entry = RecordFailure(entry, false)
	if !entry.LockedUntil.After(firstLock) {
		t.Error("backoff should increase with more failures")
	}
}

func TestRecordFailure_BackupCodeStricterBackoff(t *testing.T) {
	totpEntry := &store.RateEntry{IP: "1.2.3.4"}
	backupEntry := &store.RateEntry{IP: "1.2.3.4"}

	// 3 failures on both
	for i := 0; i < 3; i++ {
		totpEntry = RecordFailure(totpEntry, false)
		backupEntry = RecordFailure(backupEntry, true)
	}

	// TOTP should still be allowed (threshold is 5)
	totpResult := CheckRateLimit(totpEntry, false)
	if !totpResult.Allowed {
		t.Error("TOTP should still be allowed at 3 failures")
	}

	// Backup code should be locked (threshold is 3)
	backupResult := CheckRateLimit(backupEntry, true)
	if backupResult.Allowed {
		t.Error("backup code should be locked at 3 failures")
	}
}

func TestResetRateLimit(t *testing.T) {
	entry := &store.RateEntry{
		IP:          "1.2.3.4",
		Failures:    10,
		LockedUntil: time.Now().Add(time.Hour),
	}
	entry = ResetRateLimit(entry)
	if entry.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", entry.Failures)
	}
	if !entry.LockedUntil.IsZero() {
		t.Error("lock should be cleared")
	}
}
