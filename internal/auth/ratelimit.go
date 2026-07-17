// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"math"
	"time"

	"github.com/itsbrody/clear-wicket/internal/store"
)

const (
	totpMaxFailures      = 5
	backupMaxFailures    = 3
	baseBackoffSeconds   = 1.0
	backupBackoffMulti   = 3.0
)

type RateLimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

func CheckRateLimit(entry *store.RateEntry, isBackupCode bool) RateLimitResult {
	if entry == nil {
		return RateLimitResult{Allowed: true}
	}

	threshold := totpMaxFailures
	if isBackupCode {
		threshold = backupMaxFailures
	}

	if entry.Failures < threshold {
		return RateLimitResult{Allowed: true}
	}

	if !entry.LockedUntil.IsZero() && time.Now().Before(entry.LockedUntil) {
		return RateLimitResult{
			Allowed:    false,
			RetryAfter: time.Until(entry.LockedUntil),
		}
	}

	return RateLimitResult{Allowed: true}
}

func RecordFailure(entry *store.RateEntry, isBackupCode bool) *store.RateEntry {
	if entry == nil {
		entry = &store.RateEntry{}
	}
	entry.Failures++
	entry.LastFail = time.Now()

	threshold := totpMaxFailures
	multiplier := baseBackoffSeconds
	if isBackupCode {
		threshold = backupMaxFailures
		multiplier = backupBackoffMulti
	}

	if entry.Failures >= threshold {
		exponent := entry.Failures - threshold
		backoff := multiplier * math.Pow(2, float64(exponent))
		entry.LockedUntil = time.Now().Add(time.Duration(backoff * float64(time.Second)))
	}

	return entry
}

func ResetRateLimit(entry *store.RateEntry) *store.RateEntry {
	entry.Failures = 0
	entry.LockedUntil = time.Time{}
	return entry
}
