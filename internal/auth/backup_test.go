// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"strings"
	"testing"
)

func TestGenerateBackupCodes(t *testing.T) {
	plaintexts, hashes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	if len(plaintexts) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(plaintexts))
	}
	if len(hashes) != 10 {
		t.Fatalf("expected 10 hashes, got %d", len(hashes))
	}

	for i, code := range plaintexts {
		if len(code) != 9 { // xxxx-xxxx
			t.Errorf("code %d: expected length 9, got %d (%s)", i, len(code), code)
		}
		if code[4] != '-' {
			t.Errorf("code %d: expected dash at position 4, got %c", i, code[4])
		}
	}

	// All codes should be unique
	seen := make(map[string]bool)
	for _, code := range plaintexts {
		if seen[code] {
			t.Errorf("duplicate code: %s", code)
		}
		seen[code] = true
	}
}

func TestVerifyBackupCode_Match(t *testing.T) {
	plaintexts, hashes, err := GenerateBackupCodes(3)
	if err != nil {
		t.Fatal(err)
	}

	idx := VerifyBackupCode(plaintexts[1], hashes)
	if idx != 1 {
		t.Errorf("expected match at index 1, got %d", idx)
	}
}

func TestVerifyBackupCode_NoMatch(t *testing.T) {
	_, hashes, err := GenerateBackupCodes(3)
	if err != nil {
		t.Fatal(err)
	}

	idx := VerifyBackupCode("xxxx-xxxx", hashes)
	if idx != -1 {
		t.Errorf("expected no match (-1), got %d", idx)
	}
}

func TestVerifyBackupCode_UsedCode(t *testing.T) {
	plaintexts, hashes, err := GenerateBackupCodes(3)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate using code 1 by clearing its hash
	idx := VerifyBackupCode(plaintexts[1], hashes)
	if idx == -1 {
		t.Fatal("code should match before invalidation")
	}
	hashes[idx] = ""

	// Same code should no longer match
	idx = VerifyBackupCode(plaintexts[1], hashes)
	if idx != -1 {
		t.Error("used code should not match after invalidation")
	}
}

func TestVerifyBackupCode_CaseInsensitive(t *testing.T) {
	plaintexts, hashes, err := GenerateBackupCodes(1)
	if err != nil {
		t.Fatal(err)
	}

	upper := strings.ToUpper(plaintexts[0])
	idx := VerifyBackupCode(upper, hashes)
	if idx == -1 {
		t.Error("verification should be case-insensitive")
	}
}

func TestVerifyBackupCode_WithoutDash(t *testing.T) {
	plaintexts, hashes, err := GenerateBackupCodes(1)
	if err != nil {
		t.Fatal(err)
	}

	noDash := strings.ReplaceAll(plaintexts[0], "-", "")
	idx := VerifyBackupCode(noDash, hashes)
	if idx == -1 {
		t.Error("verification should work without dash")
	}
}

func TestBackupCodeFormat(t *testing.T) {
	plaintexts, _, err := GenerateBackupCodes(100)
	if err != nil {
		t.Fatal(err)
	}

	for _, code := range plaintexts {
		raw := strings.ReplaceAll(code, "-", "")
		for _, c := range raw {
			if !strings.ContainsRune(safeAlphabet, c) {
				t.Errorf("code %s contains ambiguous character: %c", code, c)
			}
		}
	}
}
