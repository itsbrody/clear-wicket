// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestGenerateSecret(t *testing.T) {
	key, err := GenerateSecret("TestIssuer", "user@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if key.Issuer() != "TestIssuer" {
		t.Errorf("expected issuer TestIssuer, got %s", key.Issuer())
	}
	if key.Secret() == "" {
		t.Error("secret should not be empty")
	}
}

func TestValidateTOTP_CurrentCode(t *testing.T) {
	key, err := GenerateSecret("Test", "test@test.com")
	if err != nil {
		t.Fatal(err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	result := ValidateTOTP(key.Secret(), code, 1, 0)
	if !result.Valid {
		t.Error("expected valid TOTP code")
	}
	if result.Step == 0 {
		t.Error("expected non-zero step")
	}
}

func TestValidateTOTP_ReplayProtection(t *testing.T) {
	key, err := GenerateSecret("Test", "test@test.com")
	if err != nil {
		t.Fatal(err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	result := ValidateTOTP(key.Secret(), code, 1, 0)
	if !result.Valid {
		t.Fatal("first validation should succeed")
	}

	// Same code with the accepted step should be rejected
	result2 := ValidateTOTP(key.Secret(), code, 1, result.Step)
	if result2.Valid {
		t.Error("replayed code should be rejected")
	}
}

func TestValidateTOTP_InvalidCode(t *testing.T) {
	key, err := GenerateSecret("Test", "test@test.com")
	if err != nil {
		t.Fatal(err)
	}

	result := ValidateTOTP(key.Secret(), "000000", 1, 0)
	if result.Valid {
		t.Error("invalid code should be rejected")
	}
}

func TestValidateTOTP_RFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B test vectors for SHA1
	// Secret: 12345678901234567890 (ASCII) = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" (base32)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	tests := []struct {
		time int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			ts := time.Unix(tc.time, 0)
			generated, err := totp.GenerateCodeCustom(secret, ts, totp.ValidateOpts{
				Period:    30,
				Skew:     0,
				Digits:   otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if err != nil {
				t.Fatalf("GenerateCodeCustom: %v", err)
			}
			if generated != tc.code {
				t.Errorf("time=%d: expected %s, got %s", tc.time, tc.code, generated)
			}
		})
	}
}
