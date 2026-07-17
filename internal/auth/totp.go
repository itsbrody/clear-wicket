// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GenerateSecret(issuer, account string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

type TOTPResult struct {
	Valid bool
	Step  int64
}

func ValidateTOTP(secret, code string, skew uint, lastStep int64) TOTPResult {
	now := time.Now()
	period := uint(30)
	currentStep := now.Unix() / int64(period)

	for i := -int(skew); i <= int(skew); i++ {
		step := currentStep + int64(i)
		if step <= lastStep {
			continue
		}
		t := time.Unix(step*int64(period)+int64(period)/2, 0)
		valid, _ := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
			Period:    period,
			Skew:     0,
			Digits:   otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if valid {
			return TOTPResult{Valid: true, Step: step}
		}
	}
	return TOTPResult{Valid: false}
}
