// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func ValidateCSRFToken(submitted, stored string) bool {
	if len(submitted) == 0 || len(stored) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(stored)) == 1
}

func SignCSRFToken(token string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(token)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func VerifyCSRFCookie(cookieValue string, secret []byte) (string, error) {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid csrf cookie format")
	}

	tokenBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid csrf cookie encoding")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid csrf signature encoding")
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(tokenBytes)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return "", errors.New("invalid csrf signature")
	}

	return string(tokenBytes), nil
}
