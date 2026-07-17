// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	BackupCodeCount  = 10
	backupCodeLen    = 8
	argon2Time       = 1
	argon2Memory     = 64 * 1024
	argon2Threads    = 4
	argon2KeyLen     = 32
	argon2SaltLen    = 16
)

// safeAlphabet excludes ambiguous characters: 0/O, 1/l/I
const safeAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

func GenerateBackupCodes(count int) (plaintexts []string, hashes []string, err error) {
	plaintexts = make([]string, count)
	hashes = make([]string, count)

	for i := 0; i < count; i++ {
		code, err := generateCode()
		if err != nil {
			return nil, nil, err
		}
		plaintexts[i] = formatCode(code)
		hash, err := hashBackupCode(code)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = hash
	}
	return plaintexts, hashes, nil
}

func VerifyBackupCode(code string, hashes []string) (matchIndex int) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(code)), "-", "")
	matchIndex = -1
	for i, h := range hashes {
		if h == "" {
			continue
		}
		if verifyHash(normalized, h) {
			matchIndex = i
		}
	}
	return matchIndex
}

func generateCode() (string, error) {
	b := make([]byte, backupCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := make([]byte, backupCodeLen)
	for i := range b {
		code[i] = safeAlphabet[int(b[i])%len(safeAlphabet)]
	}
	return string(code), nil
}

func formatCode(code string) string {
	if len(code) != backupCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

func hashBackupCode(code string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(code), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("%s$%s", hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

func verifyHash(code, hash string) bool {
	parts := strings.SplitN(hash, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	key := argon2.IDKey([]byte(code), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return subtle.ConstantTimeCompare(key, expected) == 1
}
