package argon2password_test

import (
	"bytes"
	"strings"
	"testing"

	argon2password "gopkg.hlmpn.dev/pkg/argon2password"
)

func TestHashPW(t *testing.T) {
	tests := []struct {
		name        string
		password    []byte
		shouldError bool
	}{
		{
			name:        "Valid password",
			password:    []byte("correcthorsebatterystaple"),
			shouldError: false,
		},
		{
			name:        "Empty password",
			password:    []byte(""),
			shouldError: true,
		},
		{
			name:        "Very long password",
			password:    bytes.Repeat([]byte("a"), 1000),
			shouldError: false,
		},
		{
			name:        "Unicode password",
			password:    []byte("пароль密码パスワード"),
			shouldError: false,
		},
		{
			name:        "Password with special chars",
			password:    []byte("p@$$w0rd!#$%^&*()"),
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := argon2password.HashPWBytes(tt.password)

			// Check error expectations
			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// For valid passwords, check hash format
			if !tt.shouldError {
				if len(hash) == 0 {
					t.Errorf("Expected non-empty hash")
				}

				// Check hash starts with $argon2id$ - use string conversion to handle any whitespace
				hashStr := string(hash)
				if !strings.HasPrefix(hashStr, "$argon2id$") {
					t.Errorf("Hash doesn't have correct format, got: %s", hashStr)
				}
			}
		})
	}
}

func TestComparePW(t *testing.T) {
	// Create a hash for testing
	password := []byte("mysecretpassword")
	hash, err := argon2password.HashPWBytes(password)
	if err != nil {
		t.Fatalf("Failed to create hash for testing: %v", err)
	}

	tests := []struct {
		name        string
		password    []byte
		hash        []byte
		wantMatch   bool
		shouldError bool
	}{
		{
			name:        "Matching password",
			password:    password,
			hash:        hash,
			wantMatch:   true,
			shouldError: false,
		},
		{
			name:        "Wrong password",
			password:    []byte("wrongpassword"),
			hash:        hash,
			wantMatch:   false,
			shouldError: false,
		},
		{
			name:        "Empty password",
			password:    []byte(""),
			hash:        hash,
			wantMatch:   false,
			shouldError: true,
		},
		{
			name:        "Nil hash",
			password:    password,
			hash:        nil,
			wantMatch:   false,
			shouldError: true,
		},
		{
			name:        "Invalid hash format",
			password:    password,
			hash:        []byte("not-a-valid-hash"),
			wantMatch:   false,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := argon2password.ComparePWBytes(tt.password, tt.hash)

			// Check error expectations
			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check match expectations
			if match != tt.wantMatch {
				t.Errorf("ComparePWBytes() match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestHash_AliasForHashPW(t *testing.T) {
	// Verify Hash is an alias for HashPW
	password := []byte("testpassword")

	hash1, err1 := argon2password.HashPWBytes(password)
	if err1 != nil {
		t.Fatalf("HashPW() error = %v", err1)
	}

	// Generate a new hash with Hash
	hash2, err2 := argon2password.HashPWBytes(password)
	if err2 != nil {
		t.Fatalf("Hash() error = %v", err2)
	}

	// Verify both hashes work with ComparePWBytes
	match1, err := argon2password.ComparePWBytes(password, hash1)
	if err != nil {
		t.Fatalf("ComparePWBytes() with hash1 error = %v", err)
	}

	match2, err := argon2password.ComparePWBytes(password, hash2)
	if err != nil {
		t.Fatalf("ComparePWBytes() with hash2 error = %v", err)
	}

	if !match1 || !match2 {
		t.Errorf("Hash() and HashPW() should behave the same")
	}
}

// TestComparePWString tests the string version of ComparePW
func TestComparePWString(t *testing.T) {
	// Create a password and hash
	passwordStr := "stringpassword"
	passwordBytes := []byte(passwordStr)

	hashBytes, err := argon2password.HashPWBytes(passwordBytes)
	if err != nil {
		t.Fatalf("Failed to create hash for testing: %v", err)
	}
	hashStr := string(hashBytes)

	// Test correct password with string version
	match, err := argon2password.ComparePW(passwordStr, hashStr)
	if err != nil {
		t.Errorf("ComparePW() with correct password returned error: %v", err)
	}
	if !match {
		t.Errorf("ComparePW() with correct password should match")
	}

	// Test wrong password with string version
	wrongMatch, err := argon2password.ComparePW("wrongpassword", hashStr)
	if err != nil {
		t.Errorf("ComparePW() with wrong password returned error: %v", err)
	}
	if wrongMatch {
		t.Errorf("ComparePW() with wrong password shouldn't match")
	}

	// Verify string version produces same result as bytes version
	bytesMatch, bytesErr := argon2password.ComparePWBytes(passwordBytes, hashBytes)
	if match != bytesMatch || (err != nil) != (bytesErr != nil) {
		t.Errorf("ComparePW(string) and ComparePWBytes([]byte) should behave the same")
	}
}

// TestHashPWString tests the string version of HashPW and Hash
func TestHashPWString(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
	}{
		{
			name:        "Valid password",
			password:    "correcthorsebatterystaple",
			shouldError: false,
		},
		{
			name:        "Empty password",
			password:    "",
			shouldError: true,
		},
		{
			name:        "Very long password",
			password:    strings.Repeat("a", 1000),
			shouldError: false,
		},
		{
			name:        "Unicode password",
			password:    "пароль密码パスワード",
			shouldError: false,
		},
		{
			name:        "Password with special chars",
			password:    "p@$$w0rd!#$%^&*()",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_HashPW", func(t *testing.T) {
			hash, err := argon2password.HashPW(tt.password)

			// Check error expectations
			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// For valid passwords, check hash format
			if !tt.shouldError {
				if len(hash) == 0 {
					t.Errorf("Expected non-empty hash")
				}

				if !strings.HasPrefix(hash, "$argon2id$") {
					t.Errorf("Hash doesn't have correct format, got: %s", hash)
				}
			}
		})

		t.Run(tt.name+"_Hash", func(t *testing.T) {
			hash, err := argon2password.Hash(tt.password)

			// Check error expectations
			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// For valid passwords, check hash format
			if !tt.shouldError {
				if len(hash) == 0 {
					t.Errorf("Expected non-empty hash")
				}

				if !strings.HasPrefix(hash, "$argon2id$") {
					t.Errorf("Hash doesn't have correct format, got: %s", hash)
				}
			}
		})
	}
}

// TestHash_StringAliasForHashPW tests that Hash is truly an alias for HashPW with string inputs
func TestHash_StringAliasForHashPW(t *testing.T) {
	// Verify Hash is an alias for HashPW with string inputs
	password := "testpassword"

	hash1, err1 := argon2password.HashPW(password)
	if err1 != nil {
		t.Fatalf("HashPW() error = %v", err1)
	}

	// Hash2 should have a different value (random salt) but should verify the same password
	hash2, err2 := argon2password.Hash(password)
	if err2 != nil {
		t.Fatalf("Hash() error = %v", err2)
	}

	// Both hashes should verify the same password
	match1, err1 := argon2password.ComparePW(password, hash1)
	if err1 != nil || !match1 {
		t.Errorf("HashPW() produced invalid hash, match = %v, err = %v", match1, err1)
	}

	match2, err2 := argon2password.ComparePW(password, hash2)
	if err2 != nil || !match2 {
		t.Errorf("Hash() produced invalid hash, match = %v, err = %v", match2, err2)
	}
}
