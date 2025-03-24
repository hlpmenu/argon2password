package argon2password_test

import (
	"testing"

	argon2password "gopkg.hlmpn.dev/pkg/argon2password"
)

// TestGeneratedPasswordVerification tests the full flow from password generation
// to hashing to verification
func TestGeneratedPasswordVerification(t *testing.T) {
	// Test different types of password generation
	tests := []struct {
		name       string
		genFunc    func() (string, error)
		shouldPass bool
	}{
		{
			name: "GeneratePassword standard",
			genFunc: func() (string, error) { //nolint:gocritic // Allow this lambda function
				return argon2password.GeneratePassword()
			},
			shouldPass: true,
		},
		{
			name: "GeneratePasswordWithLength short",
			genFunc: func() (string, error) {
				return argon2password.GeneratePasswordWithLength(8)
			},
			shouldPass: true,
		},
		{
			name: "GeneratePasswordWithLength long",
			genFunc: func() (string, error) {
				return argon2password.GeneratePasswordWithLength(100)
			},
			shouldPass: true,
		},
		{
			name: "GeneratePasswordWithCharset alphanumeric",
			genFunc: func() (string, error) {
				return argon2password.GeneratePasswordWithCharset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 20)
			},
			shouldPass: true,
		},
		{
			name: "GeneratePasswordWithCharset numeric only",
			genFunc: func() (string, error) {
				return argon2password.GeneratePasswordWithCharset("0123456789", 15)
			},
			shouldPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate password
			password, err := tt.genFunc()
			if err != nil {
				if tt.shouldPass {
					t.Errorf("Failed to generate password: %v", err)
				}
				return
			}

			// Hash the password
			hash, err := argon2password.HashPW(password)
			if err != nil {
				if tt.shouldPass {
					t.Errorf("Failed to hash password: %v", err)
				}
				return
			}

			// Verify the password
			match, err := argon2password.ComparePW(password, hash)
			if err != nil {
				if tt.shouldPass {
					t.Errorf("Failed to verify password: %v", err)
				}
				return
			}

			if !match {
				t.Errorf("Password verification failed for generated password")
			}

			// Verify a wrong password doesn't match
			wrongMatch, err := argon2password.ComparePW(password+"wrong", hash)
			if err != nil {
				// We don't expect an error for wrong passwords
				t.Errorf("Error verifying wrong password: %v", err)
			}
			if wrongMatch {
				t.Errorf("Wrong password should not verify successfully")
			}
		})
	}
}

// TestMultipleHashesSamePassword tests that the same password hashed multiple times
// produces different hashes but all verify correctly
func TestMultipleHashesSamePassword(t *testing.T) {
	// Generate a test password
	password, err := argon2password.GeneratePassword()
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}

	// Generate multiple hashes for the same password
	const hashCount = 5
	hashes := make([]string, hashCount)

	for i := 0; i < hashCount; i++ { //nolint:intrange
		hash, err := argon2password.HashPW(password)
		if err != nil {
			t.Fatalf("Failed to hash password (iteration %d): %v", i, err)
		}
		hashes[i] = hash
	}

	// Verify all hashes are different (due to different salts)
	for i := 0; i < hashCount; i++ {
		for j := i + 1; j < hashCount; j++ {
			if hashes[i] == hashes[j] {
				t.Errorf("Hash collision between iterations %d and %d", i, j)
			}
		}
	}

	// Verify all hashes work with the original password
	for i, hash := range hashes {
		match, err := argon2password.ComparePW(password, hash)
		if err != nil {
			t.Errorf("Failed to verify password with hash from iteration %d: %v", i, err)
		}
		if !match {
			t.Errorf("Password verification failed for hash from iteration %d", i)
		}
	}
}
