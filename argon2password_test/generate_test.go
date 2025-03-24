package argon2password_test

import (
	"regexp"
	"testing"

	argon2password "gopkg.hlmpn.dev/pkg/argon2password"
)

// TestGeneratePassword tests the public GeneratePassword function
func TestGeneratePassword(t *testing.T) {
	// Test multiple password generations to ensure they are random and meet requirements
	for i := 0; i < 10; i++ { //nolint:intrange
		password, err := argon2password.GeneratePassword()

		// Check success
		if err != nil {
			t.Errorf("GeneratePassword() error = %v", err)
		}

		// Validate password length (default length is 32-37 from constants.go)
		if len(password) < 32 || len(password) > 40 {
			t.Errorf("GeneratePassword() generated password with invalid length: got %d, want 32-40", len(password))
		}

		// Validate character set - password should only contain characters from the defined charset
		validCharsetRegex := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{}|;:,.<>?/~]+$`)
		if !validCharsetRegex.MatchString(password) {
			t.Errorf("GeneratePassword() generated password with invalid characters: %s", password)
		}
	}
}

// TestGeneratePasswordWithLength tests the public GeneratePasswordWithLength function
func TestGeneratePasswordWithLength(t *testing.T) {
	tests := []struct {
		name       string
		length     int
		wantErr    bool
		errMessage string
	}{
		{
			name:    "Valid short length",
			length:  8,
			wantErr: false,
		},
		{
			name:    "Valid medium length",
			length:  32,
			wantErr: false,
		},
		{
			name:    "Valid large length",
			length:  1000,
			wantErr: false,
		},
		{
			name:       "Zero length",
			length:     0,
			wantErr:    true,
			errMessage: "argon2Password: Length cannot be zero",
		},
		{
			name:       "Negative length",
			length:     -10,
			wantErr:    true,
			errMessage: "argon2Password: Length cannot be negative",
		},
	}

	validCharsetRegex := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{}|;:,.<>?/~]+$`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := argon2password.GeneratePasswordWithLength(tt.length)

			// Check error expectations
			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePasswordWithLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// For expected errors, verify the error message
			if tt.wantErr && err != nil && err.Error() != tt.errMessage {
				t.Errorf("GeneratePasswordWithLength() error message = %v, want %v", err.Error(), tt.errMessage)
				return
			}

			// For successful cases, validate the password
			if !tt.wantErr {
				// Check length
				if len(password) != tt.length {
					t.Errorf("GeneratePasswordWithLength() password length = %d, want %d", len(password), tt.length)
				}

				// Check character set
				if !validCharsetRegex.MatchString(password) {
					t.Errorf("GeneratePasswordWithLength() generated password with invalid characters: %s", password)
				}
			}
		})
	}
}

// TestGeneratePasswordWithCharset tests the public GeneratePasswordWithCharset function
func TestGeneratePasswordWithCharset(t *testing.T) {
	tests := []struct {
		name       string
		charset    string
		length     int
		wantErr    bool
		errMessage string
	}{
		{
			name:    "Valid charset and length",
			charset: "abc123",
			length:  10,
			wantErr: false,
		},
		{
			name:    "Numeric charset",
			charset: "0123456789",
			length:  8,
			wantErr: false,
		},
		{
			name:    "Special chars only",
			charset: "!@#$%^&*()_+-=",
			length:  15,
			wantErr: false,
		},
		{
			name:       "Empty charset",
			charset:    "",
			length:     10,
			wantErr:    true,
			errMessage: "argon2Password: Invalid charset",
		},
		{
			name:       "Zero length",
			charset:    "abc123",
			length:     0,
			wantErr:    true,
			errMessage: "argon2Password: Length cannot be zero",
		},
		{
			name:       "Negative length",
			charset:    "abc123",
			length:     -5,
			wantErr:    true,
			errMessage: "argon2Password: Length cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := argon2password.GeneratePasswordWithCharset(tt.charset, tt.length)

			// Check error expectations
			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePasswordWithCharset() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// For expected errors, verify the error message
			if tt.wantErr && err != nil && err.Error() != tt.errMessage {
				t.Errorf("GeneratePasswordWithCharset() error message = %v, want %v", err.Error(), tt.errMessage)
				return
			}

			// For successful cases, validate the password
			if !tt.wantErr {
				// Check length
				if len(password) != tt.length {
					t.Errorf("GeneratePasswordWithCharset() password length = %d, want %d", len(password), tt.length)
				}

				// Check that each character is from the charset
				for _, char := range password {
					if !containsRune(tt.charset, char) {
						t.Errorf("GeneratePasswordWithCharset() generated character '%c' not in charset '%s'", char, tt.charset)
					}
				}
			}
		})
	}
}

// TestGenerateAndHashPassword tests the public GenerateAndHashPassword function
func TestGenerateAndHashPassword(t *testing.T) {
	// Run multiple times to ensure randomness works properly
	for i := 0; i < 5; i++ { //nolint:intrange
		password, hash, err := argon2password.GenerateAndHashPassword()

		// Check for errors
		if err != nil {
			t.Errorf("GenerateAndHashPassword() error = %v", err)
			return
		}

		// Check password is not empty and has proper length
		if password == "" {
			t.Errorf("GenerateAndHashPassword() returned empty password")
		}
		if len(password) < 32 || len(password) > 40 {
			t.Errorf("GenerateAndHashPassword() password length = %d, want between 32-40", len(password))
		}

		// Check hash format
		if hash == "" {
			t.Errorf("GenerateAndHashPassword() returned empty hash")
		}

		// Verify hash is valid by comparing the password against it
		match, err := argon2password.ComparePW(password, hash)
		if err != nil {
			t.Errorf("ComparePW() error = %v", err)
		}
		if !match {
			t.Errorf("GenerateAndHashPassword() produced password and hash that don't match")
		}
	}
}

// Helper function to check if a rune is in a string
func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func Unsafe(number int64) uint8 {
	return uint8(number)

}
