package argon2password

import (
	cryptrand "crypto/rand"
	"fmt"
	"math/big"
)

// generatePasswordByLength creates a cryptographically secure random password.
// It generates each character's index using crypto/rand to ensure uniform randomness.
func generateRandomPassword(length int, charset string) (string, error) {
	password := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))
	for i := 0; i < length; i++ {
		index, err := cryptrand.Int(cryptrand.Reader, charsetLength)
		if err != nil {
			return "", fmt.Errorf("argon2Password: failed to generate random index: %w", err)
		}
		password[i] = charset[index.Int64()]
	}
	return string(password), nil

}

// generatePasswordByLength creates a cryptographically secure random password of the given length.
func generatePasswordByLength(length int) (string, error) {
	return generateRandomPassword(length, passwordGenerationCharset)
}

// generateWithDefaultLength creates a cryptographically secure random password of the default length.
func generateWithDefaultLength() (string, error) {
	return generateRandomPassword(generatePasswordDefaultLength, passwordGenerationCharset)
}

// generateWithCharset creates a cryptographically secure random password using the given charset.
func generateWithCharset(charset string, length int) (string, error) {
	return generateRandomPassword(length, charset)
}

func generateWithRandomLength() (string, error) {
	extra, err := RandomNumN(5)
	if err != nil {
		return "", fmt.Errorf("argon2Password: failed to generate random extra length: %w", err)
	}
	length := generatePasswordDefaultLength + extra
	pw, err := generatePasswordByLength(length)
	if err != nil {
		return "", fmt.Errorf("argon2Password: failed to generate password: %w", err)
	}
	return pw, nil
}

func Nolint() {
	_ = generateWithDefaultLength
	_ = generateWithCharset
	_ = generateRandomPassword

}
