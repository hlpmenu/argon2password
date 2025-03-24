package argon2password

import "fmt"

// Global variables assigned runtime
// Static global consts and variables are defined in constants.go
var (
	// default parallelism based on the number of available CPUs
	argonDefaultParallelism = getArgonParallelism()
	numCPU                  int // asigned when argonDefaultParallelism is set
)

// HashPW hashes the given password using Argon2id and returns the hash along with an error if any.
// Argon2id is the OWASP-recommended algorithm for password hashing as it provides the best
// protection against both side-channel attacks and GPU-based attacks.
func HashPW(password string) (string, error) {
	hash, err := HashPWBytes([]byte(password))
	if err != nil {
		return "", fmt.Errorf("argon2Password: failed to hash password: %w", err)
	}
	return string(hash), nil
}

// Hash is an alias for HashPW
func Hash(password string) (string, error) {
	return HashPW(password)
}

func HashPWBytes(password []byte) ([]byte, error) {
	// Reject empty passwords
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	hash, err := generateHashFromInput(password)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

// ComparePW compares a given password with a stored hash.
// This function uses a constant-time comparison to prevent timing attacks.
func ComparePWBytes(password []byte, hash []byte) (bool, error) {
	if hash == nil {
		return false, ErrNilHash
	}
	return compareArgonPasswordAndHash(password, hash)
}

// ComparePW compares a given password with a stored hash.
// This function uses a constant-time comparison to prevent timing attacks.
func ComparePW(password string, hash string) (bool, error) {
	return ComparePWBytes([]byte(password), []byte(hash))
}

// Password generation

// GeneratePassword generates a cryptographically secure random password.
// Resulting password will be length between 32-40 characters.
// And can contain any of the following characters: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~
func GeneratePassword() (string, error) {
	return generateWithRandomLength()
}

// GeneratePasswordWithCharset generates a cryptographically secure random password
// using the given charset and length.
func GeneratePasswordWithCharset(charset string, length int) (string, error) {
	switch {
	case charset == "":
		return "", ErrInvalidCharset
	case length < 0:
		return "", ErrNegativeLength
	case length == 0:
		return "", ErrLengthZero
	}
	return generateWithCharset(charset, length)
}

// GeneratePasswordWithLength generates a cryptographically secure random password of the given length.
func GeneratePasswordWithLength(length int) (string, error) {
	switch {
	case length < 0:
		return "", ErrNegativeLength
	case length == 0:
		return "", ErrLengthZero
	}
	return generatePasswordByLength(length)
}

func GenerateAndHashPassword() (string, string, error) {
	password, err := GeneratePassword()
	if err != nil {
		return "", "", fmt.Errorf("argon2Password: failed to generate password: %w", err)
	}
	hash, err := HashPW(password)
	if err != nil {
		return "", "", fmt.Errorf("argon2Password: failed to hash password: %w", err)
	}
	return password, hash, nil

}

// Custom config

func HashWithConfig(password string, config *Config) (string, error) {
	switch {
	case config == nil:
		return "", ErrConfigNil
	case password == "":
		return "", ErrEmptyPassword
	}
	hash, err := generateHashFromInputCustom([]byte(password), config)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func HashWithConfigBytes(password []byte, config *Config) ([]byte, error) {
	switch {
	case config == nil:
		return nil, ErrConfigNil
	case len(password) == 0:
		return nil, ErrEmptyPassword
	}
	hash, err := generateHashFromInputCustom(password, config)
	if err != nil {
		return nil, err
	}
	return hash, nil
}
