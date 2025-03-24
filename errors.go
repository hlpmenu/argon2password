package argon2password

import "errors"

// Password-related errors
var (
	// Argon2 specific errors
	ErrInvalidHashFormat    = errors.New("argon2Password: Invalid hash format")
	ErrUnsupportedAlgorithm = errors.New("argon2Password: Unsupported algorithm")
	ErrInvalidVersion       = errors.New("argon2Password: Invalid argon2 version")
	ErrInvalidParams        = errors.New("argon2Password: Invalid parameters in hash")
	ErrInvalidSalt          = errors.New("argon2Password: Invalid salt in hash")
	ErrInvalidHash          = errors.New("argon2Password: Invalid hash")
	ErrHashTooLarge         = errors.New("argon2Password: Hash length exceeds supported limit")
	ErrEmptyPassword        = errors.New("argon2Password: Password cannot be empty")
	ErrNilHash              = errors.New("argon2Password: Hash is nil")
)

// Overflow errors
var (
	ErrIntegerOverflow = errors.New("argon2Password: Invalid input, operation would cause an integer overflow")
	ErrEmptyByteSlice  = errors.New("argon2Password: Invalid input, empty data provided")
	ErrInvalidDigit    = errors.New("argon2Password: Invalid input, contains non-numeric characters")
)

// Password generation errors
var (
	ErrGenerateLength   = errors.New("argon2Password: Failed to generate length")
	ErrLengthZero       = errors.New("argon2Password: Length cannot be zero")
	ErrInvalidCharset   = errors.New("argon2Password: Invalid charset")
	ErrGeneratePassword = errors.New("argon2Password: Failed to generate password")
	ErrNegativeLength   = errors.New("argon2Password: Length cannot be negative")
)

// Random number generation errors
var (
	ErrRandomNumNegativeN = errors.New("argon2Password: n must be greater than 0")
)
