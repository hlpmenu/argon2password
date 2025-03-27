package argon2password

import (
	"regexp"
	"strings"
)

// Password validation constants
const (
	lowercaseLetters  = "abcdefghijklmnopqrstuvwxyz"
	uppercaseLetters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers           = "0123456789"
	passwordMinLength = 8
	passwordMaxLength = 129
)

// Password validation regex for special chars
var specialCharRegex = regexp.MustCompile(`(?:[[:punct:]]|_)`)

// IsValid checks if the password is valid
// Reqs: Length over 8, at least 1 number, 1 uppercase, 1 lowercase, 1 special character
func IsValid(password string) bool {
	if len(password) < passwordMinLength || len(password) > passwordMaxLength {
		return false
	}
	hasLowercase := strings.ContainsAny(password, lowercaseLetters)
	hasUppercase := strings.ContainsAny(password, uppercaseLetters)
	hasNumber := strings.ContainsAny(password, numbers)
	hasSpecialChar := specialCharRegex.MatchString(password)
	return hasLowercase && hasUppercase && hasNumber && hasSpecialChar
}

type PasswordRequirements struct {
	HasLowercase bool
	HasUppercase bool
	HasNumber    bool
	HasSpecial   bool
	MinLength    int
	MaxLength    int
}
