package argon2password

import (
	cryptrand "crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// Generates a random number between 0 and n
func RandomNumN(n int) (int, error) {
	switch {
	case n < 0:
		return 0, ErrRandomNumNegativeN
	case n == 0:
		return 0, nil
	}
	maxVal := big.NewInt(int64(n))
	num, err := cryptrand.Int(cryptrand.Reader, maxVal)
	if err != nil {
		return 0, fmt.Errorf("argon2Password: failed to generate random number: %w", err)
	}
	newn := int(num.Int64())

	return newn, nil
}

func generateRandomBytes(length uint32) ([]byte, error) {
	b := make([]byte, length)
	_, err := io.ReadFull(cryptrand.Reader, b)
	if err != nil {
		return nil, fmt.Errorf("argon2Password: Failed to generate random bytes: %w", err)
	}
	return b, nil
}
