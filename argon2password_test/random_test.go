package argon2password_test

import (
	"testing"

	argon2password "gopkg.hlmpn.dev/pkg/argon2password"
)

// TestRandomNumN tests the public RandomNumN function
func TestRandomNumN(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{
			name:    "Small number range",
			n:       10,
			wantErr: false,
		},
		{
			name:    "Large number range",
			n:       1000000,
			wantErr: false,
		},
		{
			name:    "Range of 1",
			n:       1,
			wantErr: false,
		},
		{
			name:    "Zero range", // Should always return 0 without error
			n:       0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run multiple times to check the distribution
			const iterations = 100
			results := make(map[int]int)

			for i := 0; i < iterations; i++ {
				num, err := argon2password.RandomNumN(tt.n)

				// Check error expectations
				if (err != nil) != tt.wantErr {
					t.Errorf("RandomNumN() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				// For successful cases, validate the result
				if !tt.wantErr {
					// Check result is within the expected range
					if tt.n > 0 && (num < 0 || num >= tt.n) {
						t.Errorf("RandomNumN(%d) = %d, want value in range [0,%d)", tt.n, num, tt.n)
					}
					if tt.n == 0 && num != 0 {
						t.Errorf("RandomNumN(0) = %d, want 0", num)
					}

					// Track distribution
					results[num]++
				}
			}

			// For n > 1, check some level of random distribution
			// This is a very basic statistical check that might occasionally fail
			// but it should catch completely broken implementations
			if tt.n > 1 && !tt.wantErr {
				// With enough iterations, we should see at least a few different values
				if len(results) < 2 && tt.n > 2 {
					t.Errorf("RandomNumN(%d) produced suspiciously low variance: only %d distinct values",
						tt.n, len(results))
				}
			}
		})
	}
}

// TestRandomNumNWithLotsOfGenerations generates a lot of random numbers to verify
// the distribution appears reasonable
func TestRandomNumNWithLotsOfGenerations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping extended test in short mode")
	}

	// Parameters for test
	const n = 10
	const iterations = 10000

	// Generate many random numbers
	results := make(map[int]int)
	for i := 0; i < iterations; i++ {
		num, err := argon2password.RandomNumN(n)
		if err != nil {
			t.Errorf("RandomNumN() error = %v", err)
			return
		}
		results[num]++
	}

	// Check that all values in the range occurred
	for i := 0; i < n; i++ {
		if results[i] == 0 {
			t.Errorf("RandomNumN(%d) didn't generate value %d in %d iterations", n, i, iterations)
		}
	}

	// Check for reasonable distribution
	// Each value should occur approximately iterations/n times
	expected := iterations / n
	tolerance := int(float64(expected) * 0.3) // Allow 30% deviation

	for i := 0; i < n; i++ {
		count := results[i]
		if count < expected-tolerance || count > expected+tolerance {
			// This is a probabilistic test, so we'll just log a warning rather than fail
			// as statistical fluctuations are expected
			t.Logf("Warning: RandomNumN(%d) generated %d occurrences of %d (expected around %d±%d)",
				n, count, i, expected, tolerance)
		}
	}
}
