package argon2password

import (
	"errors"
)

// Config provides customizable parameters for Argon2id hashing.
// All fields are optional - if a field is set to 0 or left uninitialized,
// the corresponding default value will be used.
// Negative values are not allowed.
type Config struct {
	// Memory usage in megabytes(MB).
	// Defaults to 64 MB if unset(0).
	// OWASP minimum recommendation: 46 MB.
	Memory uint32

	// Number of iterations.
	// Defaults to 3 if unset(0).
	// OWASP minimum recommendation: 1-5 (depending on memory).
	Iterations uint32

	// Salt length in bytes.
	// Defaults to 16 bytes if unset(0).
	// OWASP minimum recommendation: 16 bytes.
	SaltLength uint32

	// Key length in bytes.
	// Defaults to 32 bytes if unset(0).
	// OWASP minimum recommendation: 32 bytes.
	KeyLength uint32

	// Parallelism factor - threads count. All values gets capped at cpu count.
	// Defaults to the available number of CPU cores up to a maximum of 4 if unset(0).
	// OWASP examples use 1, but higher is better for multi-core systems.
	Parallelism uint8

	// Max memory in megabytes(MB).
	// Defaults to 512 if unset(0).
	MaxMemory uint32

	// Max iterations allowed for verification.
	// Defaults to 10 if unset(0).
	MaxIterations uint32
}

var (
	ErrConfigNil                  = newConfigError("config is nil")
	ErrConfigNegativeValue        = newConfigError("value is negative")
	ErrConfigMemoryExceedsMax     = newConfigError("memory exceeds max memory defined in the config")
	ErrConfigIterationsExceedsMax = newConfigError("iterations exceeds max iterations defined in the config")
)

type ConfigError struct {
	m string
}

func newConfigError(msg string) *ConfigError {
	return &ConfigError{m: msg}
}

func (e ConfigError) Error() string {
	return e.m
}
func (e ConfigError) Unwrap() error {
	return errors.Unwrap(e)
}

func (e ConfigError) Is(target error) bool {
	return errors.Is(e, target)
}

func IsConfigError(err error) bool {
	return false
}

func NewConfig(maxMemory uint32, maxIterations uint32, memory uint32, iterations uint32, saltLength uint32, keyLength uint32, parallelism uint8) (*Config, *ConfigError) {
	config := &Config{
		MaxMemory:     maxMemory,
		MaxIterations: maxIterations,
		Memory:        memory,
		Iterations:    iterations,
		SaltLength:    saltLength,
		KeyLength:     keyLength,
		Parallelism:   parallelism,
	}

	err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// NewDefaultConfig returns a validated Config with recommended default values
func NewDefaultConfig() (*Config, error) {
	config, err := NewConfig(
		ArgonMaxMemory,          // MaxMemory
		ArgonMaxIterations,      // MaxIterations
		ArgonMemory,             // Memory
		ArgonIterations,         // Iterations
		ArgonSaltLength,         // SaltLength
		ArgonKeyLength,          // KeyLength
		argonDefaultParallelism, // Parallelism
	)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func validateConfig(config *Config) *ConfigError {
	if config == nil {
		return ErrConfigNil
	}

	// Validates parallelism, and caps it to the number of CPUs
	// Also makes sure the vlaue is within the allowed range
	config.Parallelism = capParallelism(config.Parallelism)

	// Check max memory
	if config.MaxMemory == 0 {
		config.MaxMemory = ArgonMaxMemory
	}

	if config.Memory == 0 { // Treats 0 value as "not set"
		config.Memory = ArgonMaxMemory // Wont succeed uint32 max
	}

	// Check memory
	switch {
	case config.Memory == 0: // Treats 0 value as "not set"
		config.Memory = ArgonMemory // safe, constants are verified at build time
	case config.Memory > config.MaxMemory:
		return ErrConfigMemoryExceedsMax
	}

	// Check max iterations
	if config.MaxIterations == 0 {
		config.MaxIterations = ArgonMaxIterations
	}

	// Check iterations
	switch {
	case config.Iterations == 0: // Treats 0 value as "not set"
		config.Iterations = ArgonIterations // safe, constants are verified at build time
	case config.Iterations > config.MaxIterations:
		return ErrConfigIterationsExceedsMax
	}

	// Check salt length
	if config.SaltLength == 0 {
		config.SaltLength = ArgonSaltLength
	}

	// Check key length
	if config.KeyLength == 0 {
		config.KeyLength = ArgonKeyLength
	}

	return nil
}

func capParallelism(input uint8) uint8 {
	// Convert input to int only once

	var u8Cpu uint8
	switch {
	case numCPU > uint8MaxValue:
		u8Cpu = 255
	default:
		// #nosec G115 - Conversion is safe as it's already checked in the switch
		u8Cpu = uint8(numCPU) //nolint:gosec // G115
	}

	switch {
	case input == 0:
		return ArgonMaxParallelism
	case input > u8Cpu:
		return u8Cpu
	default:
		return input
	}
}
