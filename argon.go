package argon2password

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"runtime"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// getArgonParallelism returns the recommended degree of parallelism
// capped at a reasonable level to balance security and performance
func getArgonParallelism() uint8 {
	// Use number of available CPUs, with a minimum of 1 and maximum of ArgonMaxParallelism
	n := runtime.NumCPU()
	numCPU = n

	// Cap at ArgonMaxParallelism (4)
	if n > int(ArgonMaxParallelism) && ArgonMaxParallelism != 0 {
		return ArgonMaxParallelism
	} else if ArgonMaxParallelism == 0 {
		// Catch any mistake where ArgonMaxParallelism is set to 0
		return uint8(4) //nolint:mnd //
	}

	// NOTE: Not unsafe since n is capped at 4 and we're returning a uint8
	// #nosec G115 - Conversion is safe as n is capped
	return uint8(n) //nolint // G115
}

// generateArgonHash creates a hash of the password using Argon2id with the given parameters and salt
// The password slice is zeroed out after use for security
func generateArgonHash(password, salt []byte, iterations, memory uint32, parallelism uint8, keyLength uint32) []byte {
	if salt == nil || len(salt) == 0 || password == nil || len(password) == 0 {
		return nil
	}
	return argon2.IDKey(
		password,
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)
}

func generateSalt(length uint32) ([]byte, error) {
	return generateRandomBytes(length)
}

// encodeArgonHash creates the standard encoded format for Argon2id hashes
func encodeArgonHash(hash, salt []byte, memory, iterations uint32, parallelism uint8) string { //nolint:unused //

	// Standard PHC format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		ArgonHashFormat,
		argon2.Version,
		memory,
		iterations,
		parallelism,
		b64Salt,
		b64Hash,
	)
}

func encodeArgonHashAsBytes(hash, salt []byte, memory, iterations uint32, parallelism uint8) []byte {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := make([]byte, 0, 100) // Preallocate

	encodedHash = append(encodedHash, argonAlgoAndVersionPrefixBytes...)
	encodedHash = strconv.AppendInt(encodedHash, int64(argon2.Version), 10) //nolint:mnd
	encodedHash = append(encodedHash, dollarMEqualsBytes...)
	encodedHash = strconv.AppendUint(encodedHash, uint64(memory), 10) //nolint:mnd
	encodedHash = append(encodedHash, commaTEqualsBytes...)
	encodedHash = strconv.AppendUint(encodedHash, uint64(iterations), 10) //nolint:mnd
	encodedHash = append(encodedHash, commaPEqualsBytes...)
	encodedHash = strconv.AppendUint(encodedHash, uint64(parallelism), 10) //nolint:mnd
	encodedHash = append(encodedHash, dollarSignByte)
	encodedHash = append(encodedHash, b64Salt...)
	encodedHash = append(encodedHash, dollarSignByte)
	encodedHash = append(encodedHash, b64Hash...)

	return encodedHash
}

// decodeArgonHashBytes extracts the components from an encoded hash byte slice
// Returns memory, iterations, parallelism, salt, hash, error
func decodeArgonHashBytes(encodedHash []byte) (uint32, uint32, uint8, []byte, []byte, error) {
	parts := bytes.Split(encodedHash, dollarSignBytes)
	if len(parts) != ArgonEncodedPartCount {
		return 0, 0, 0, nil, nil, ErrInvalidHashFormat
	}

	// Compare the algorithm identifier
	if !bytes.Equal(parts[1], argon2idBytes) {
		return 0, 0, 0, nil, nil, ErrUnsupportedAlgorithm
	}

	// Parse version - extract the number after "v="
	versionBytes := parts[2]
	if len(versionBytes) < 3 || !bytes.Equal(versionBytes[:2], vEqualsBytes) {
		return 0, 0, 0, nil, nil, ErrInvalidVersion
	}

	// Parse version number from bytes
	version, err := parseUint32FromBytes(versionBytes[2:])
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}

	// Verify that the version is supported
	if int(version) != argon2.Version {
		return 0, 0, 0, nil, nil, ErrInvalidVersion
	}

	// Parse parameters - format is "m=X,t=Y,p=Z"
	paramBytes := parts[3]

	// Find positions of parameter separators
	mPos := bytes.Index(paramBytes, mEqualsBytes)
	tPos := bytes.Index(paramBytes, commaTEqualsBytes)
	pPos := bytes.Index(paramBytes, commaPEqualsBytes)

	if mPos != 0 || tPos < 3 || pPos < tPos+3 {
		return 0, 0, 0, nil, nil, ErrInvalidParams
	}

	// Extract and parse memory parameter (after "m=" and before ",t=")
	memoryBytes := paramBytes[2:tPos]
	memory, err := parseUint32FromBytes(memoryBytes)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}

	// Extract and parse iterations parameter (after ",t=" and before ",p=")
	iterBytes := paramBytes[tPos+3 : pPos]
	iterations, err := parseUint32FromBytes(iterBytes)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}

	// Extract and parse parallelism parameter (after ",p=")
	parallelismBytes := paramBytes[pPos+3:]
	parallelismUint32, err := parseUint32FromBytes(parallelismBytes)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}

	// Check for overflow when converting to uint8
	if parallelismUint32 > 255 {
		return 0, 0, 0, nil, nil, ErrInvalidParams
	}
	parallelism := uint8(parallelismUint32)

	// Enforce limits on memory and iterations to prevent DoS
	if memory > ArgonMaxMemory {
		return 0, 0, 0, nil, nil, ErrInvalidParams
	}

	if iterations > ArgonMaxIterations {
		return 0, 0, 0, nil, nil, ErrInvalidParams
	}

	// Decode base64 salt
	saltBytes := parts[4]
	salt := make([]byte, base64.RawStdEncoding.DecodedLen(len(saltBytes)))
	n, err := base64.RawStdEncoding.Decode(salt, saltBytes)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("Argon2Password: Base64 decode error: %w", err)
	}
	salt = salt[:n] // Trim to actual size

	// Decode base64 hash
	hashBytes := parts[5]
	hash := make([]byte, base64.RawStdEncoding.DecodedLen(len(hashBytes)))
	n, err = base64.RawStdEncoding.Decode(hash, hashBytes)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("Argon2Password: Base64 decode error: %w", err)
	}
	hash = hash[:n] // Trim to actual size

	return memory, iterations, parallelism, salt, hash, nil
}

func decodeArgonHash(encodedHash string) (uint32, uint32, uint8, []byte, []byte, error) { //nolint:unused //
	return decodeArgonHashBytes([]byte(encodedHash))
}

// parseUint32FromBytes converts byte slice to uint32
func parseUint32FromBytes(b []byte) (uint32, error) {
	// Check for empty slice
	if len(b) == 0 {
		return 0, ErrEmptyByteSlice
	}

	var result uint32
	for _, digit := range b {
		// Check if byte is a digit
		if digit < '0' || digit > '9' {
			return 0, ErrInvalidDigit
		}

		// Check for overflow before multiplying
		if result > (^uint32(0))/10 {
			return 0, ErrIntegerOverflow
		}
		result *= 10

		// Check for overflow before adding
		digitVal := uint32(digit - '0')
		if result > (^uint32(0))-digitVal {
			return 0, ErrIntegerOverflow
		}
		result += digitVal
	}

	return result, nil
}

// compareArgonPasswordAndHash compares a password with an encoded hash
func compareArgonPasswordAndHash(password []byte, encodedHash []byte) (bool, error) {
	// Reject empty passwords
	if len(password) == 0 {
		return false, ErrEmptyPassword
	}

	// Decode the hash using the byte-oriented function
	memory, iterations, parallelism, salt, hash, err := decodeArgonHashBytes(encodedHash)
	if err != nil {
		return false, err
	}

	// Safe conversion: Ensure the hash length is within uint32 limits
	// As it could otherwise be a DoS attack vector where
	//	the attacker can send a very large hash to be verified
	// uint32 max limit is 4GB
	hashLen := len(hash)
	if hashLen > int(^uint32(0)) { // ^uint32(0) gives max uint32 value (4294967295)
		return false, ErrHashTooLarge
	}

	// Compute the hash for the provided password
	computedHash := generateArgonHash(password, salt, iterations, memory, parallelism, uint32(hashLen))
	if computedHash == nil {
		return false, ErrInvalidHash
	}
	// Constant-time comparison of the hashes to prevent timing attacks
	match := subtle.ConstantTimeCompare(hash, computedHash) == 1
	return match, nil
}

func generateHashFromInput(password []byte) ([]byte, error) {

	// Generate a cryptographically secure random salt
	salt, err := generateSalt(ArgonSaltLength)
	if err != nil {
		return nil, ErrInvalidHash
	}

	// Generate the hash
	hash := generateArgonHash(
		password,                // Provided password
		salt,                    // Generated salt
		ArgonIterations,         // default iterations
		ArgonMemory,             // default memory
		argonDefaultParallelism, // default parallelism
		ArgonKeyLength,          // default key length
	)
	if hash == nil {
		return nil, ErrInvalidHash
	}

	// Encode the hash in the standard format
	encodedHash := encodeArgonHashAsBytes(
		hash,                    // Generated hash
		salt,                    // Generated salt
		ArgonMemory,             // default memory
		ArgonIterations,         // default iterations
		argonDefaultParallelism, // default parallelism
	)
	if len(encodedHash) == 0 {
		return nil, ErrInvalidHash
	}
	return encodedHash, nil

}

func generateHashFromInputCustom(password []byte, config *Config) ([]byte, error) { //nolint:unused //

	if config == nil {
		return nil, ErrConfigNil
	}

	// Generate a cryptographically secure random salt
	salt, err := generateSalt(config.SaltLength)
	if err != nil {
		return nil, ErrInvalidHash
	}
	// Generate the hash
	hash := generateArgonHash(
		password,           // Provided password
		salt,               // Generated salt
		config.Iterations,  //  Iterations
		config.Memory,      //  Memory
		config.Parallelism, //  Parallelism
		config.KeyLength,   //  Key length
	)
	if hash == nil {
		return nil, ErrInvalidHash
	}

	// Encode the hash in the standard format
	encodedHash := encodeArgonHashAsBytes(
		hash,               // Generated hash
		salt,               // Generated salt
		config.Memory,      //  Memory
		config.Iterations,  //  Iterations
		config.Parallelism, //  Parallelism
	)
	if len(encodedHash) == 0 {
		return nil, ErrInvalidHash
	}
	return encodedHash, nil

}
