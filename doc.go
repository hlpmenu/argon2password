package argon2password

// Package argon2password provides secure password hashing and verification
// using the Argon2id algorithm.
//
// Default Argon2id Parameters:
//   - ArgonMemory: 64MB (64 * 1024)
//   - ArgonIterations: 3 iterations for enhanced security
//   - ArgonSaltLength: 16 bytes (128-bit)
//   - ArgonKeyLength: 32 bytes (256-bit)
//
// DoS Protection Parameters:
//   - ArgonMaxMemory: Max 512MB (512 * 1024)
//   - ArgonMaxIterations: Max 10 iterations
//
// Parallelism:
//   - ArgonMaxParallelism: 4 (Optimal cap to balance security and performance)
//
// These parameters follow OWASP recommendations for Argon2id (2025) while providing
// protection against denial-of-service attacks through reasonable upper bounds.
//
// OWASP Recommended Configurations:
// The current implementation uses higher memory than OWASP minimum recommendations.
// All of these configurations provide equivalent protection:
//   - 46 MiB memory, 1 iteration, 1 parallel thread (m=47104, t=1, p=1)
//   - 19 MiB memory, 2 iterations, 1 parallel thread (m=19456, t=2, p=1)
//   - 12 MiB memory, 3 iterations, 1 parallel thread (m=12288, t=3, p=1)
//   - 9 MiB memory, 4 iterations, 1 parallel thread (m=9216, t=4, p=1)
//   - 7 MiB memory, 5 iterations, 1 parallel thread (m=7168, t=5, p=1)
//
// Password generation
//
