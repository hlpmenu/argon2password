# Argon2id Password Hashing, comparison, and password generation

[![Go Reference](https://pkg.go.dev/badge/gopkg.hlmpn.dev/pkg/argon2password.svg)](https://pkg.go.dev/gopkg.hlmpn.dev/pkg/argon2password)
[![Go Report Card](https://goreportcard.com/badge/gopkg.hlmpn.dev/pkg/argon2password)](https://goreportcard.com/report/gopkg.hlmpn.dev/pkg/argon2password)
[![Build and Test](https://github.com/hlmpenu/argon2password/actions/workflows/go-build-test.yml/badge.svg)](https://github.com/hlpmenu/argon2password/actions/workflows/go-build-test.yml)
[![codecov](https://codecov.io/gh/hlpmenu/argon2password/graph/badge.svg?token=2B6W3OWH1R)](https://codecov.io/gh/hlpmenu/argon2password)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hlpmenu/argon2password/badge)](https://scorecard.dev/viewer/?uri=github.com/hlpmenu/argon2password)

## Overview

This package provides secure password hashing and verification using the Argon2id algorithm by wrapping the [Go standard library's crypto/argon2](https://pkg.go.dev/crypto/argon2) package.

It implements best practices for password security with sensible defaults while allowing for customization.

## Features

- Secure password hashing using Argon2id
- Verification/Comparison of password against hashed values
- Customizable hashing parameters
- All cryptographic operations use Go's standard crypto libraries
- Password generation(not related to argon2 though)


### Custom parameters
  - While the defaults should be good for most cases, pkg provides a Config struct to customize the parameters

## Parameters & Security

### OWASP-compliant defaults for 2025 recommendations
  - Memory: 64MB / OWASP minimum recommendation: 46 MiB
  - Iterations: 3 / OWASP minimum recommendation: 1
  - Salt Length: 16 bytes / OWASP minimum recommendation: 16 bytes
  - Key Length: 32 bytes / OWASP minimum recommendation: 32 bytes
  - Parallelism: Number of available CPU core, capped at 4 / OWASP examples use 1, but higher is     better for multi-core systems

### Security considerations
 - Password inputs are zeroed out after use for security
 - Max memory for at lest some form of DoS protection
 - Uses constant-time comparison to prevent timing attacks
 - Format follows the PHC standard: `$argon2id$v=19$m=65536,t=3,p=4$salt$hash`



These parameters follow OWASP recommendations for Argon2id (2025).

## Installation

```bash
go get gopkg.hlmpn.dev/pkg/argon2password
```

## Usage

### Basic Password Hashing

```go
package main

import (
    "fmt"
    "log"

    "gopkg.hlmpn.dev/pkg/argon2password"
)

func main() {
    // Hash a password using default settings
    hashedPassword, err := argon2password.GenerateHash("my-secure-password")
    if err != nil {
        log.Fatalf("Failed to hash password: %v", err)
    }
    
    fmt.Printf("Hashed password: %s\n", hashedPassword)
    
    // Verify a password against a hash
    match, err := argon2password.ComparePassword("my-secure-password", hashedPassword)
    if err != nil {
        log.Fatalf("Error verifying password: %v", err)
    }
    
    if match {
        log.Print("Password is correct!")
    } else {
        log.Print("Password is incorrect!")
    }
}
```

### Password generation

Default length is 32-40 characters(random).

Default charset is:
```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~
```

charset can bee customized with `argon2password.GeneratePasswordWithCharset`

#### Generate a random password
By default length is random between 32-40 characters
```go
pw, err := argon2password.GeneratePassword()
if err != nil {
    log.Printf("Failed to generate password: %v", err)
}
```

#### Generate a password with a specific length

```go
pw, err := argon2password.GeneratePasswordWithLength(16)
if err != nil {
    log.Printf("Failed to generate password: %v", err)
}
```

#### Generate a password with a specific charset
```go
pw, err := argon2password.GeneratePasswordWithCharset("abc", 16)
if err != nil {
    log.Printf("Failed to generate password: %v", err)
}
```

### Custom Configuration

```go
package main

import (
    "fmt"
    "log"

    "gopkg.hlmpn.dev/pkg/argon2password"
)

func main() {
    // Create custom configuration
    config, err := argon2password.NewConfig(
        512*1024,  // MaxMemory (512MB)
        10,        // MaxIterations
        128*1024,  // Memory (128MB)
        4,         // Iterations
        16,        // SaltLength
        32,        // KeyLength
        2,         // Parallelism
    )
    if err != nil {
        log.Fatalf("Failed to create config: %v", err)
    }
    
    // Hash with custom config
    hashedPassword, err := argon2password.GenerateHashWithConfig("my-secure-password", config)
    if err != nil {
        log.Fatalf("Failed to hash password with custom config: %v", err)
    }
    
    fmt.Printf("Custom hashed password: %s\n", hashedPassword)
}
```

### Password Generation

```go
package main

import (
    "fmt"
    "log"

    "gopkg.hlmpn.dev/pkg/argon2password"
)

func main() {
    // Generate a secure random password
    password, err := argon2password.GeneratePassword(32)
    if err != nil {
        log.Fatalf("Failed to generate password: %v", err)
    }
    
    fmt.Printf("Generated password: %s\n", password)
}
```



## License

This project is licensed under the terms of the [MIT License](LICENSE).
