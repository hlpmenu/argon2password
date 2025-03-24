package argon2password

// Argon2 parameters
// For custom uses, see custom.go
const (
	// Current implementation uses higher memory than OWASP minimum recommendations
	// OWASP recommended configurations (all equivalent protection):
	// - m=47104 (46 MiB), t=1, p=1
	// - m=19456 (19 MiB), t=2, p=1
	// - m=12288 (12 MiB), t=3, p=1
	// - m=9216 (9 MiB), t=4, p=1
	// - m=7168 (7 MiB), t=5, p=1

	// OWASP recommended parameters for Argon2id (2025)
	ArgonMemory     uint32 = 64 * 1024 // 64MB
	ArgonIterations uint32 = 3         // 3 iterations for enhanced security
	ArgonSaltLength uint32 = 16        // 16 bytes salt (128-bit)
	ArgonKeyLength  uint32 = 32        // 32 bytes key (256-bit)

	// DoS protection parameters - maximum allowed values for verification
	ArgonMaxMemory     uint32 = 512 * 1024 // Max 512MB
	ArgonMaxIterations uint32 = 10         // Max 10 iterations

	// Optimal parallelism cap to balance security and performance
	ArgonMaxParallelism uint8 = 4
)

// Misc constants
const (
	ArgonEncodedPartCount int = 6                  // Number of parts in a valid encoded hash
	uint32MaxValue        int = 4294967295 - 1     // minus 1 to avoid any mistakes leading to overflow
	int32MaxValue         int = uint32MaxValue / 2 // Max value for int32
	uint8MaxValue         int = 255                // Max value for uint8
)

// String constants
const (
	argon2id                  = "argon2id"
	vEqual                    = "v="
	mEqual                    = "m="
	commaTEqual               = ",t="
	commaPEqual               = ",p="
	dollarSign                = "$"
	argonAlgoAndVersionPrefix = "$argon2id$v="
	dollarMEqual              = "$m="
)

// Pre declared []byte versions of the above constants
var (
	argon2idBytes                  = []byte(argon2id)
	vEqualsBytes                   = []byte(vEqual)
	mEqualsBytes                   = []byte(mEqual)
	commaTEqualsBytes              = []byte(commaTEqual)
	commaPEqualsBytes              = []byte(commaPEqual)
	dollarMEqualsBytes             = []byte(dollarMEqual)
	dollarSignBytes                = []byte(dollarSign)
	argonAlgoAndVersionPrefixBytes = []byte(argonAlgoAndVersionPrefix)
)

// byte values for parsing
const (
	dollarSignByte = '$'
)

// Format directives
const (
	ArgonHashFormat         string = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	ArgonVersionLabelFormat string = "v=%d"
	ArgonParamsFormat       string = "m=%d,t=%d,p=%d"
)

// Password generation constants
const (
	passwordGenerationCharset     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~"
	generatePasswordDefaultLength = 32
)
