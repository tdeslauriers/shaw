package creds

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Algorithm         = "argon2id" // Using Argon2id variant
	argon2MinVersion uint32 = 0x13       // Minimum supported Argon2 version: 19
	argon2Time       uint32 = 3          // Number of iterations
	argon2Memory     uint32 = 64 * 1024  // Memory in KiB (64 MB)
	argon2Threads    uint8  = 4          // Number of parallel threads
	argon2KeyLen     uint32 = 32         // Length of the generated key
	argon2SaltLen    uint32 = 16         // Length of the salt
)

// Service for hashing and verifying passwords
type Service interface {

	// HashPassword hashes the given password and returns the encoded hash string
	// Note: current implementation uses Argon2id, and
	// generates a salt, hashes the given password using Argon2id, and returns the encoded hash string
	HashPassword(password string) (string, error)

	// VerifyPassword verifies a password against the given encoded hash value
	// fullHash is the params, salt, and hash, concatenated to a string and will need to be decoded
	// within the implementation
	VerifyPassword(password, fullHash string) (bool, error)
}

// NewService creates a new creds Service interface and returns a pointer to a
// argon2Hasher implementation with default parameters
func NewService() Service {

	return &argon2Hasher{
		algorithm: argon2Algorithm,
		version:   argon2.Version,
		time:      argon2Time,
		memory:    argon2Memory,
		threads:   argon2Threads,
		keyLen:    argon2KeyLen,
		saltLen:   argon2SaltLen,
	}
}

var _ Service = (*argon2Hasher)(nil)

// Argon2Hasher provides methods for hashing and verifying passwords using Argon2id
type argon2Hasher struct {
	algorithm string
	version   uint32
	time      uint32
	memory    uint32
	threads   uint8
	keyLen    uint32
	saltLen   uint32
}

// HashPassword generates a salt, hashes the given password using Argon2id, and returns the encoded hash string
func (h *argon2Hasher) HashPassword(password string) (string, error) {

	// generate a random salt
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// gernerate the hash using Argon2id mechanism recommended by docs
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.time,
		h.memory,
		h.threads,
		h.keyLen,
	)

	// encode the  salt and hash to base64 for formatted concatenation and storage
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	fullHash := fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		h.algorithm, argon2.Version, h.memory, h.time, h.threads, encodedSalt, encodedHash)

	return fullHash, nil
}

// argon2Params holds the parameters extracted from an encoded hash
type argon2Params struct {
	algorithm string
	version   uint32
	time      uint32
	memory    uint32
	threads   uint8
	keyLen    uint32
}

// VerifyPassword verifies a password against the given encoded Argon2id encoded hash value
// fullHash is the params, salt, and hash concatenated string
func (h *argon2Hasher) VerifyPassword(password, fullHash string) (bool, error) {

	// extract the params, salt, and hash from the full hash string
	params, salt, hash, err := h.decodeHash(fullHash)
	if err != nil {
		return false, err
	}

	// TODO: add a version and algorithm check here if needed in future

	// generate a new hash with the same parameters and salt
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		params.keyLen,
	)

	// compare the original hash with the new computed hash (from the password) using constant time comparison
	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return true, nil
	}

	return false, nil
}

// decodeHash decodes a full Argon2id hash string into its components (salt and hash) for verification
func (h *argon2Hasher) decodeHash(fullHash string) (*argon2Params, []byte, []byte, error) {

	// lightweight length check
	// redundant, but avoids unnecessary processing on obviously invalid hashes
	if len(fullHash) < 32 {
		return nil, nil, nil, fmt.Errorf("hash too short")
	}

	// key length check based on max reasonable expected length of base64 encoded salt and hash
	if len(fullHash) > 512 {
		return nil, nil, nil, fmt.Errorf("hash too long")
	}

	// split the full hash into its components: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	parts := strings.Split(fullHash, "$")

	// validate their are 6 parts when split by "$"
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	// instantiate params struct
	params := &argon2Params{}

	// validate the algorithm is argon2id
	if parts[1] != argon2Algorithm {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	params.algorithm = parts[1]

	// parse the version
	var version uint32
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, err
	}

	// validate the version is supported
	if version < h.version {
		return nil, nil, nil, fmt.Errorf("unsupported argon2 version: %d", version)
	}

	params.version = version

	// parse memory, time, threads
	// these dont need manual validation as they will be validated during hash comparison
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads); err != nil {
		return nil, nil, nil, err
	}

	// decode the salt from base64
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %v", err)
	}

	// decode the hash from base64
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %v", err)
	}

	// set the key length
	params.keyLen = uint32(len(hash))

	return params, salt, hash, nil
}
