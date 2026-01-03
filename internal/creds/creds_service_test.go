package creds

import (
	"strings"
	"testing"
)

// TestHashPassword_UniqueSalts verifies that each hash uses a unique salt
func TestHashPassword_UniqueSalts(t *testing.T) {
	hasher := NewService()
	password := "samepassword123"

	// Generate multiple hashes of the same password
	hash1, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	hash2, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	hash3, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	// All hashes should be different (due to different salts)
	if hash1 == hash2 {
		t.Error("Two hashes of the same password should be different (different salts)")
	}
	if hash1 == hash3 {
		t.Error("Two hashes of the same password should be different (different salts)")
	}
	if hash2 == hash3 {
		t.Error("Two hashes of the same password should be different (different salts)")
	}

	// But all should verify correctly
	if match, _ := hasher.VerifyPassword(password, hash1); !match {
		t.Error("Password should verify against hash1")
	}
	if match, _ := hasher.VerifyPassword(password, hash2); !match {
		t.Error("Password should verify against hash2")
	}
	if match, _ := hasher.VerifyPassword(password, hash3); !match {
		t.Error("Password should verify against hash3")
	}
}

// TestVerifyPassword tests the VerifyPassword method
func TestVerifyPassword(t *testing.T) {
	hasher := NewService()

	// Pre-generated hash for consistent testing
	testPassword := "testpassword123"
	testHash, err := hasher.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name        string
		password    string
		hash        string
		wantMatch   bool
		wantErr     bool
		errContains string
	}{
		{
			name:      "correct password",
			password:  testPassword,
			hash:      testHash,
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "incorrect password",
			password:  "wrongpassword123",
			hash:      testHash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "case sensitive password",
			password:  "TestPassword123",
			hash:      testHash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "password with extra character",
			password:  testPassword + "x",
			hash:      testHash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "password missing character",
			password:  testPassword[:len(testPassword)-1],
			hash:      testHash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:        "invalid hash - too short",
			password:    testPassword,
			hash:        "$argon2id$v=19$m=65536",
			wantMatch:   false,
			wantErr:     true,
			errContains: "hash too short",
		},
		{
			name:        "invalid hash - wrong format",
			password:    testPassword,
			hash:        "notavalidhash",
			wantMatch:   false,
			wantErr:     true,
			errContains: "hash too short",
		},
		{
			name:        "invalid hash - missing parts",
			password:    testPassword,
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$salty",
			wantMatch:   false,
			wantErr:     true,
			errContains: "invalid hash format",
		},
		{
			name:        "invalid hash - wrong algorithm",
			password:    testPassword,
			hash:        "$bcrypt$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA",
			wantMatch:   false,
			wantErr:     true,
			errContains: "unsupported algorithm",
		},
		{
			name:        "invalid hash - bad base64 salt",
			password:    testPassword,
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$not-valid-base64!@#$aGFzaA",
			wantMatch:   false,
			wantErr:     true,
			errContains: "failed to decode salt",
		},
		{
			name:        "invalid hash - bad base64 hash",
			password:    testPassword,
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$not-valid-base64!@#",
			wantMatch:   false,
			wantErr:     true,
			errContains: "failed to decode hash",
		},
		{
			name:      "empty password against valid hash",
			password:  "",
			hash:      testHash,
			wantMatch: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := hasher.VerifyPassword(tt.password, tt.hash)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("VerifyPassword() error = %v, should contain %q", err, tt.errContains)
				}
				return
			}

			if match != tt.wantMatch {
				t.Errorf("VerifyPassword() match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

// TestVerifyPassword_VersionCompatibility tests version handling
func TestVerifyPassword_VersionCompatibility(t *testing.T) {
	hasher := NewService()

	tests := []struct {
		name        string
		hash        string
		wantErr     bool
		errContains string
	}{
		{
			name:    "current version v19",
			hash:    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr: false,
		},
		{
			name:    "future version v20 should work",
			hash:    "$argon2id$v=20$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr: false,
		},
		{
			name:    "future version v25 should work",
			hash:    "$argon2id$v=25$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr: false,
		},
		{
			name:        "old version v18 should fail",
			hash:        "$argon2id$v=18$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     true,
			errContains: "unsupported argon2 version",
		},
		{
			name:        "old version v10 should fail",
			hash:        "$argon2id$v=10$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     true,
			errContains: "unsupported argon2 version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hasher.VerifyPassword("testpassword", tt.hash)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("VerifyPassword() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestDecodeHash tests the decodeHash method
func TestDecodeHash(t *testing.T) {
	hasher := NewService().(*argon2Hasher)

	tests := []struct {
		name        string
		hash        string
		wantErr     bool
		errContains string
		checkParams bool
		wantMemory  uint32
		wantTime    uint32
		wantThreads uint8
	}{
		{
			name:        "valid hash",
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     false,
			checkParams: true,
			wantMemory:  65536,
			wantTime:    3,
			wantThreads: 4,
		},
		{
			name:        "different parameters",
			hash:        "$argon2id$v=19$m=131072,t=5,p=8$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     false,
			checkParams: true,
			wantMemory:  131072,
			wantTime:    5,
			wantThreads: 8,
		},
		{
			name:        "hash too short",
			hash:        "$argon2id$v=19",
			wantErr:     true,
			errContains: "hash too short",
		},
		{
			name:        "hash too long",
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$" + strings.Repeat("a", 500) + "$hash",
			wantErr:     true,
			errContains: "hash too long",
		},
		{
			name:        "invalid format - too few parts",
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$salt",
			wantErr:     true,
			errContains: "invalid hash format",
		},
		{
			name:        "invalid format - too many parts",
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$salt$hash$extra",
			wantErr:     true,
			errContains: "invalid hash format",
		},
		{
			name:        "wrong algorithm",
			hash:        "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     true,
			errContains: "unsupported algorithm",
		},
		{
			name:        "invalid version format",
			hash:        "$argon2id$version=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     true,
			errContains: "", // Sscanf will fail
		},
		{
			name:        "invalid parameters format",
			hash:        "$argon2id$v=19$memory=65536,time=3,parallel=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
			wantErr:     true,
			errContains: "", // Sscanf will fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, salt, hash, err := hasher.decodeHash(tt.hash)

			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("decodeHash() error = %v, should contain %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				return
			}

			// Verify params were extracted correctly
			if tt.checkParams {
				if params.memory != tt.wantMemory {
					t.Errorf("decodeHash() memory = %d, want %d", params.memory, tt.wantMemory)
				}
				if params.time != tt.wantTime {
					t.Errorf("decodeHash() time = %d, want %d", params.time, tt.wantTime)
				}
				if params.threads != tt.wantThreads {
					t.Errorf("decodeHash() threads = %d, want %d", params.threads, tt.wantThreads)
				}
			}

			// Verify salt and hash were decoded
			if len(salt) == 0 {
				t.Error("decodeHash() salt should not be empty")
			}
			if len(hash) == 0 {
				t.Error("decodeHash() hash should not be empty")
			}

			// Verify keyLen matches hash length
			if params.keyLen != uint32(len(hash)) {
				t.Errorf("decodeHash() keyLen = %d, should match hash length %d", params.keyLen, len(hash))
			}
		})
	}
}

// TestArgon2Integration tests the full integration with actual Argon2 library
func TestArgon2Integration(t *testing.T) {
	hasher := NewService()

	password := "integration-test-password-123"

	// Hash the password
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Verify it works
	match, err := hasher.VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() failed: %v", err)
	}
	if !match {
		t.Error("VerifyPassword() should match the original password")
	}

	// Verify wrong password fails
	match, err = hasher.VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() failed: %v", err)
	}
	if match {
		t.Error("VerifyPassword() should not match wrong password")
	}
}

// TestConstantTimeComparison verifies that constant-time comparison is being used
// This is a behavioral test - we can't directly test timing, but we can verify the function works correctly
func TestConstantTimeComparison(t *testing.T) {
	hasher := NewService()

	password := "testpassword123"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Create variations that differ at different positions
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"exact match", password, true},
		{"differ at start", "Xestpassword123", false},
		{"differ at middle", "testpaXXword123", false},
		{"differ at end", "testpassword12X", false},
		{"completely different", "xxxxxxxxxxxxxxx", false},
		{"one char short", "testpassword12", false},
		{"one char long", "testpassword1234", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := hasher.VerifyPassword(tt.password, hash)
			if err != nil {
				t.Errorf("VerifyPassword() error = %v", err)
			}
			if match != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", match, tt.want)
			}
		})
	}
}

// BenchmarkHashPassword benchmarks password hashing
func BenchmarkHashPassword(b *testing.B) {
	hasher := NewService()
	password := "benchmarkpassword123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.HashPassword(password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyPassword benchmarks password verification
func BenchmarkVerifyPassword(b *testing.B) {
	hasher := NewService()
	password := "benchmarkpassword123"

	hash, err := hasher.HashPassword(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.VerifyPassword(password, hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyPassword_Failure benchmarks password verification with wrong password
func BenchmarkVerifyPassword_Failure(b *testing.B) {
	hasher := NewService()
	password := "benchmarkpassword123"
	wrongPassword := "wrongpassword123"

	hash, err := hasher.HashPassword(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.VerifyPassword(wrongPassword, hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}
