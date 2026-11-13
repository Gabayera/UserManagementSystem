package security

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordHasher wraps Argon2id with the OWASP 2024 parameters and a bounded
// concurrency semaphore to prevent a hash-flood DoS on the login endpoint.
type PasswordHasher struct {
	params argonParams
	sem    chan struct{}
}

type argonParams struct {
	memory      uint32 // KiB
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// NewPasswordHasher builds a hasher with memory=19456 KiB, iterations=2,
// parallelism=1, saltLen=16, keyLen=32. maxConcurrent caps how many hashes
// may run at once; pass <=0 to default to a reasonable value (4).
func NewPasswordHasher(maxConcurrent int) *PasswordHasher {
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	return &PasswordHasher{
		params: argonParams{
			memory:      19456,
			iterations:  2,
			parallelism: 1,
			saltLength:  16,
			keyLength:   32,
		},
		sem: make(chan struct{}, maxConcurrent),
	}
}

// Hash derives an Argon2id PHC string from password. Respects ctx while
// queued for a semaphore slot; returns ctx.Err() if the caller bails.
func (h *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	salt := make([]byte, h.params.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%w: salt: %v", ErrPasswordHashFailed, err)
	}

	key := argon2.IDKey(
		[]byte(password), salt,
		h.params.iterations, h.params.memory, h.params.parallelism,
		h.params.keyLength,
	)
	return encodePHC(h.params, salt, key), nil
}

// Verify returns (true, nil) if password matches phc, (false, nil) on a
// straightforward mismatch, and (false, ErrPasswordHashFailed) if phc can't
// be parsed. Constant-time on the final comparison.
func (h *PasswordHasher) Verify(ctx context.Context, phc, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	params, salt, expected, err := decodePHC(phc)
	if err != nil {
		return false, err
	}
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	got := argon2.IDKey(
		[]byte(password), salt,
		params.iterations, params.memory, params.parallelism,
		params.keyLength,
	)
	if subtle.ConstantTimeCompare(got, expected) == 1 {
		return true, nil
	}
	return false, nil
}

func encodePHC(p argonParams, salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	)
}

func decodePHC(phc string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, fmt.Errorf("%w: malformed PHC", ErrPasswordHashFailed)
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParams{}, nil, nil, fmt.Errorf("%w: unsupported version", ErrPasswordHashFailed)
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: malformed params", ErrPasswordHashFailed)
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: salt: %v", ErrPasswordHashFailed, err)
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: key: %v", ErrPasswordHashFailed, err)
	}
	p.saltLength = uint32(len(salt))
	p.keyLength = uint32(len(key))
	if p.saltLength < 8 || p.keyLength < 16 {
		return argonParams{}, nil, nil, fmt.Errorf("%w: implausibly small salt/key", ErrPasswordHashFailed)
	}
	return p, salt, key, nil
}

// compile-time guard: ensure errors package isn't accidentally unused if the
// above is trimmed further later.
var _ = errors.Is
