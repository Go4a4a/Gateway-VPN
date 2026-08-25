package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var ErrInvalidPassword = errors.New("password must contain 12..1024 bytes")

type Argon2Parameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

func DefaultArgon2Parameters() Argon2Parameters {
	return Argon2Parameters{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, KeyBytes: 32}
}

func HashPassword(password string, parameters Argon2Parameters) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", ErrInvalidPassword
	}
	if err := validateArgon2Parameters(parameters); err != nil {
		return "", err
	}
	salt := make([]byte, parameters.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, parameters.Iterations, parameters.MemoryKiB, parameters.Parallelism, parameters.KeyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, parameters.MemoryKiB, parameters.Iterations, parameters.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(password, encoded string) (bool, error) {
	parameters, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, parameters.Iterations, parameters.MemoryKiB, parameters.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parsePasswordHash(encoded string) (Argon2Parameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Argon2Parameters{}, nil, nil, errors.New("unsupported password hash format")
	}
	var parameters Argon2Parameters
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &parameters.MemoryKiB, &parameters.Iterations, &parameters.Parallelism); err != nil {
		return Argon2Parameters{}, nil, nil, errors.New("invalid password hash parameters")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Argon2Parameters{}, nil, nil, errors.New("invalid password hash salt")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Argon2Parameters{}, nil, nil, errors.New("invalid password hash key")
	}
	parameters.SaltBytes, parameters.KeyBytes = uint32(len(salt)), uint32(len(key))
	if err := validateArgon2Parameters(parameters); err != nil {
		return Argon2Parameters{}, nil, nil, err
	}
	return parameters, salt, key, nil
}

func validateArgon2Parameters(parameters Argon2Parameters) error {
	if parameters.MemoryKiB < 8*1024 || parameters.MemoryKiB > 256*1024 || parameters.Iterations < 1 || parameters.Iterations > 10 || parameters.Parallelism < 1 || parameters.Parallelism > 8 || parameters.SaltBytes < 16 || parameters.SaltBytes > 64 || parameters.KeyBytes < 32 || parameters.KeyBytes > 64 {
		return errors.New("Argon2id parameters are outside safe supported limits")
	}
	return nil
}
