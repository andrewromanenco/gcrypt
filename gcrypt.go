package gcrypt

import (
	"errors"

	"crypto/rand"
	"golang.org/x/crypto/scrypt"
)

const defaultKeyLen = 32

// DerivateKey256 creates 256 bit key based on a password. Random salt is
// returned with the key.
func DerivateKey256(password string) ([]byte, []byte, error) {
	salt, err := generateSalt(defaultKeyLen)
	if err != nil {
		return nil, nil, err
	}
	key, err := DerivateKey256WithSalt(password, salt)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

// DerivateKey256WithSalt creates 256 bit key from provided password and salt.
func DerivateKey256WithSalt(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("Empty pass")
	}
	if salt == nil || len(salt) != 32 {
		return nil, errors.New("Salt is not 256 bit")
	}
	// Recommended settings for scrypt
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, defaultKeyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
