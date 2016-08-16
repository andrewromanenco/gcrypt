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
	if password == "" {
		return nil, nil, errors.New("Empty pass")
	}
	salt, err := generateSalt(defaultKeyLen)
	if err != nil {
		return nil, nil, err
	}
	// params as recommended
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, defaultKeyLen)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func generateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
