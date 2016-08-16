package gcrypt

import (
	"errors"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

// appendHMAC appends 32 bytes to data. Returns nil if no data is provided.
func appendHMAC(key, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	macProducer := hmac.New(sha256.New, key)
	macProducer.Write(data)
	mac := macProducer.Sum(nil)
	return append(data, mac...)
}

// validateHMAC checks mac, and returns original data without mac bytes.
// Returns nil, if mac is not valid.
func validateHMAC(key, data []byte) []byte {
	if len(data) <= 32 {
		return nil
	}
	message := data[:len(data)-32]
	mac := data[len(data)-32:]
	macProducer := hmac.New(sha256.New, key)
	macProducer.Write(message)
	calculatedMac := macProducer.Sum(nil)
	if calculatedMac == nil {
		return nil
	}
	for i := 0; i < 32; i++ {
		if mac[i] != calculatedMac[i] {
			return nil
		}
	}
	return message
}
