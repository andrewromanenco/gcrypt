package gcrypt

import (
	"reflect"
	"testing"
)

func TestDerivateKeyFailsIfPwdIsEmpty(t *testing.T) {
	_, _, err := DerivateKey256("")
	if err == nil {
		t.Error("Must fail for empty password")
	}
}

func TestDerivateKeyDoesNotFailIfPwdIsAString(t *testing.T) {
	key, salt, err := DerivateKey256("password")
	if err != nil {
		t.Error("Must not fail if password is not empty")
	}
	if key == nil {
		t.Error("Must return non nil key")
	}
	if salt == nil {
		t.Error("Must return non nil salt")
	}
}

func TestDerivateKeyReturns256KeyAndSalt(t *testing.T) {
	key, salt, _ := DerivateKey256("password")
	if len(key) != 32 {
		t.Error("Key size is not 256 bits")
	}
	if len(salt) != 32 {
		t.Error("Salt size is not 32 bits")
	}
}

func TestDerivateKeyReturnsDifferentKeySaltWhenCalledTwice(t *testing.T) {
	key1, salt1, _ := DerivateKey256("password")
	key2, salt2, _ := DerivateKey256("password")
	if reflect.DeepEqual(key1, key2) {
		t.Error("Key must be different for each call")
	}
	if reflect.DeepEqual(salt1, salt2) {
		t.Error("Salt must be different for each call")
	}
}
