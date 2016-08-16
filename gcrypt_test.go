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

func TestDerivateKeyWithSaltFailsOnEmptyPassword(t *testing.T) {
	_, err := DerivateKey256WithSalt("", []byte("12345678901234567890123456789012"))
	if err == nil {
		t.Error("Must fail on empty password")
	}
}

func TestDerivateKeyWithSaltFailsOnEmptySalt(t *testing.T) {
	_, err := DerivateKey256WithSalt("password", nil)
	if err == nil {
		t.Error("Must fail on no salt")
	}
}

func TestDerivateKeyWithSaltFailsOnWrongSizeSalt(t *testing.T) {
	_, err := DerivateKey256WithSalt("password", []byte("too-short"))
	if err == nil {
		t.Error("Must fail on salt with wrong size")
	}
}

func TestDerivateKeyWithSaltReturns256BitKey(t *testing.T) {
	key, err := DerivateKey256WithSalt("password", []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Error("Must not return any errors")
	}
	if len(key) != 32 {
		t.Error("Must return 256 bit key")
	}
}

func TestDerivateKeyWithSaltReturnsSameKey(t *testing.T) {
	key1, _ := DerivateKey256WithSalt("password", []byte("12345678901234567890123456789012"))
	key2, _ := DerivateKey256WithSalt("password", []byte("12345678901234567890123456789012"))
	if !reflect.DeepEqual(key1, key2) {
		t.Error("Must return same key for same pwd and salt")
	}
}

func TestAppendHMACFailsOnNilInput(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	result := appendHMAC(key, nil)
	if result != nil {
		t.Error("Must return nil if input is nil")
	}
}

func TestAppendHMACFailsOn0Input(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	result := appendHMAC(key, []byte(""))
	if result != nil {
		t.Error("Must return nil if input is empty")
	}
}

func TestAppendHMACIncreasesDataLen(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("some-data")
	result := appendHMAC(key, data)
	if len(data)+32 != len(result) {
		t.Error("Result must be longer by 32 bytes of hmac")
	}
}

func TestValidateHMACWorksForValidData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("some-data")
	withHmac := appendHMAC(key, data)
	result := validateHMAC(key, withHmac)
	if !reflect.DeepEqual(data, result) {
		t.Error("MAC validation failed")
	}
}

func TestValidateHMACFailsIfDataIsModified(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("some-data")
	withHmac := appendHMAC(key, data)
	withHmac[2] = 99
	result := validateHMAC(key, withHmac)
	if result != nil {
		t.Error("MAC must fail with modified data")
	}
}

func TestEncryptFailsForNilKey(t *testing.T) {
	_, err := Encrypt(nil, []byte("data"))
	if err == nil {
		t.Error("Must fail if key is nil")
	}
}

func TestEncryptFailsForKeyIsNot32Bytes(t *testing.T) {
	_, err := Encrypt([]byte("not-long-enough"), []byte("data"))
	if err == nil {
		t.Error("Must fail if key is nil")
	}
}

func TestEncryptFailsForNilData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	_, err := Encrypt(key, nil)
	if err == nil {
		t.Error("Must fail if data is nil")
	}
}

func TestEncryptFailsForEmptyData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	_, err := Encrypt(key, []byte(""))
	if err == nil {
		t.Error("Must fail if data is empty")
	}
}

func TestEncryptWorksWithValidInput(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("some-data")
	encrypted, err := Encrypt(key, data)
	if err != nil {
		t.Error("Must not fail")
	}
	if len(encrypted) == 0 {
		t.Error("Encrypted result must not be empty")
	}
}

func TestDecryptFailsForNilKey(t *testing.T) {
	_, err := Decrypt(nil, []byte("data"))
	if err == nil {
		t.Error("Must fail if key is nil")
	}
}

func TestDecryptFailsForKeyIsNot32Bytes(t *testing.T) {
	_, err := Decrypt([]byte("not-long-enough"), []byte("data"))
	if err == nil {
		t.Error("Must fail if key is nil")
	}
}

func TestDecryptFailsForNilData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	_, err := Decrypt(key, nil)
	if err == nil {
		t.Error("Must fail if data is nil")
	}
}

func TestDecryptFailsForEmptyData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	_, err := Decrypt(key, []byte(""))
	if err == nil {
		t.Error("Must fail if data is empty")
	}
}

func TestDecryptWorksWithValidInput(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("some-data")
	encrypted, _ := Encrypt(key, data)
	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Error("Valid encrypted message should not fail")
	}
	if !reflect.DeepEqual(data, decrypted) {
		t.Error("Decrypted data must be the same as original data")
	}
}

func TestDecryptFailsWithWrongKey(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	key2 := []byte("abc45678901234567890123456789012")
	data := []byte("some-data")
	encrypted, _ := Encrypt(key, data)
	_, err := Decrypt(key2, encrypted)
	if err == nil {
		t.Error("Must fail with invalid key")
	}
}

func TestConfirmEncryptHasRandomizedOutput(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("some-data")
	encrypted1, _ := Encrypt(key, data)
	encrypted2, _ := Encrypt(key, data)
	if reflect.DeepEqual(encrypted1, encrypted2) {
		t.Error("Result must be different for every encrypt run")
	}
}
