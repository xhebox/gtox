package gtoxcrypt

/*
#include <tox/toxencryptsave.h>
*/
import "C"
import (
	"errors"
	. "github.com/xhebox/gtox/tox"
)

// ======== type and enum ==========
const (
	PASS_SALT_LENGTH = C.TOX_PASS_SALT_LENGTH
	PASS_KEY_LENGTH = C.TOX_PASS_KEY_LENGTH
	PASS_ENCRYPTION_EXTRA_LENGTH = C.TOX_PASS_ENCRYPTION_EXTRA_LENGTH
)

// main struct
type Pass_key struct {
	// private
	key *C.Tox_Pass_Key
}

var (
	ErrEncryptionKeyDerivationFailed = errors.New("the crypto lib was unable to derive a key from the given passphrase.")
	ErrKeyDerivationFailed = errors.New("the crypto lib was unable to derive a key from the given passphrase, which is usually a lack of memory issue.")
	ErrEncryptionFailed = errors.New("the encryption itself failed.")
	ErrCryptionBadFormat = errors.New("the input data is missing the magic number.")

	ErrDecryptionInvalidLength = errors.New("the input data was shorter than PASS_ENCRYPTION_EXTRA_LENGTH bytes.")
	ErrDecryptionFailed = errors.New("the encrypted byte array could not be decrypted. either the data was corrupted or the password/key was incorrect.")
)
// ================================

// =========== methods ============
// begin part 1
func Pass_encrypt(plain []byte, pass []byte) ([]byte, error) {
	var err C.TOX_ERR_ENCRYPTION = C.TOX_ERR_ENCRYPTION_OK
	cipher := make([]byte, PASS_ENCRYPTION_EXTRA_LENGTH+len(plain))

	C.tox_pass_encrypt((*C.uint8_t)(&plain[0]),
		C.size_t(len(plain)),
    (*C.uint8_t)(&pass[0]),
		C.size_t(len(pass)),
    (*C.uint8_t)(&cipher[0]),
	  &err)

	switch err {
	case C.TOX_ERR_ENCRYPTION_OK:
		return cipher, nil
	case C.TOX_ERR_ENCRYPTION_NULL:
		return cipher, ErrNull
	case C.TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED:
		return cipher, ErrKeyDerivationFailed
	case C.TOX_ERR_ENCRYPTION_FAILED:
		return cipher, ErrEncryptionFailed
	default:
		return cipher, ErrInternal
	}
}

func Pass_decrypt(cipher []byte, pass []byte) ([]byte, error) {
	var err C.TOX_ERR_DECRYPTION = C.TOX_ERR_DECRYPTION_OK
	plain := make([]byte, PASS_ENCRYPTION_EXTRA_LENGTH+len(cipher))

	r := C.tox_pass_decrypt((*C.uint8_t)(&cipher[0]),
		C.size_t(len(cipher)),
    (*C.uint8_t)(&pass[0]),
		C.size_t(len(pass)),
    (*C.uint8_t)(&plain[0]),
	  &err)

	switch err {
	case C.TOX_ERR_DECRYPTION_OK:
		if !bool(r) {
			return plain, ErrInternal
		}
		return plain, nil
	case C.TOX_ERR_DECRYPTION_NULL:
		return plain, ErrNull
	case C.TOX_ERR_DECRYPTION_INVALID_LENGTH:
		return plain, ErrDecryptionInvalidLength
	case C.TOX_ERR_DECRYPTION_BAD_FORMAT:
		return plain, ErrCryptionBadFormat
	case C.TOX_ERR_DECRYPTION_FAILED:
		return plain, ErrDecryptionFailed
	default:
		return plain, ErrInternal
	}
}

// begin part 2
func (this *Pass_key) New() error {
	this.key = C.tox_pass_key_new();
	if this.key == nil {
		return ErrMalloc
	}
	return nil
}

func (this *Pass_key) Del() {
	C.tox_pass_key_free(this.key)
}

func (this *Pass_key) Pass_key_derive(pass []byte) (bool, error) {
	var err C.TOX_ERR_KEY_DERIVATION = C.TOX_ERR_KEY_DERIVATION_OK

	r := C.tox_pass_key_derive(this.key,
    (*C.uint8_t)(&pass[0]),
		C.size_t(len(pass)),
		&err)

	switch err {
	case C.TOX_ERR_KEY_DERIVATION_OK:
		return bool(r), nil
	case C.TOX_ERR_KEY_DERIVATION_NULL:
		return bool(r), ErrNull
	case C.TOX_ERR_KEY_DERIVATION_FAILED:
		return bool(r), ErrKeyDerivationFailed
	default:
		return bool(r), ErrInternal
	}
}

func (this *Pass_key) Pass_key_derive_with_salt(pass []byte, salt [PASS_SALT_LENGTH]byte) (bool, error) {
	var err C.TOX_ERR_KEY_DERIVATION = C.TOX_ERR_KEY_DERIVATION_OK

	r := C.tox_pass_key_derive_with_salt(this.key,
    (*C.uint8_t)(&pass[0]),
		C.size_t(len(pass)),
    (*C.uint8_t)(&salt[0]),
		&err)

	switch err {
	case C.TOX_ERR_KEY_DERIVATION_OK:
		return bool(r), nil
	case C.TOX_ERR_KEY_DERIVATION_NULL:
		return bool(r), ErrNull
	case C.TOX_ERR_KEY_DERIVATION_FAILED:
		return bool(r), ErrKeyDerivationFailed
	default:
		return bool(r), ErrInternal
	}
}

func (this *Pass_key) Pass_key_encrypt(plain []byte) ([]byte, error) {
	var err C.TOX_ERR_ENCRYPTION = C.TOX_ERR_ENCRYPTION_OK
	cipher := make([]byte, PASS_ENCRYPTION_EXTRA_LENGTH+len(plain))

	C.tox_pass_key_encrypt(this.key,
		(*C.uint8_t)(&plain[0]),
		C.size_t(len(plain)),
    (*C.uint8_t)(&cipher[0]),
	  &err)

	switch err {
	case C.TOX_ERR_ENCRYPTION_OK:
		return cipher, nil
	case C.TOX_ERR_ENCRYPTION_NULL:
		return cipher, ErrNull
	case C.TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED:
		return cipher, ErrKeyDerivationFailed
	case C.TOX_ERR_ENCRYPTION_FAILED:
		return cipher, ErrEncryptionFailed
	default:
		return cipher, ErrInternal
	}
}

func (this *Pass_key) Pass_key_decrypt(cipher []byte) ([]byte, error) {
	var err C.TOX_ERR_DECRYPTION = C.TOX_ERR_DECRYPTION_OK
	plain := make([]byte, PASS_ENCRYPTION_EXTRA_LENGTH+len(cipher))

	C.tox_pass_key_decrypt(this.key,
		(*C.uint8_t)(&cipher[0]),
		C.size_t(len(cipher)),
    (*C.uint8_t)(&plain[0]),
	  &err)

	switch err {
	case C.TOX_ERR_DECRYPTION_OK:
		return plain, nil
	case C.TOX_ERR_DECRYPTION_NULL:
		return plain, ErrNull
	case C.TOX_ERR_DECRYPTION_INVALID_LENGTH:
		return plain, ErrDecryptionInvalidLength
	case C.TOX_ERR_DECRYPTION_BAD_FORMAT:
		return plain, ErrCryptionBadFormat
	case C.TOX_ERR_DECRYPTION_FAILED:
		return plain, ErrDecryptionFailed
	default:
		return plain, ErrInternal
	}
}

func Salt(cipher []byte) ([PASS_SALT_LENGTH]byte, error) {
	var err C.TOX_ERR_GET_SALT = C.TOX_ERR_GET_SALT_OK
	var salt [PASS_SALT_LENGTH]byte

	C.tox_get_salt((*C.uint8_t)(&cipher[0]),
		(*C.uint8_t)(&salt[0]),
		&err)

	switch err {
	case C.TOX_ERR_GET_SALT_OK:
		return salt, nil
	case C.TOX_ERR_GET_SALT_NULL:
		return salt, ErrNull
	case C.TOX_ERR_GET_SALT_BAD_FORMAT:
		return salt, ErrCryptionBadFormat
	default:
		return salt, ErrInternal
	}
}

func Is_data_encrypted(data []byte) bool {
	return bool(C.tox_is_data_encrypted((*C.uint8_t)(&data[0])))
}
// ================================
