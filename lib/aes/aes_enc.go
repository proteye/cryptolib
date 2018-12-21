package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const BLOCK_SIZE = 32         // AES-256 encrypting
const PBKDF_ITER_COUNT = 4096 // PBKDF2 iteration count

// AES-256 encrypt with CFB mode
func Encrypt(plaintext []byte, password string, salt []byte) ([]byte, error) {
	derivedKey := deriveKey(password, salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// IV needs to be unique, but doesn't have to be secure.
	// It's common to put it at the beginning of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// AES-256 decrypt with CFB mode
func Decrypt(ciphertext []byte, password string, salt []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("cryptolib/aes: decryption error - ciphertext size is too short")
	}

	derivedKey := deriveKey(password, salt)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	// IV needs to be unique, but doesn't have to be secure.
	// It's common to put it at the beginning of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// http://www.ietf.org/rfc/rfc2898.txt
func deriveKey(password string, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, 8)
	}

	return pbkdf2.Key([]byte(password), salt, PBKDF_ITER_COUNT, BLOCK_SIZE, sha256.New)
}
