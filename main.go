package main

import (
	"bytes"
	"cryptolib/lib/aes"
	"cryptolib/lib/rsa"
	"fmt"
)

func main() {
	// RSA
	params := rsa.KeyParams{}
	keyPair, err := rsa.GenerateKeyPair(&params)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("RSA key pair =", keyPair.PrivateKey)
	maxLen := keyPair.PublicKey.Size()
	fmt.Println("\nMax text len =", maxLen*8)

	message := []byte("Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello!!!")
	fmt.Println("\nText len =", len(message)*8)

	cipher, err := rsa.Encrypt(message, keyPair.PublicKey)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("\ncipher =", cipher)
	}

	plaintext, err := rsa.Decrypt(cipher, keyPair.PrivateKey)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("\nplaintext =", string(plaintext))
	}

	message = []byte("Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! OK!!")
	fmt.Println("\nText len =", len(message)*8)

	cipher, _ = rsa.Encrypt(message, keyPair.PublicKey)
	fmt.Println("\nRSA cipher =", cipher)

	plaintext, _ = rsa.Decrypt(cipher, keyPair.PrivateKey)
	fmt.Println("\nRSA plaintext =", string(plaintext))
	fmt.Println("\nIs messages equal?", bytes.Equal(message, plaintext))

	// AES
	password := "password!"
	salt := []byte("salt!")
	cipher, _ = aes.Encrypt(message, password, salt)
	fmt.Println("\nAES cipher =", cipher)

	plaintext, _ = aes.Decrypt(cipher, password, salt)
	fmt.Println("\nAES plaintext =", string(plaintext))
	fmt.Println("\nIs messages equal?", bytes.Equal(message, plaintext))
}
