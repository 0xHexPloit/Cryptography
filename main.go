package main

import (
	"fmt"
	_ "cryptography/key"
	. "cryptography/algorithms/chacha"
)

func main() {
	chachaKey := [32]byte{}
	chachaKey[31] = byte(10)
	nonce := uint64(4987)

	fmt.Printf("%x\n", nonce)

	message := []byte("Hello World!")

	chacha := ChaCha8(chachaKey[:], nonce)
	ciphertext := chacha.Encrypt(message)
	fmt.Printf("%x\n", ciphertext)

	deciphertext := chacha.Decrypt(ciphertext)
	fmt.Printf("%s\n", deciphertext)
}