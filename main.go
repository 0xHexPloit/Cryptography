package main

import (
	"fmt"
	"cryptography/key"
	. "cryptography/algorithms"
)

func main() {
	chachaKey := key.FromHex("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649")
	nonce := uint64(4987)
	message := []byte("Hello World!")

	chacha := ChaCha8(chachaKey.Bytes(), nonce)
	ciphertext := chacha.Encrypt(message)
	fmt.Printf("%x\n", ciphertext)

	deciphertext := chacha.Decrypt(ciphertext)
	fmt.Printf("%s\n", deciphertext)
}