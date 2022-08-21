package key

import (
	"encoding/hex"
	"math/rand"
)

type key struct {
	key_bytes []byte
}

func GenerateRandomKey(numberBytes uint16) *key {
	key_bytes := make([]byte, numberBytes)
	_, err := rand.Read(key_bytes)
	if err != nil {
		panic(err)
	}
	return &key{key_bytes}
}

func FromHex(hex_string string) *key {
	key_bytes, err := hex.DecodeString(hex_string)
	if err != nil {
		panic(err)
	}
	return &key{key_bytes}
}

func (k *key) Bytes() []byte {
	return k.key_bytes
}

func (k *key) Hex() string {
	return hex.EncodeToString(k.key_bytes)
}