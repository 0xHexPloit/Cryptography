package key

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomKey(t *testing.T) {
	keyLength := uint16(16)
	key := GenerateRandomKey(keyLength)
	assert.Equal(t, int(keyLength), len(key.Bytes()), "Key length should be equal to 16")
}

func TestFromHex(t *testing.T) {
	hex := "ff4216"
	key := FromHex(hex)
	assert.Equal(t, int(len(hex)/2), len(key.Bytes()), "Key length should be equal to 4")
}

func TestBytes(t *testing.T) {
	hex := "ff4216"
	key := FromHex(hex)
	bytes := key.Bytes()

	assert.Equal(t, byte(255), bytes[0], "First byte should be equal to 0xff")
}

func TestHex(t *testing.T) {
	hex := "ff4216"
	key := FromHex(hex)
	assert.Equal(t, hex, key.Hex(), "Hex should be equal to ff4216")
}