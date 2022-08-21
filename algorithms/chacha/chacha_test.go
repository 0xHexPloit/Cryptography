package chacha

import (
	// "fmt"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	// "unsafe"
	// "github.com/stretchr/testify/assert"
)

func uint32ToBytes(value uint32) [4]byte {
	bytes := [4]byte{}
	bytes[0] = byte(value >> 24)
	bytes[1] = byte(value >> 16)
	bytes[2] = byte(value >> 8)
	bytes[3] = byte(value)
	return bytes
}

func TestGenerateMatrix(t *testing.T) {
	key := 10
	key_bytes := [32]byte{}
	key_bytes[31] = byte(key)
	nonce := uint64(1024)
	blockNumber := 1

	matrix := generateMatrix(
		key_bytes[:],
		nonce,
		uint64(blockNumber),
	)

	// Checking ChaCha constants
	assert.Equal(t, fmt.Sprintf("%s", uint32ToBytes(matrix[0][0])), "expa", "the first constant should be expa")
	assert.Equal(t, fmt.Sprintf("%s", uint32ToBytes(matrix[0][1])), "nd 3", "the second constant should be nd 3")
	assert.Equal(t, fmt.Sprintf("%s", uint32ToBytes(matrix[0][2])), "2-by", "the third constant should be 2-by")
	assert.Equal(t, fmt.Sprintf("%s", uint32ToBytes(matrix[0][3])), "te k", "the fourth constant should be te k")

	// Checking key
	for i := 0; i < 7; i++ {
		row := int(i / 4)
		col := i % 4
		assert.Equal(t, matrix[row + 1][col], uint32(0), "the cell should equal zero")
	}
	assert.Equal(t, matrix[2][3], uint32(key), "the cell should equal to 10")

	// Checking block number
	assert.Equal(t, matrix[3][0], uint32(0), "the cell should equal zero")
	assert.Equal(t, matrix[3][1], uint32(1), "the cell should equal one")

	// Checking nonce
	assert.Equal(t, matrix[3][2], uint32(0), "the cell should equal zero")
	assert.Equal(t, matrix[3][3], uint32(1024), "the cell should equal 1024")
}

func TestGetUint32FromBytes(t *testing.T) {
	bytes := [4]byte{}
	bytes[0] = byte(0x12)
	bytes[1] = byte(0x34)
	bytes[2] = byte(0x56)
	bytes[3] = byte(0x78)
	assert.Equal(t, getUint32FromBytes(bytes[:]), uint32(0x12345678), "the value should be 0x12345678")
}

func TestGetUint32FromBytesPanicCase(t *testing.T) {
	bytes := [3]byte{}
	bytes[0] = byte(0x12)
	bytes[1] = byte(0x34)
	bytes[2] = byte(0x56)
	assert.Panics(t, func() { getUint32FromBytes(bytes[:]) }, "the function should panic")
}


func TestByteCyclingShift(t *testing.T) {
	
}