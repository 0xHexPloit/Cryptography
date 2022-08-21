package algorithms

type chachaCore struct {
	key                []byte
	nonce              uint64
	numberRound        uint8
	initial_matrix     [4][4]uint32
	transformed_matrix [4][4]uint32
}

// generateNewChachaCore permits to generate a new chachaCore instance.
// The algorithm is based on the ChaCha algorithm that uses a 256-bit key and a 64-bit nonce
// (some algorithms use a 96-bit nonce). 
// The number of rounds is set to 20 for the ChaCha20 algorithm and 8 for the ChaCha8 algorithm.
func generateNewChachaCore(key []byte, nonce uint64, numberRound uint8) *chachaCore {
	if len(key) != 32 {
		panic("key length must be 32")
	}
	initialBlockNumber := uint64(1)
	matrix := generateMatrix(key, nonce, initialBlockNumber)
	return &chachaCore{key, nonce, numberRound, matrix, matrix}
}

// ChaCha8 creates a new instance of the ChaCha8 algorithm.
func ChaCha8(key []byte, nonce uint64) *chachaCore {
	return generateNewChachaCore(key, nonce, 8)
}

// ChaCha20 creates a new instance of the ChaCha20 algorithm.
func ChaCha20(key []byte, nonce uint64) *chachaCore {
	return generateNewChachaCore(key, nonce, 20)
}

// getUint32FromBytes converts a slice of bytes to a uint32.
// We assume that the length of the slice is 4.
func getUint32FromBytes(bytes []byte) uint32 {
	if len(bytes) != 4 {
		panic("bytes length must be 4")
	}

	// Big endian format
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

// getConstantValue pemits to get the uint32 value of a constant used
// in the ChaCha algorithm.
func getConstantValue(constant string) uint32 {
	bytes := []byte(constant)
	return getUint32FromBytes(bytes)
}

// As the name suggests, this function produces the initial matrix
// of the ChaCha algorithm.
func generateMatrix(key []byte, nonce uint64, blockNumber uint64) [4][4]uint32 {
	matrix := [4][4]uint32{}

	matrix[0][0] = getConstantValue("expa")
	matrix[0][1] = getConstantValue("nd 3")
	matrix[0][2] = getConstantValue("2-by")
	matrix[0][3] = getConstantValue("te k")

	matrix[1][0] = getUint32FromBytes(key[0:4])
	matrix[1][1] = getUint32FromBytes(key[4:8])
	matrix[1][2] = getUint32FromBytes(key[8:12])
	matrix[1][3] = getUint32FromBytes(key[12:16])

	matrix[2][0] = getUint32FromBytes(key[16:20])
	matrix[2][1] = getUint32FromBytes(key[20:24])
	matrix[2][2] = getUint32FromBytes(key[24:28])
	matrix[2][3] = getUint32FromBytes(key[28:32])

	matrix[3][0] = uint32(blockNumber >> 32)
	matrix[3][1] = uint32(blockNumber)
	matrix[3][2] = uint32(nonce >> 32)
	matrix[3][3] = uint32(nonce)

	return matrix
}

// byteCyclingShift permits to shift a byte to the left by a 
// given number of bits in a cyclic fashion.
func byteCyclingShift(byteValue byte, numberBitsToShift uint) byte {
	numberBitsToShift %= 8
	return byteValue<<numberBitsToShift | byteValue>>(8-numberBitsToShift)
}

// This functions performs the quarter round operation of the 
// ChaCha algorithm.
func apply_quarter_round(aValue *uint32, bValue *uint32, cValue *uint32, dValue *uint32) {
	*aValue += *bValue
	*dValue ^= *aValue
	*dValue = uint32(byteCyclingShift(byte(*dValue), 16))
	*cValue += *dValue
	*bValue ^= *cValue
	*bValue = uint32(byteCyclingShift(byte(*bValue), 12))
	*aValue += *bValue
	*dValue ^= *aValue
	*dValue = uint32(byteCyclingShift(byte(*dValue), 8))
	*cValue += *dValue
	*bValue ^= *cValue
	*bValue = uint32(byteCyclingShift(byte(*bValue), 7))
}

// getChaChaBlock permits to obtain the matrix that is used
// in the ChaCha algorithm to encrypt a message given a block number. As a remainder,
// a matrix can only produce 32 * 16 bytes of output.
func (c *chachaCore) getChaChaBlock() [4][4]uint32 {
	c.transformed_matrix = c.initial_matrix
	for i := 1; uint8(i) <= c.numberRound; i += 2 {
		// Odd Round
		// First column
		apply_quarter_round(
			&c.transformed_matrix[0][0],
			&c.transformed_matrix[1][0],
			&c.transformed_matrix[2][0],
			&c.transformed_matrix[3][0],
		)
		// Second column
		apply_quarter_round(
			&c.transformed_matrix[0][1],
			&c.transformed_matrix[1][1],
			&c.transformed_matrix[2][1],
			&c.transformed_matrix[3][1],
		)
		// Third column
		apply_quarter_round(
			&c.transformed_matrix[0][2],
			&c.transformed_matrix[1][2],
			&c.transformed_matrix[2][2],
			&c.transformed_matrix[3][2],
		)
		// Fourth column
		apply_quarter_round(
			&c.transformed_matrix[0][3],
			&c.transformed_matrix[1][3],
			&c.transformed_matrix[2][3],
			&c.transformed_matrix[3][3],
		)
	}

	// Even Round
	// First Diagonal
	apply_quarter_round(
		&c.transformed_matrix[0][0],
		&c.transformed_matrix[1][1],
		&c.transformed_matrix[2][2],
		&c.transformed_matrix[3][3],
	)
	// Second Diagonal
	apply_quarter_round(
		&c.transformed_matrix[0][1],
		&c.transformed_matrix[1][2],
		&c.transformed_matrix[2][3],
		&c.transformed_matrix[3][0],
	)
	// Third Diagonal
	apply_quarter_round(
		&c.transformed_matrix[0][2],
		&c.transformed_matrix[1][3],
		&c.transformed_matrix[2][0],
		&c.transformed_matrix[3][1],
	)
	// Fourth Diagonal
	apply_quarter_round(
		&c.transformed_matrix[0][3],
		&c.transformed_matrix[1][0],
		&c.transformed_matrix[2][1],
		&c.transformed_matrix[3][2],
	)

	for i := 0; i < 16; i++ {
		row := uint(i / 4)
		column := uint(i % 4)
		c.transformed_matrix[row][column] += c.initial_matrix[row][column]
	}

	return c.transformed_matrix
}

// generateKeyStream generates the keystream (the bytes used to encrypt
// the message) for a given block number
func (c *chachaCore) generateKeyStream(numberBytesToGenerate uint) <-chan byte {
	ch := make(chan uint8)
	blockNumber := 1
	go func() {
		defer close(ch)
		chachaBlock := c.getChaChaBlock()
		numberBytesStreamed := 0

		for {
			for i := 0; i < 16; i++ {
				matrixCell := chachaBlock[uint(i/4)][uint(i%4)]
				for j := 0; j < 4; j++ {
					if numberBytesStreamed == int(numberBytesToGenerate) {
						return
					}
					ch <- byte(matrixCell>>uint32(24-8*j)) & 0xFF
					numberBytesStreamed++
				}

			}

			blockNumber++
			c.initial_matrix[3][0] = uint32(blockNumber >> 32)
			c.initial_matrix[3][1] = uint32(blockNumber)
			chachaBlock = c.getChaChaBlock()
		}

	}()
	return ch
}

// getOutputMessageFrom encapsulates the logic used by both the Encrypt and Decrypt functions.
func (c *chachaCore) getOutputMessageFrom(message []byte) []byte {
	output := []byte{}
	keyStreamGeneratorChannel := c.generateKeyStream(uint(len(message)))

	index := 0

	for byte := range keyStreamGeneratorChannel {
		output = append(output, message[index]^byte)
		index++
	}

	return output
}

// Encrypt encrypts a message using one of the ChaCha encryption algorithms.
func (c *chachaCore) Encrypt(plaintext []byte) []byte {
	return c.getOutputMessageFrom(plaintext)
}

// Decrypt decrypts a message using one of the ChaCha encryption algorithms.
func (c *chachaCore) Decrypt(ciphertext []byte) []byte {
	return c.getOutputMessageFrom(ciphertext)
}
