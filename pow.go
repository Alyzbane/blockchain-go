package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
)

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// Arbitrary target bit for hash function of POW
// Target < 256 bits in memory
const targetBits = 16

// Define the ProofOfWork datas'
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

// Convert the block data into byte for hashing the POW
// HashCash = data + nonce
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.HashTransactions(),
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)

	return data
}

// Performing the mining operation in blockchain w/ POW
func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	// 1 byte = 8 bits
	// ... 32 byte * 8 = 256 (SHA256) fixed size
	var hash [32]byte
	nonce := 0
	// Counter the overflow
	maxNonce := math.MaxInt64

	//	fmt.Printf("Mining the block containing \"%s\"\n", pow.block.)
	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		fmt.Printf("\r%x", hash)
		// Convert the Hash into Big Integer
		hashInt.SetBytes(hash[:])
		//		fmt.Printf("\rHashInt: %s", &hashInt)

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}

	fmt.Print("\n\n")

	return nonce, hash[:]
}

func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}
