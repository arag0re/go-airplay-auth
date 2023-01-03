package srp6cryptoparams

import (
	"crypto/rand"
	"math/big"
)

type SRP6CryptoParams struct {
	G, N *big.Int
}

func (p SRP6CryptoParams) GetInstance(bitLength int, hashAlgorithm string) SRP6CryptoParams {
	p.G = big.NewInt(7) 
	p.N, _ = rand.Prime(rand.Reader, bitLength)
	return p
}