package main

import (
	"crypto/sha1"
	"math/big"

)

type AppleSRP6ClientSessionImpl struct {
	clientId      string
	pin           string
	cryptoParams  SRP6CryptoParams
	salt          *big.Int
	pk            *big.Int
	publicClient  *big.Int
	secretClient  *big.Int
	clientEvidence *big.Int
	proof         *big.Int
	key           []byte
}

func (s *AppleSRP6ClientSessionImpl) Step1(clientId string, pin string) error {
	s.clientId = clientId
	s.pin = pin
	return nil
}

func (s *AppleSRP6ClientSessionImpl) Step2(cryptoParams SRP6CryptoParams, salt *big.Int, pk *big.Int) error {
	s.cryptoParams = cryptoParams
	s.salt = salt
	s.pk = pk

	s.publicClient = srp6.NewPublicClientValue(s.cryptoParams, s.salt, s.clientId, s.pin)
	s.secretClient = srp6.NewSecretClientValue(s.cryptoParams, s.salt, s.clientId, s.pin)
	s.clientEvidence = srp6.CalculateClientEvidence(s.cryptoParams, s.pk, s.publicClient, s.salt, s.clientId)
	return nil
}

func (s *AppleSRP6ClientSessionImpl) Step3(proof *big.Int) error {
	s.proof = proof
	s.key = srp6.CalculateSessionKey(s.cryptoParams, s.pk, s.publicClient, s.secretClient, s.proof)
	return nil
}

func (s *AppleSRP6ClientSessionImpl) GetPublicClientValue() *big.Int {
	return s.publicClient
}

func (s *AppleSRP6ClientSessionImpl) GetClientEvidenceMessage() *big.Int {
	return s.clientEvidence
}

func (s *AppleSRP6ClientSessionImpl) GetSessionKeyHash() []byte {
	hash := sha1.Sum(s.key)
	return hash[:]
}
