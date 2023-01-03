package applesrp6c

import (
	"crypto/sha1"
	"crypto/sha512"
	. "main/internal/srp6cryptoparams"
	"math/big"
)

var clientId string
var pin string
var cryptoParams SRP6CryptoParams
var salt *big.Int
var pk *big.Int
var publicClient *big.Int
var secretClient *big.Int
var clientEvidence *big.Int
var proof *big.Int
var key []byte

type AppleSRP6Client struct {
}

type AppleSRP6ClientSessionImpl struct {
	clientId       string
	pin            string
	cryptoParams   SRP6CryptoParams
	salt           *big.Int
	pk             *big.Int
	publicClient   *big.Int
	secretClient   *big.Int
	clientEvidence *big.Int
	proof          *big.Int
	key            []byte
}

func (s *AppleSRP6ClientSessionImpl) NewAppleSRP6ClientSessionImpl() AppleSRP6ClientSessionImpl {
	return AppleSRP6ClientSessionImpl{}
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
	publicClient, _ = s.NewPublicClientValue()
	secretClient, _ = s.NewSecretClientValue()
	clientEvidence, _ = s.CalculateClientEvidence()
	return nil
}

func (s *AppleSRP6ClientSessionImpl) Step3(proof *big.Int) error {
	s.proof = proof
	key, _ = s.CalculateSessionKey()
	return nil
}

func (s *AppleSRP6ClientSessionImpl) PublicClientValue() []byte {
	return publicClient.Bytes()
}

func (s *AppleSRP6ClientSessionImpl) GetClientEvidenceMessage() []byte {
	return clientEvidence.Bytes()
}

func (s *AppleSRP6ClientSessionImpl) GetSessionKeyHash() []byte {
	hash := sha1.Sum(key)
	return hash[:]
}

func (s *AppleSRP6ClientSessionImpl) NewPublicClientValue() (*big.Int, error) {
	hasher := sha512.New()
	hasher.Write(salt.Bytes())
	hasher.Write([]byte(clientId))
	xH := hasher.Sum(nil)
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(cryptoParams.G, x, s.cryptoParams.N)
	return v, nil
}

func (s *AppleSRP6ClientSessionImpl) NewSecretClientValue() (*big.Int, error) {
	hasher := sha512.New()
	hasher.Write(pk.Bytes())
	hasher.Write([]byte(clientId))
	hasher.Write([]byte(pin))
	xH := hasher.Sum(nil)
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(cryptoParams.G, x, cryptoParams.N)
	return v, nil
}

func (s *AppleSRP6ClientSessionImpl) CalculateClientEvidence() (*big.Int, error) {
	hasher := sha512.New()
	hasher.Write(pk.Bytes())
	hasher.Write(publicClient.Bytes())
	hasher.Write(salt.Bytes())
	hasher.Write([]byte(clientId))
	xH := hasher.Sum(nil)
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(cryptoParams.G, x, cryptoParams.N)
	return v, nil
}

func (s *AppleSRP6ClientSessionImpl) CalculateSessionKey() ([]byte, error) {
	hasher := sha512.New()
	hasher.Write(pk.Bytes())
	hasher.Write(publicClient.Bytes())
	hasher.Write(secretClient.Bytes())
	hasher.Write(proof.Bytes())
	xH := hasher.Sum(nil)
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(cryptoParams.G, x, cryptoParams.N)
	return v.Bytes(), nil
}
