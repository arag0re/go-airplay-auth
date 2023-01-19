package airplayauth

import (
	"encoding/xml"

	"maze.io/x/crypto/x25519"
)

type PairingState uint8

const (
	PairingStateM1 PairingState = 0x01
	PairingStateM2 PairingState = 0x02
	PairingStateM3 PairingState = 0x03
	PairingStateM4 PairingState = 0x04
	PairingStateM5 PairingState = 0x05
	PairingStateM6 PairingState = 0x06
)

type PairingMethod uint8

const (
	PairingMethodPairSetup         PairingMethod = 0x00
	PairingMethodPairSetupWithAuth PairingMethod = 0x01
	PairingMethodPairVerify        PairingMethod = 0x02
	PairingMethodAddPairing        PairingMethod = 0x03
	PairingMethodRemovePairing     PairingMethod = 0x04
	PairingMethodListPairings      PairingMethod = 0x05
)

type PairSetupPin1Response struct {
	Pk   []byte
	Salt []byte
}
type PairSetupPin2Response struct {
	Proof []byte
}

type PairSetupPin3Response struct {
	Epk     []byte
	AuthTag []byte
}

type PrivateKey struct {
	PublicKey x25519.PublicKey
	b         []byte
}
type Plist struct {
	XMLName xml.Name `xml:"plist"`
	Dict    Dict     `xml:"dict"`
}
type Dict struct {
	Key   string   `xml:"key"`
	Array []string `xml:"array>string"`
}
