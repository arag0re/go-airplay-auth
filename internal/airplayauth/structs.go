package airplayauth

import (
	"encoding/xml"

	"maze.io/x/crypto/x25519"
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