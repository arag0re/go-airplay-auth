package tlv8

type TLV8Tag uint8

const (
	TLV8TagMethod TLV8Tag = iota
	TLV8TagIdentifier
	TLV8TagSalt
	TLV8TagPublicKey
	TLV8TagProof
	TLV8TagEncryptedData
	TLV8TagState
	TLV8TagError
	TLV8TagRetryDelay
	TLV8TagCertificate
	TLV8TagSignature
	TLV8TagPermissions
	TLV8TagFragmentData
	TLV8TagFragmentLast
	TLV8TagFlags     TLV8Tag = 19
	TLV8TagSeparator TLV8Tag = 255
)

type TLV8Item struct {
	Tag   TLV8Tag
	Value []byte
}

func NewTLV8Item(tag TLV8Tag, value []byte) TLV8Item {
	return TLV8Item{
		Tag:   tag,
		Value: value,
	}
}
