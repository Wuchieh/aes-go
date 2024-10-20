package aesgo

type EncryptionMode string

// AES modes
const (
	ECB EncryptionMode = "ecb"
	CBC EncryptionMode = "cbc"
	CFB EncryptionMode = "cfb"
	OFB EncryptionMode = "ofb"
)

type PaddingMode string

// Padding types
const (
	PKCS5Padding PaddingMode = "pkcs5"
	PKCS7Padding PaddingMode = "pkcs7"
	ZeroPadding  PaddingMode = "zero"
	ISO10126     PaddingMode = "iso10126"
	ANSIX923     PaddingMode = "ansix923"
)

type OutputFormat string

// Output formats
const (
	Base64 OutputFormat = "base64"
	Hex    OutputFormat = "hex"
)
