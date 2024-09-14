package aesgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// Padding types
const (
	PKCS5Padding = "pkcs5"
	PKCS7Padding = "pkcs7"
	ZeroPadding  = "zero"
	ISO10126     = "iso10126"
	ANSIX923     = "ansix923"
)

// AES modes
const (
	ECB = "ecb"
	CBC = "cbc"
	CFB = "cfb"
	OFB = "ofb"
)

// Output formats
const (
	Base64 = "base64"
	Hex    = "hex"
)

// AESOptions Encryption options structure
type AESOptions struct {
	Mode    string
	Padding string
	Output  string
	Key     []byte
	IV      []byte
}

// PKCS5/PKCS7 padding
func applyPKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Zero padding
func applyZeroPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{0}, padding)...)
}

// ISO10126 padding
func applyISO10126Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding-1)
	_, _ = io.ReadFull(rand.Reader, padText)
	return append(data, append(padText, byte(padding))...)
}

// ANSI X9.23 padding
func applyANSIX923Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := append(bytes.Repeat([]byte{0}, padding-1), byte(padding))
	return append(data, padText...)
}

// Removes padding after decryption
func removePadding(data []byte, paddingType string) ([]byte, error) {
	length := len(data)
	switch paddingType {
	case PKCS5Padding, PKCS7Padding:
		padding := int(data[length-1])
		return data[:length-padding], nil
	case ZeroPadding:
		return bytes.TrimRight(data, "\x00"), nil
	case ISO10126, ANSIX923:
		padding := int(data[length-1])
		return data[:length-padding], nil
	default:
		return nil, errors.New("unsupported padding type")
	}
}

func (a *AESOptions) Encryption(content string) (string, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(content)
	blockSize := block.BlockSize()

	// Apply padding
	switch a.Padding {
	case PKCS5Padding, PKCS7Padding:
		plaintext = applyPKCS7Padding(plaintext, blockSize)
	case ZeroPadding:
		plaintext = applyZeroPadding(plaintext, blockSize)
	case ISO10126:
		plaintext = applyISO10126Padding(plaintext, blockSize)
	case ANSIX923:
		plaintext = applyANSIX923Padding(plaintext, blockSize)
	default:
		return "", errors.New("unsupported padding type")
	}

	ciphertext := make([]byte, len(plaintext))

	switch a.Mode {
	case ECB:
		for bs, be := 0, blockSize; bs < len(plaintext); bs, be = bs+blockSize, be+blockSize {
			block.Encrypt(ciphertext[bs:be], plaintext[bs:be])
		}
	case CBC:
		mode := cipher.NewCBCEncrypter(block, a.IV)
		mode.CryptBlocks(ciphertext, plaintext)
	case CFB:
		mode := cipher.NewCFBEncrypter(block, a.IV)
		mode.XORKeyStream(ciphertext, plaintext)
	case OFB:
		mode := cipher.NewOFB(block, a.IV)
		mode.XORKeyStream(ciphertext, plaintext)
	default:
		return "", errors.New("unsupported encryption mode")
	}

	var result string
	switch a.Output {
	case Base64:
		result = base64.StdEncoding.EncodeToString(ciphertext)
	case Hex:
		result = hex.EncodeToString(ciphertext)
	default:
		return "", errors.New("unsupported output format")
	}

	return result, nil
}

func (a *AESOptions) Decryption(content string) (string, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return "", err
	}

	var ciphertext []byte
	switch a.Output {
	case Base64:
		ciphertext, err = base64.StdEncoding.DecodeString(content)
	case Hex:
		ciphertext, err = hex.DecodeString(content)
	default:
		return "", errors.New("unsupported input format")
	}
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertext))

	switch a.Mode {
	case ECB:
		blockSize := block.BlockSize()
		for bs, be := 0, blockSize; bs < len(ciphertext); bs, be = bs+blockSize, be+blockSize {
			block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
		}
	case CBC:
		mode := cipher.NewCBCDecrypter(block, a.IV)
		mode.CryptBlocks(plaintext, ciphertext)
	case CFB:
		mode := cipher.NewCFBDecrypter(block, a.IV)
		mode.XORKeyStream(plaintext, ciphertext)
	case OFB:
		mode := cipher.NewOFB(block, a.IV)
		mode.XORKeyStream(plaintext, ciphertext)
	default:
		return "", errors.New("unsupported decryption mode")
	}

	// Remove padding
	plaintext, err = removePadding(plaintext, a.Padding)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
