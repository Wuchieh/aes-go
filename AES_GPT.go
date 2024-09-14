package aesgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

func (a *AESOptions) applyPadding(data []byte, blockSize int) ([]byte, error) {
	switch a.Padding {
	case PKCS5Padding, PKCS7Padding:
		return applyPKCS7Padding(data, blockSize), nil
	case ZeroPadding:
		return applyZeroPadding(data, blockSize), nil
	case ISO10126:
		return applyISO10126Padding(data, blockSize), nil
	case ANSIX923:
		return applyANSIX923Padding(data, blockSize), nil
	default:
		return nil, errors.New("unsupported padding type")
	}
}

func (a *AESOptions) EncryptionGPT(content string) (string, error) {
	// Generate AES block cipher
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return "", err
	}

	// Convert content to bytes
	data := []byte(content)

	// Apply padding
	data, err = a.applyPadding(data, block.BlockSize())
	if err != nil {
		return "", err
	}

	var encrypted []byte

	// Select encryption mode
	switch a.Mode {
	case ECB:
		encrypted, err = a.ecbEncrypt(data, block)
	case CBC:
		encrypted, err = a.cbcEncrypt(data, block)
	case CFB:
		encrypted, err = a.cfbEncrypt(data, block)
	case OFB:
		encrypted, err = a.ofbEncrypt(data, block)
	default:
		return "", errors.New("unsupported AES mode")
	}

	if err != nil {
		return "", err
	}

	// Convert to the desired output format (Base64 or Hex)
	switch a.Output {
	case Base64:
		return base64.StdEncoding.EncodeToString(encrypted), nil
	case Hex:
		return hex.EncodeToString(encrypted), nil
	default:
		return "", errors.New("unsupported output format")
	}
}

func (a *AESOptions) DecryptionGPT(content string) (string, error) {
	// Decode content based on the input format
	var encrypted []byte
	var err error

	switch a.Output {
	case Base64:
		encrypted, err = base64.StdEncoding.DecodeString(content)
	case Hex:
		encrypted, err = hex.DecodeString(content)
	default:
		return "", errors.New("unsupported input format")
	}

	if err != nil {
		return "", err
	}

	// Generate AES block cipher
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return "", err
	}

	var decrypted []byte

	// Select decryption mode
	switch a.Mode {
	case ECB:
		decrypted, err = a.ecbDecrypt(encrypted, block)
	case CBC:
		decrypted, err = a.cbcDecrypt(encrypted, block)
	case CFB:
		decrypted, err = a.cfbDecrypt(encrypted, block)
	case OFB:
		decrypted, err = a.ofbDecrypt(encrypted, block)
	default:
		return "", errors.New("unsupported AES mode")
	}

	if err != nil {
		return "", err
	}

	// Remove padding
	decrypted, err = removePadding(decrypted, a.Padding)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// ECB encryption
func (a *AESOptions) ecbEncrypt(data []byte, block cipher.Block) ([]byte, error) {
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("data length must be a multiple of block size")
	}

	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Encrypt(encrypted[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}
	return encrypted, nil
}

// ECB decryption
func (a *AESOptions) ecbDecrypt(data []byte, block cipher.Block) ([]byte, error) {
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("data length must be a multiple of block size")
	}

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Decrypt(decrypted[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}
	return decrypted, nil
}

// CBC encryption
func (a *AESOptions) cbcEncrypt(data []byte, block cipher.Block) ([]byte, error) {
	if len(a.IV) != block.BlockSize() {
		return nil, errors.New("IV length must equal block size")
	}

	encrypted := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, a.IV)
	mode.CryptBlocks(encrypted, data)
	return encrypted, nil
}

// CBC decryption
func (a *AESOptions) cbcDecrypt(data []byte, block cipher.Block) ([]byte, error) {
	if len(a.IV) != block.BlockSize() {
		return nil, errors.New("IV length must equal block size")
	}

	decrypted := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, a.IV)
	mode.CryptBlocks(decrypted, data)
	return decrypted, nil
}

// CFB encryption
func (a *AESOptions) cfbEncrypt(data []byte, block cipher.Block) ([]byte, error) {
	if len(a.IV) != block.BlockSize() {
		return nil, errors.New("IV length must equal block size")
	}

	encrypted := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(block, a.IV)
	stream.XORKeyStream(encrypted, data)
	return encrypted, nil
}

// CFB decryption
func (a *AESOptions) cfbDecrypt(data []byte, block cipher.Block) ([]byte, error) {
	if len(a.IV) != block.BlockSize() {
		return nil, errors.New("IV length must equal block size")
	}

	decrypted := make([]byte, len(data))
	stream := cipher.NewCFBDecrypter(block, a.IV)
	stream.XORKeyStream(decrypted, data)
	return decrypted, nil
}

// OFB encryption/decryption
func (a *AESOptions) ofbEncrypt(data []byte, block cipher.Block) ([]byte, error) {
	return a.ofbStream(data, block)
}

func (a *AESOptions) ofbDecrypt(data []byte, block cipher.Block) ([]byte, error) {
	return a.ofbStream(data, block)
}

func (a *AESOptions) ofbStream(data []byte, block cipher.Block) ([]byte, error) {
	if len(a.IV) != block.BlockSize() {
		return nil, errors.New("IV length must equal block size")
	}

	stream := cipher.NewOFB(block, a.IV)
	processed := make([]byte, len(data))
	stream.XORKeyStream(processed, data)
	return processed, nil
}
