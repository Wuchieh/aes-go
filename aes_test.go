package aesgo

import "testing"

func TestAES(t *testing.T) {
	mode := []EncryptionMode{ECB, CBC, CFB, OFB}
	paddingType := []PaddingMode{PKCS5Padding, PKCS7Padding, ZeroPadding, ISO10126, ANSIX923}
	outputFormat := []OutputFormat{Base64, Hex}
	key := []byte("pwFHCqoQZGmho4w6")
	iv := []byte("EkRm7iFT261dpevs")
	content := "hello world"

	for _, formatType := range outputFormat {
		for _, paddingType_ := range paddingType {
			for _, mode_ := range mode {
				aes := AESOptions{
					Mode:    mode_,
					Padding: paddingType_,
					Output:  formatType,
					Key:     key,
					IV:      iv,
				}

				encryption, err := aes.Encryption(content)
				if err != nil {
					t.Fatal("Encryption error",
						formatType,
						paddingType_,
						mode_,
						err)
					return
				}

				t.Log(formatType,
					paddingType_,
					mode_,
					encryption)

				encryptionGPT, err := aes.EncryptionGPT(content)
				if err != nil {
					t.Fatal("Encryption error",
						formatType,
						paddingType_,
						mode_,
						err)
					return
				}

				if encryption != encryptionGPT && paddingType_ != ISO10126 {
					t.Log("加密結果不一致",
						formatType,
						paddingType_,
						mode_,
						encryption,
						encryptionGPT)
				}

				decryption, err := aes.Decryption(encryption)
				if err != nil {
					t.Fatal("Decryption error",
						formatType,
						paddingType_,
						mode_,
						err)
					return
				}

				decryptionGPT, err := aes.DecryptionGPT(encryptionGPT)
				if err != nil {
					t.Fatal("Decryption error",
						formatType,
						paddingType_,
						mode_,
						err)
					return
				}

				if decryption != content {
					t.Fatal("Decrypted string does not match",
						formatType,
						paddingType_,
						mode_)
				}

				if decryptionGPT != content {
					t.Fatal("GPT Decrypted string does not match",
						formatType,
						paddingType_,
						mode_)
				}

			}
		}
	}
}
