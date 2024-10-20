package aesgo

import (
	"fmt"
	"log"
)

func ExampleAESOptions_Encryption() {
	key := []byte("pwFHCqoQZGmho4w6")
	iv := []byte("EkRm7iFT261dpevs")

	aes := AESOptions{
		Mode:    CBC,
		Padding: PKCS5Padding,
		Output:  Base64,
		Key:     key,
		IV:      iv,
	}

	encryption, err := aes.Encryption("hello world")
	if err != nil {
		log.Println("Encryption error:", err)
		return
	}

	fmt.Println(encryption)

	decryption, err := aes.Decryption(encryption)
	if err != nil {
		log.Println("Decryption error:", err)
		return
	}

	fmt.Println(decryption)

	//	Output:
	//ajjTrSSO/Z11GxiPAphb7Q==
	//hello world
}
