# aes-go

[english](README.md) | 中文

golang AES 加解密包

## 加密模式

* ecb
* cbc
* cfb
* ofb

## 填充模式

* pkcs5
* pkcs7
* zero
* iso10126
* ansix923

## 範例

```go
package main

import (
    "github.com/wuchieh/aes-go"
)

func main(){
	key := []byte("pwFHCqoQZGmho4w6")
	iv := []byte("EkRm7iFT261dpevs")

	aes := aesgo.AESOptions{
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
}
```
