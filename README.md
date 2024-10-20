# aes-go

english | [中文](README_TW.md)

golang AES encryption/decryption package

## Encryption Mode

* ecb
* cbc
* cfb
* ofb

## Padding Type

* pkcs5
* pkcs7
* zero
* iso10126
* ansix923

## Example

```go
package main

import (
    "github.com/wuchieh/aes-go"
)

func main(){
    key := []byte("pwFHCqoQZGmho4w6")
    iv := []byte("EkRm7iFT261dpevs")
    
    aes := aesgo.AESOptions{
        Mode:    aesgo.PKCS5Padding,
        Padding: aesgo.CBC,
        Output:  aesgo.Base64,
        Key:     key,
        IV:      iv,
    }
    
    encryption, err := aesgo.Encryption("hello world")
    if err != nil {
        log.Println("Encryption error:", err)
        return
    }
    
    decryption, err := aesgo.Decryption(encryption)
    if err != nil {
        log.Println("Decryption error:", err)
        return
    }
}
```
