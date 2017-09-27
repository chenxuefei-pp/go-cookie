// Copyright 2017 The Xuefei Chen Authors. All rights reserved.
// Created on 2017/9/8 12:51
// Email chenxuefei_pp@163.com

package cookie

import (
    "fmt"
    "runtime"
    "crypto/md5"
    "crypto/aes"
    "log"
    "crypto/cipher"
    "encoding/base64"
)

type AesEncryptor struct {
    key []byte
}

func NewAesEncryptor(salt string) *AesEncryptor{
    id := fmt.Sprintf("%s;%s;%s",salt,runtime.GOARCH,runtime.GOOS)
    key := md5.Sum([]byte(id))
    return &AesEncryptor{key: key[:md5.Size]}
}

func (a* AesEncryptor) encode(val string) string {
    key := a.key
    var iv = []byte(key)[:aes.BlockSize]
    encrypted := make([]byte, len(val))
    aesBlockEncrypter, err := aes.NewCipher(key)
    if err != nil {
        log.Print("Encrypt failed!")
        return ""
    }
    aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
    aesEncrypter.XORKeyStream(encrypted, []byte(val))
    encodeString := base64.StdEncoding.EncodeToString(encrypted)
    return encodeString
}

func (a *AesEncryptor) decode(val string ) string {
    src ,err := base64.StdEncoding.DecodeString(val)
    if err != nil {
        log.Print("String is not a base64 encoding")
        return ""
    }
    defer func() {
        if e := recover(); e != nil {
            err = e.(error)
        }
    }()
    key := a.key
    var iv = []byte(key)[:aes.BlockSize]
    decrypted := make([]byte, len(src))
    var aesBlockDecrypter cipher.Block
    aesBlockDecrypter, err = aes.NewCipher([]byte(key))
    if err != nil {
        return ""
    }
    aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
    aesDecrypter.XORKeyStream(decrypted, src)
    return string(decrypted)
}