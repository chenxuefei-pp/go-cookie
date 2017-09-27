// Copyright 2017 The Xuefei Chen Authors. All rights reserved.
// Created on 2017/9/8 12:54
// Email chenxuefei_pp@163.com

package cookie

import (
    "testing"
)


func TestAesEncryptor(t * testing.T){
    encryptor := NewAesEncryptor("SALT")
    src := "Testing me"
    enby := encryptor.encode(src)
    val := encryptor.decode(enby)
    if val != src {
        t.Fatal("Testing fatal!")
    }
}