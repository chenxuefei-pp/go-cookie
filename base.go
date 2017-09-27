// Copyright 2017 The Xuefei Chen Authors. All rights reserved.
// Created on 2017/9/8 12:48
// Email chenxuefei_pp@163.com

package cookie

type Encryptor interface {
    encode(string)  string
    decode(string)  string
}
