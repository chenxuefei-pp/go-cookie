// Copyright 2017 The Xuefei Chen Authors. All rights reserved.
// Created on 2017/9/7 15:24
// Email chenxuefei_pp@163.com

package cookie

import (
   "testing"
   "net/http"
)

func TestSqliteJar(t *testing.T) {
   jar := NewSqliteJar("F:\\Workplace\\test.sqlite3")
   client := http.Client{
      Jar: jar,
   }
   client.Get("http://www.baidu.com")
}