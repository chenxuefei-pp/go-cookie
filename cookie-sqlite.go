// Copyright 2017 The Xuefei Chen Authors. All rights reserved.
// Created on 2017/9/7 12:09
// Email chenxuefei_pp@163.com

package cookie

import (
    _ "github.com/mattn/go-sqlite3"
    "database/sql"
    "os"
    "fmt"
    "net/url"
    "net/http"
    "time"
    "strings"
    "net/http/cookiejar"
    "math/rand"
    "log"
)

type SqliteJar struct {
    jar    *cookiejar.Jar
    encry  Encryptor
    conn   *sql.DB
}

func NewSqliteJar(dbname string) (*SqliteJar) {
    salt := func(_len int) string {
        str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        bytes := []byte(str)
        result := []byte{}
        r := rand.New(rand.NewSource(time.Now().UnixNano()))
        for i := 0; i < _len; i++ {
            result = append(result, bytes[r.Intn(len(bytes))])
        }
        return string(result)
    }

    if dbname == "" {
        curPath, _ := os.Getwd()
        dbname = fmt.Sprintf("%s/cookies", curPath)
        log.Printf("Sqlite3 filename not be set! Set default : %s", dbname)
    }
    _, err := os.Stat(dbname)

    jar, _ := cookiejar.New(nil)
    if err == nil {
        conn, err := sql.Open("sqlite3", dbname)
        if err != nil {
            log.Printf("Open sqlite3 database failed! %s", err)
        }
        re, err := conn.Query(`SELECT value from meta WHERE key="s"`)
        defer re.Close()

        if err != nil {
            log.Printf("Faild load database s! %s", err)
        }
        var s string
        rs := re.Next()
        if !rs {
            log.Printf("Faild load database s!")
        }
        err = re.Scan(&s)
        if err != nil {
            log.Printf("Faild load database s!")
        }

        return &SqliteJar{
            jar:   jar,
            encry: NewAesEncryptor(s),
            conn:  conn,
        }
    } else if os.IsNotExist(err) {
        conn, err := sql.Open("sqlite3", dbname)
        if err != nil {
            log.Printf("Open sqlite3 database failed! %s", err)
        }
        ct_sql := `PRAGMA foreign_keys
                    = OFF;
                    DROP TABLE IF EXISTS "main"."cookies";
                    CREATE TABLE cookies
                    (
                        creation_utc INTEGER NOT NULL UNIQUE PRIMARY KEY,
                        host_key TEXT NOT NULL,
                        name TEXT NOT NULL,
                        value TEXT NOT NULL,
                        path TEXT NOT NULL,
                        expires_utc INTEGER NOT NULL,
                        secure INTEGER NOT NULL,
                        httponly INTEGER NOT NULL,
                        has_expires INTEGER NOT NULL DEFAULT 1,
                        persistent INTEGER NOT NULL DEFAULT 1,
                        priority INTEGER NOT NULL DEFAULT 1,
                        encrypted_value BLOB DEFAULT '',
                        firstpartyonly INTEGER NOT NULL DEFAULT 0
                    );
                    DROP TABLE IF EXISTS "main"."meta";
                    CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
                    CREATE INDEX "main"."domain"
                    ON "cookies"
                    ("host_key" ASC);`

        _, err = conn.Exec(ct_sql)

        if err != nil {
            log.Printf("Create table error! %s", err.Error())
        }
        s := salt(32)
        _, err = conn.Exec("INSERT INTO meta(key,value) VALUES('s',?)", s)

        if err != nil {
            log.Printf("Failed write to database! %s", err.Error())
        }

        return &SqliteJar{
            jar:   jar,
            encry: NewAesEncryptor(s),
            conn:  conn,
        }
    } else {
        log.Printf("Unresolved fatal %s", err)
    }
    return nil
}

func (j *SqliteJar) saveCookies(u *url.URL, cookies []*http.Cookie) {
    if cookies == nil {
        return
    }
    log.Print("Save cookies to database")
    delete_query := `
      DELETE FROM cookies
      WHERE host_key=? AND name=?;
    `
    insert_query := `
      INSERT INTO cookies (
      creation_utc,
      host_key,
      name,
      value,
      encrypted_value,
      path,
      expires_utc,
      secure,
      httponly)
      VALUES(?,?,?,?,?,?,?,?,?)`

    delete_smt, err := j.conn.Prepare(delete_query)
    if err != nil {
        log.Printf("Create delete prepare err : %s", err)
    }
    insert_smt, err := j.conn.Prepare(insert_query)
    if err != nil {
        log.Printf("Create insert prepare err : %s", err)
    }

    defer delete_smt.Close()
    defer insert_smt.Close()

    for _, cookie := range cookies {
        secure, httponly := 0, 0
        if cookie.Secure {
            secure = 1
        }
        if cookie.HttpOnly {
            httponly = 1
        }
        _, err = delete_smt.Exec(
            cookie.Domain,
            cookie.Name,
        )
        if err != nil {
            log.Printf("Exec sql %s error : %s", delete_query, err)
        }

        if j.encry == nil {
            _, err = insert_smt.Exec(
                time.Now().UnixNano(),
                cookie.Domain,
                cookie.Name,
                cookie.Value,
                "",
                cookie.Path,
                cookie.Expires.UnixNano(),
                secure,
                httponly,
            )
        } else {
            _, err = insert_smt.Exec(
                time.Now().UnixNano(),
                cookie.Domain,
                cookie.Name,
                "",
                j.encry.encode(cookie.Value),
                cookie.Path,
                cookie.Expires.UnixNano(),
                secure,
                httponly,
            )
        }
        if err != nil {
            log.Printf("Exec sql %s error : %s", insert_query, err)
        }
    }
    j.jar.SetCookies(u, cookies)
}

func (j *SqliteJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
    j.saveCookies(u, cookies)
}

func (j *SqliteJar) domainKey(u *url.URL) string {
    i := strings.LastIndex(u.Host, ".")
    prevDot := strings.LastIndex(u.Host[:i-1], ".")
    return u.Host[prevDot:]
}

func (j *SqliteJar) loadCookies(u *url.URL) ([]*http.Cookie) {
    memcokies := j.jar.Cookies(u)
    if memcokies != nil {
        return memcokies
    }
    domain := j.domainKey(u)
    query := `
    SELECT
      host_key,
      name,
      value,
      encrypted_value,
      path,
      expires_utc,
      secure,
      httponly FROM cookies WHERE host_key = "%s"
    `
    result, err := j.conn.Query(fmt.Sprintf(query, domain))
    defer result.Close()
    if err != nil {
        log.Printf("Load cookies from database failed : %s", err)
    }
    cookies := make([]*http.Cookie, 0)
    for result.Next() {
        cookie := http.Cookie{}
        var expires int64
        secure, httponly := 0, 0
        var value, encry_value string

        err = result.Scan(
            &cookie.Domain,
            &cookie.Name,
            &value,
            &encry_value,
            &cookie.Path,
            &expires,
            &secure,
            &httponly,
        )
        if j.encry == nil {
            cookie.Value = value
        } else {
            cookie.Value = j.encry.decode(encry_value)
        }
        cookie.Expires = time.Unix(expires/1e9, expires%1e9)
        cookie.Secure = !(secure == 0)
        cookie.HttpOnly = !(httponly == 0)
        cookies = append(cookies, &cookie)
    }
    j.jar.SetCookies(u, cookies)
    return cookies
}

func (j *SqliteJar) Cookies(u *url.URL) ([]*http.Cookie) {
    return j.loadCookies(u)
}
