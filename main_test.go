package main

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/yeka/zip"
)

func decrypt_sample(filename string) []byte {
	var buf []byte
	r, err := zip.OpenReader(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword("infected")
		}

		r, err := f.Open()
		if err != nil {
			fmt.Println(err)
		}

		buf, err = ioutil.ReadAll(r)
		if err != nil {
			fmt.Println(err)
		}
		defer r.Close()
	}
	return buf
}

func Testdecrypt_sample(t *testing.T) { // 测试函数名必须以Test开头，必须接收一个*testing.T类型参数
	buf := decrypt_sample("./samples/320a5f715aa5724c21013fc14bfe0a10893ce9723ebc25d9ae9f06f5517795d4.zip")
	got := beacon_config(buf) // 程序输出的结果
	if got["Watermark_Hash"] != "xi1knfb/QiftN2EAhdtcyw==" && got["Retry_Max_Attempts"] != "0" && got["Retry_Increase_Attempts"] != "0" && got["Retry_Duration"] != "0" {
		t.Errorf(got["Watermark_Hash"] + "\n" + got["Retry_Max_Attempts"] + "\n" + got["Retry_Increase_Attempts"] + "\n" + got["Retry_Duration"])
	}
}
