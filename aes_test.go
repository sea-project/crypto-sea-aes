package aes

import (
	"testing"
)

// 例举CBC模式用法，其他类似
func TestAesEncryptToBase64(t *testing.T) {
	data, err := AesECBEncryptToBase64("123", "1234567891234567")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(data)

	data, err = AesECBDecryptFromBase64(data, "1234567891234567")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(data)
}
