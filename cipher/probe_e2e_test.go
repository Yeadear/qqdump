package cipher

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	sqlcipher "github.com/Yeadear/sqlcipher"
)

func makeNTFile(t *testing.T, h sqlcipher.HMACAlgo, iter int) []byte {
	t.Helper()
	reserve := 16 + (func() int {
		if h == sqlcipher.HMACSHA1 {
			return 32
		}
		return 64
	}())
	page := make([]byte, 4096)
	copy(page, "SQLite format 3\x00")
	page[20] = byte(reserve)
	// page 1 必须是结构自洽的表 b-tree 页：魔数之后第 100 字节起是页头，
	// 页头后面跟 cell 指针。探测阶段就是靠这个结构区分"可用长度算错"的。
	page[100] = 0x0d // leaf table
	page[103] = 0    // nCells = 1
	page[104] = 1
	// cell 指针指向 cell 起始位置：可用区 4048/4016 都留有余量的位置。
	page[108] = 0x0e // 0x0e00 = 3584
	page[109] = 0x00
	plain := bytes.Repeat(page, 64)

	var enc bytes.Buffer
	if err := sqlcipher.EncryptFile(&enc, bytes.NewReader(plain), sqlcipher.Passphrase("probekey1234567890"), nil,
		sqlcipher.Params{PageSize: 4096, Iter: iter, HMAC: h}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return append(make([]byte, HeaderSize), enc.Bytes()...)
}

func TestDecryptNTQQFileProbe(t *testing.T) {
	cases := []struct {
		name string
		h    sqlcipher.HMACAlgo
		iter int
	}{
		{"sha512-64000", sqlcipher.HMACSHA512, 64000},
		{"sha512-256000", sqlcipher.HMACSHA512, 256000},
		{"sha1-256000", sqlcipher.HMACSHA1, 256000},
		{"sha1-4000-default", sqlcipher.HMACSHA1, 4000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nt := makeNTFile(t, c.h, c.iter)
			src := filepath.Join(t.TempDir(), "nt_msg.db")
			if err := os.WriteFile(src, nt, 0o644); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(t.TempDir(), "plain.db")
			if err := DecryptNTQQFile(src, dst, "probekey1234567890"); err != nil {
				t.Fatalf("DecryptNTQQFile failed for %s: %v", c.name, err)
			}
			got, _ := os.ReadFile(dst)
			if !bytes.Contains(got, []byte("SQLite format 3\x00")) {
				t.Fatalf("no sqlite magic for %s", c.name)
			}
			if len(got) == 0 {
				t.Fatalf("content missing for %s", c.name)
			}
		})
	}
}
