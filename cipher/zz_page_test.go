package cipher_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/Yeadear/qqdump/account"
	"github.com/Yeadear/qqdump/cipher"
)

// TestZZPageHex 打印某页指定区间的十六进制，用于人工核对 cell 内部结构。
//
//	QQDUMP_DB=... QQDUMP_UID=... QQDUMP_PAGE=114670 QQDUMP_OFF=3522 QQDUMP_LEN=96
func TestZZPageHex(t *testing.T) {
	src := os.Getenv("QQDUMP_DB")
	if src == "" {
		t.Skip("设置 QQDUMP_DB 后运行")
	}
	key := os.Getenv("QQDUMP_KEY")
	if key == "" {
		head, err := account.ParseHead(src)
		if err != nil {
			t.Fatal(err)
		}
		key = account.DeriveKey(os.Getenv("QQDUMP_UID"), head.Rand)
	}
	d, err := cipher.NewDecrypter(src, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var pg uint32
	fmt.Sscan(os.Getenv("QQDUMP_PAGE"), &pg)
	p, err := d.DecryptPage(pg)
	if err != nil {
		t.Fatal(err)
	}
	off, ln := 0, 128
	fmt.Sscan(os.Getenv("QQDUMP_OFF"), &off)
	if v := os.Getenv("QQDUMP_LEN"); v != "" {
		fmt.Sscan(v, &ln)
	}
	if off+ln > len(p) {
		ln = len(p) - off
	}
	for i := 0; i < ln; i += 16 {
		end := i + 16
		if end > ln {
			end = ln
		}
		fmt.Printf("%5d: % x\n", off+i, p[off+i:off+end])
	}
	fmt.Printf("页头: type=%#x nCells=%d contentStart=%d\n", p[0],
		int(binary.BigEndian.Uint16(p[3:5])), int(binary.BigEndian.Uint16(p[5:7])))
}
