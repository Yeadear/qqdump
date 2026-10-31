package cipher_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/Yeadear/qqdump/account"
	"github.com/Yeadear/qqdump/cipher"
)

// TestZZPageLayout 打印某页的页头与 cell 指针布局，用于判断可用长度是否算对。
// QQDUMP_DB=... QQDUMP_UID=... QQDUMP_PAGE=114670 go test ./cipher -run ZZPageLayout -v
func TestZZPageLayout(t *testing.T) {
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
	if pg == 0 {
		t.Skip("设置 QQDUMP_PAGE 后运行")
	}
	p, err := d.DecryptPage(pg)
	if err != nil {
		t.Fatal(err)
	}
	hdr := 0
	nCells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
	fmt.Printf("页 %d: type=%#x nCells=%d 可用=%d len=%d\n", pg, p[hdr], nCells, d.UsableSize(), len(p))
	fmt.Printf("页头 20 字节: % x\n", p[hdr:hdr+20])
	for i := 0; i < nCells && i < 8; i++ {
		off := hdr + 8 + 2*i
		ptr := int(binary.BigEndian.Uint16(p[off : off+2]))
		var cellLen int
		if i+1 < nCells {
			nx := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
			cellLen = ptr - nx
		} else {
			cellLen = d.UsableSize() - ptr
		}
		fmt.Printf("  cell%d ptr=%d 与前cell间距=%d\n", i, ptr, cellLen)
		if ptr < len(p) {
			plen, n1, _ := readVarintLocal(p[ptr:], 0)
			fmt.Printf("    plen=%d varintLen=%d 首字节=% x\n", plen, n1, p[ptr:ptr+min(8, len(p)-ptr)])
		}
	}
	fmt.Printf("尾部 32 字节: % x\n", p[len(p)-32:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func readVarintLocal(b []byte, off int) (uint64, int, error) {
	var v uint64
	for i := 0; i < 9; i++ {
		if off+i >= len(b) {
			return 0, 0, fmt.Errorf("越界")
		}
		c := b[off+i]
		if i == 8 {
			v = (v << 8) | uint64(c)
		} else {
			v = (v << 7) | uint64(c&0x7f)
		}
		if i < 8 && c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return v, 9, nil
}
