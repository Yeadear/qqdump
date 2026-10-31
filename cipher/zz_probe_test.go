package cipher

import (
	"fmt"
	"io"
	"os"
	"testing"
)

// TestZZHeaderReserve 打印解密后 page 1 文件头里声明的页大小与 reserve，
// 用于核对代码假设的 4096/48 是否与真实库一致。需要本地有库时手动跑：
//
//	QQDUMP_DB=/path/nt_msg.db QQDUMP_UID=u_xxx go test ./cipher -run ZZHeaderReserve -v
func TestZZHeaderReserve(t *testing.T) {
	src := os.Getenv("QQDUMP_DB")
	if src == "" {
		t.Skip("设置 QQDUMP_DB 后运行")
	}
	d, err := NewDecrypter(src, os.Getenv("QQDUMP_UID"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p1, err := d.DecryptPage(1)
	if err != nil {
		t.Fatal(err)
	}
	sz := int(p1[16])<<8 | int(p1[17])
	fmt.Printf("文件头声明 pageSize=%d，代码用 %d；reserve 字节(20)=%d，代码用 %d；页数=%d\n",
		sz, d.PageSize(), p1[20], d.PageSize()-d.UsableSize(), d.PageCount())
	_ = io.EOF
}
