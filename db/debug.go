package db

import (
	"fmt"
	"io"
)

// DebugMaster 打印 sqlite_master 的解析详情，用于排查真实库的 b-tree 结构。
// 只在诊断命令里使用，不参与正常导出。
func (s *StreamDB) DebugMaster(w io.Writer) error {
	fmt.Fprintf(w, "pageSize=%d usable=%d reserve=%d\n", s.pageSize, s.usable, s.pageSize-s.usable)
	p1, err := s.dec.DecryptPage(1)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "page1 magic=%q type=%#x ncell=%d\n", string(p1[:16]), p1[100],
		int(p1[103])<<8|int(p1[104]))
	n := int(p1[103])<<8 | int(p1[104])
	for i := 0; i < n && i < 20; i++ {
		off := 108 + 2*i
		ptr := int(p1[off])<<8 | int(p1[off+1])
		if ptr < 100 || ptr >= len(p1) {
			fmt.Fprintf(w, "  cell%d ptr=%d 越界\n", i, ptr)
			continue
		}
		plen, n1, _ := readVarint(p1[ptr:], 0)
		rowid, n2, _ := readVarint(p1[ptr:], n1)
		fmt.Fprintf(w, "  cell%d ptr=%d plen=%d rowid=%d bodyAvail=%d\n",
			i, ptr, plen, rowid, len(p1)-ptr-n1-n2)
		payload, perr := s.localPayload(p1[ptr+n1+n2:], int(plen))
		if perr != nil {
			fmt.Fprintf(w, "    localPayload 失败: %v\n", perr)
			continue
		}
		cols, cerr := parseRecord(payload)
		if cerr != nil {
			fmt.Fprintf(w, "    parseRecord 失败: %v\n", cerr)
			continue
		}
		for j, c := range cols {
			str := fmt.Sprintf("%v", c)
			if len(str) > 50 {
				str = str[:50] + "..."
			}
			if b, ok := c.([]byte); ok {
				str = fmt.Sprintf("<blob %d>", len(b))
			}
			fmt.Fprintf(w, "    col%d(%T)=%s\n", j, c, str)
		}
	}
	fmt.Fprintf(w, "探测到的表: %v\n", s.tables)
	for name, ti := range s.tables {
		fmt.Fprintf(w, "  %s rootpage=%d cols=%d\n", name, ti.rootpage, len(ti.cols))
	}
	return nil
}
