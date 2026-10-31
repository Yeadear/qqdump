package db

import (
	"encoding/binary"
	"fmt"
	"io"
)

// DebugMaster 打印 sqlite_master 的解析详情，用于排查真实库的 b-tree 结构。
// 只在诊断命令里使用，不参与正常导出。
//
// 注意：page 1 既可能是 leaf 也可能是 interior，两者的页头长度不同
// （leaf 8 字节，interior 12 字节——多一个最右子页指针），cell 指针起始位置
// 也因此不同。这里按实际页类型分派，避免用错偏移读出垃圾。
func (s *StreamDB) DebugMaster(w io.Writer) error {
	fmt.Fprintf(w, "pageSize=%d usable=%d reserve=%d pages=%d\n",
		s.pageSize, s.usable, s.pageSize-s.usable, s.pages)
	p1, err := s.dec.DecryptPage(1)
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(p1[103:105]))
	fmt.Fprintf(w, "page1 magic=%q type=%#x ncell=%d\n", string(p1[:16]), p1[100], n)
	switch p1[100] {
	case 0x0d:
		fmt.Fprintf(w, "  page1 是 leaf 页，cell 指针从 108 开始\n")
		s.dumpCellPtrs(w, p1, 100, n, false)
	case 0x05:
		fmt.Fprintf(w, "  page1 是 interior 页，cell 指针从 112 开始，右子页=%d\n",
			binary.BigEndian.Uint32(p1[108:112]))
		s.dumpCellPtrs(w, p1, 100, n, true)
	default:
		fmt.Fprintf(w, "  page1 类型异常\n")
	}

	for name, ti := range s.tables {
		fmt.Fprintf(w, "\n表 %s rootpage=%d cols=%d\n", name, ti.rootpage, len(ti.cols))
		s.dumpTree(w, ti.rootpage, 2)
	}
	return nil
}

// dumpCellPtrs 按页类型打印 cell 指针与解析结果。
func (s *StreamDB) dumpCellPtrs(w io.Writer, content []byte, hdr, nCells int, interior bool) {
	base := hdr + 8
	if interior {
		base = hdr + 12
	}
	for i := 0; i < nCells && i < 20; i++ {
		off := base + 2*i
		if off+2 > len(content) {
			fmt.Fprintf(w, "  cell%d 指针位越界\n", i)
			return
		}
		ptr := int(binary.BigEndian.Uint16(content[off : off+2]))
		if ptr < hdr || ptr >= len(content) {
			fmt.Fprintf(w, "  cell%d ptr=%d 越界\n", i, ptr)
			continue
		}
		if interior {
			if ptr+4 > len(content) {
				fmt.Fprintf(w, "  cell%d ptr=%d interior cell 越界\n", i, ptr)
				continue
			}
			child := binary.BigEndian.Uint32(content[ptr : ptr+4])
			fmt.Fprintf(w, "  cell%d ptr=%d child=%d %s\n", i, ptr, child,
				validMark(s.validPage(child)))
			continue
		}
		s.dumpLeafCell(w, i, ptr, content)
	}
}

func validMark(ok bool) string {
	if ok {
		return "ok"
	}
	return "越界!"
}

// dumpLeafCell 解析一个 leaf cell 并打印其 record 内容。
func (s *StreamDB) dumpLeafCell(w io.Writer, i, ptr int, content []byte) {
	plen, n1, err := readVarint(content[ptr:], 0)
	if err != nil {
		fmt.Fprintf(w, "  cell%d ptr=%d 读 payload 长度失败: %v\n", i, ptr, err)
		return
	}
	rowid, n2, err := readVarint(content[ptr:], n1)
	if err != nil {
		fmt.Fprintf(w, "  cell%d ptr=%d 读 rowid 失败: %v\n", i, ptr, err)
		return
	}
	fmt.Fprintf(w, "  cell%d ptr=%d plen=%d rowid=%d bodyAvail=%d\n",
		i, ptr, plen, rowid, len(content)-ptr-n1-n2)
	payload, perr := s.localPayload(content[ptr+n1+n2:], int(plen))
	if perr != nil {
		fmt.Fprintf(w, "    localPayload 失败: %v\n", perr)
		return
	}
	cols, cerr := parseRecord(payload)
	if cerr != nil {
		fmt.Fprintf(w, "    parseRecord 失败: %v\n", cerr)
		return
	}
	for j, c := range cols {
		str := fmt.Sprintf("%v", c)
		if len(str) > 60 {
			str = str[:60] + "..."
		}
		if b, ok := c.([]byte); ok {
			str = fmt.Sprintf("<blob %d>", len(b))
		}
		fmt.Fprintf(w, "    col%d(%T)=%s\n", j, c, str)
	}
}

// dumpTree 遍历一棵表 b-tree，统计页类型/页数并抽样打印 cell，用于确认
// 指针是否被正确解读（正常情况下所有子页号都应落在 1..pages 之间）。
func (s *StreamDB) dumpTree(w io.Writer, root uint32, sample int) {
	type stat struct {
		leafPages, interiorPages, cells, badPtr int
	}
	st := stat{}
	visited := 0
	shown := 0
	q := []uint32{root}
	seen := map[uint32]bool{}
	for len(q) > 0 {
		pgno := q[0]
		q = q[1:]
		if seen[pgno] {
			continue // 防环：指针读坏时可能出现自指
		}
		seen[pgno] = true
		content, err := s.dec.DecryptPage(pgno)
		if err != nil {
			fmt.Fprintf(w, "    页 %d 解密失败: %v\n", pgno, err)
			continue
		}
		visited++
		hdr := 0
		if pgno == 1 {
			hdr = 100
		}
		if len(content) < hdr+8 {
			continue
		}
		nc := int(binary.BigEndian.Uint16(content[hdr+3 : hdr+5]))
		st.cells += nc
		switch content[hdr] {
		case 0x0d:
			st.leafPages++
			if shown < sample {
				s.dumpCellPtrs(w, content, hdr, nc, false)
				shown++
			}
		case 0x05:
			st.interiorPages++
			base := hdr + 12
			if base+2*nc > len(content) {
				fmt.Fprintf(w, "    页 %d interior 头越界（ncell=%d）\n", pgno, nc)
				continue
			}
			for i := 0; i < nc; i++ {
				ptr := int(binary.BigEndian.Uint16(content[base+2*i : base+2*i+2]))
				if ptr < hdr || ptr+4 > len(content) {
					st.badPtr++
					continue
				}
				child := binary.BigEndian.Uint32(content[ptr : ptr+4])
				if !s.validPage(child) {
					st.badPtr++
					fmt.Fprintf(w, "    页 %d cell%d child=%d 越界\n", pgno, i, child)
					continue
				}
				q = append(q, child)
			}
			if rp := binary.BigEndian.Uint32(content[hdr+8 : hdr+12]); s.validPage(rp) {
				q = append(q, rp)
			} else {
				st.badPtr++
				fmt.Fprintf(w, "    页 %d 右子页=%d 越界\n", pgno, rp)
			}
		default:
			fmt.Fprintf(w, "    页 %d 类型 %#x 不是表页\n", pgno, content[hdr])
		}
	}
	fmt.Fprintf(w, "  统计: 访问 %d 页（leaf %d / interior %d），%d 个 cell，坏指针 %d\n",
		visited, st.leafPages, st.interiorPages, st.cells, st.badPtr)
}
