package db

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ScanCells 逐个 leaf cell 试解析，把出错的 cell 现场打印出来，用于定位
// 真实库里的解析边界问题。它和 DebugMaster 不同：不做抽样，遍历整棵树，
// 只报告错误（正常 cell 不打印），因此输出量与库的损坏程度成正比。
func (s *StreamDB) ScanCells(w io.Writer, table string) error {
	ti, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("db: 未知表 %s", table)
	}
	var leafPages, cells, badLocal, badRecord int
	q := []uint32{ti.rootpage}
	seen := map[uint32]bool{}
	for len(q) > 0 {
		pgno := q[0]
		q = q[1:]
		if seen[pgno] {
			continue
		}
		seen[pgno] = true
		content, err := s.dec.DecryptPage(pgno)
		if err != nil {
			continue
		}
		hdr := 0
		if pgno == 1 {
			hdr = 100
		}
		if len(content) < hdr+8 {
			continue
		}
		nc := int(binary.BigEndian.Uint16(content[hdr+3 : hdr+5]))
		switch content[hdr] {
		case 0x05:
			base := hdr + 12
			if base+2*nc > len(content) {
				continue
			}
			for i := 0; i < nc; i++ {
				ptr := int(binary.BigEndian.Uint16(content[base+2*i : base+2*i+2]))
				if ptr < hdr || ptr+4 > len(content) {
					continue
				}
				if c := binary.BigEndian.Uint32(content[ptr : ptr+4]); s.validPage(c) {
					q = append(q, c)
				}
			}
			if rp := binary.BigEndian.Uint32(content[hdr+8 : hdr+12]); s.validPage(rp) {
				q = append(q, rp)
			}
		case 0x0d:
			leafPages++
			base := hdr + 8
			if base+2*nc > len(content) {
				continue
			}
			for i := 0; i < nc; i++ {
				ptr := int(binary.BigEndian.Uint16(content[base+2*i : base+2*i+2]))
				if ptr < hdr || ptr >= len(content) {
					continue
				}
				cells++
				plen, n1, err := readVarint(content[ptr:], 0)
				if err != nil {
					continue
				}
				rowid, n2, err := readVarint(content[ptr:], n1)
				if err != nil {
					continue
				}
				body := content[ptr+n1+n2:]
				payload, lerr := s.localPayload(body, int(plen))
				if lerr != nil {
					badLocal++
					if badLocal <= 10 {
						fmt.Fprintf(w, "页 %d cell%d rowid=%d plen=%d bodylen=%d → %v\n",
							pgno, i, rowid, plen, len(body), lerr)
					}
					continue
				}
				if _, rerr := parseRecord(payload); rerr != nil {
					badRecord++
					if badRecord <= 10 {
						fmt.Fprintf(w, "页 %d cell%d rowid=%d plen=%d → record: %v\n",
							pgno, i, rowid, plen, rerr)
					}
				}
			}
		}
	}
	fmt.Fprintf(w, "表 %s: leaf %d 页 / %d 个 cell，payload 失败 %d，record 失败 %d\n",
		table, leafPages, cells, badLocal, badRecord)
	return nil
}
