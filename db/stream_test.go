package db

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"testing"

	"github.com/Yeadear/qqdump/model"
)

// 这些单测覆盖流式解析器里最容易写错的纯函数：变长整数、record 反序列化、
// CREATE TABLE 列名提取。b-tree 遍历与 overflow 链由真机库端到端验证。

func TestReadVarint(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x01}, 1, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x81, 0x00}, 128, 2},
		{[]byte{0x82, 0x01}, 257, 2},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 1<<64 - 1, 9},
	}
	for _, c := range cases {
		got, n, err := readVarint(c.in, 0)
		if err != nil {
			t.Fatalf("readVarint(%v) 报错: %v", c.in, err)
		}
		if got != c.want || n != c.n {
			t.Errorf("readVarint(%v) = %d/%d, want %d/%d", c.in, got, n, c.want, c.n)
		}
	}
}

func TestParseRecord(t *testing.T) {
	// 列：int64(123) | text "hi" | blob{1,2,3} | NULL
	// serial types: 1, 17(=13+2*2), 18(=12+2*3), 0
	// header = [hdrLen=5, 0x01, 0x11, 0x12, 0x00]
	payload := []byte{
		0x05, 0x01, 0x11, 0x12, 0x00,
		0x7b,     // 123 as int8
		'h', 'i', // text "hi"
		0x01, 0x02, 0x03, // blob
	}
	cols, err := parseRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 4 {
		t.Fatalf("列数 = %d, want 4", len(cols))
	}
	if v, ok := cols[0].(int64); !ok || v != 123 {
		t.Errorf("col0 = %v, want 123", cols[0])
	}
	if v, ok := cols[1].(string); !ok || v != "hi" {
		t.Errorf("col1 = %v, want hi", cols[1])
	}
	if v, ok := cols[2].([]byte); !ok || !bytes.Equal(v, []byte{1, 2, 3}) {
		t.Errorf("col2 = %v, want [1 2 3]", cols[2])
	}
	if cols[3] != nil {
		t.Errorf("col3 = %v, want nil", cols[3])
	}
}

func TestParseColumnNames(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{
			`CREATE TABLE c2c_msg_table (40001 INTEGER, 40002 TEXT, "40800" BLOB)`,
			[]string{"40001", "40002", "40800"},
		},
		{
			`CREATE TABLE t (40001, 40002, CONSTRAINT pk PRIMARY KEY(40001))`,
			[]string{"40001", "40002"},
		},
		{
			`CREATE TABLE t (40001 INTEGER PRIMARY KEY, 40002 TEXT, 40010 INT UNIQUE)`,
			[]string{"40001", "40002", "40010"},
		},
	}
	for _, c := range cases {
		got := parseColumnNames(c.sql)
		if len(got) != len(c.want) {
			t.Errorf("parseColumnNames(%q) = %v, want %v", c.sql, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("parseColumnNames(%q)[%d] = %q, want %q", c.sql, i, got[i], c.want[i])
			}
		}
	}
}

// fakeReader 用内存页模拟 DecryptPage，便于单测 b-tree 遍历与排序。
type fakeReader struct {
	pages  map[uint32][]byte
	usable int
}

func (f *fakeReader) UsableSize() int { return f.usable }
func (f *fakeReader) Close() error    { return nil }
func (f *fakeReader) DecryptPage(pgno uint32) ([]byte, error) {
	p, ok := f.pages[pgno]
	if !ok {
		return nil, errors.New("no page")
	}
	return p, nil
}

// encVarint 编码 SQLite 变长整数。
func encVarint(v uint64) []byte {
	if v <= 0x7f {
		return []byte{byte(v)}
	}
	var tmp [9]byte
	n := 0
	for {
		tmp[n] = byte(v & 0x7f)
		v >>= 7
		n++
		if v == 0 {
			break
		}
	}
	out := make([]byte, 0, n)
	for i := n - 1; i >= 0; i-- {
		b := tmp[i]
		if i != 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

// makeRecord 造一条 record：两列，text 与 int。
func makeRecord(s string, n int64) []byte {
	// header: [hdrLen, serial(text), serial(int4)]  两个 serial 各 1 字节
	body := append([]byte(nil), s...)
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], uint32(n))
	body = append(body, ib[:]...)
	// header 总长 = 自身 1 字节 + 两个 serial type 各 1 字节
	hdr := []byte{0x03, byte(13 + 2*len(s)), 0x04}
	return append(hdr, body...)
}

// buildLeafPage 造一个只含 leaf cell 的表页，返回页内容。
// hdr 是页头偏移（page 1 为 100，其余为 0）。
func buildLeafPage(usable int, hdr int, recs [][]byte) []byte {
	page := make([]byte, usable)
	page[hdr] = 0x0d // leaf table
	cellPtrs := make([]uint16, len(recs))
	// 从页尾向前依次摆放，按倒序遍历以保证每个 cell 各占一段不重叠的区域。
	off := usable
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		cell := append(encVarint(uint64(len(r))), encVarint(uint64(i+1))...)
		cell = append(cell, r...)
		off -= len(cell)
		copy(page[off:], cell)
		cellPtrs[i] = uint16(off)
	}
	binary.BigEndian.PutUint16(page[hdr+3:], uint16(len(recs)))
	for i, p := range cellPtrs {
		binary.BigEndian.PutUint16(page[hdr+8+2*i:], p)
	}
	return page
}

func TestStreamSortWindow(t *testing.T) {
	// 物理顺序与时间序故意错开：时间 30,10,20
	tss := []int64{30, 10, 20}
	var recs [][]byte
	for i, ts := range tss {
		recs = append(recs, makeRecord("m"+strconv.Itoa(i), ts))
	}
	usable := 512
	page := buildLeafPage(usable, 0, recs)
	// page 1 在真实库里带着 SQLite 文件头（100 字节），这里只需让它通过魔数检查。
	p1 := make([]byte, usable)
	copy(p1, "SQLite format 3\x00")
	p1[100] = 0x0d

	fr := &fakeReader{pages: map[uint32][]byte{1: p1, 2: page}, usable: usable}
	// 表结构：只有 40050（时间戳）。cols 用一个不存在的列名，靠 readOrder 映射。
	s := &StreamDB{
		dec:    fr,
		usable: usable,
		tables: map[string]tableInfo{
			TableC2C: {name: TableC2C, rootpage: 2, cols: []string{ColID, ColTimestamp}, chatType: model.ChatC2C},
		},
	}

	var got []int64
	err := s.StreamSessionMessagesWindow(TableC2C, 0, Filter{}, 2, func(m model.Message) error {
		got = append(got, m.Timestamp)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("读到 %d 条, want 3", len(got))
	}
	// 窗口 2：前两条按时间排好后回调，第三条在结尾补上
	want := []int64{10, 30, 20}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("窗口排序结果 = %v, want %v", got, want)
		}
	}
}

// TestLocalPayloadOverflow 验证超过本地容量的 payload 能顺着 overflow 链拼回。
// 这是 sqlite_master 里建表 SQL 的实际形态（NTQQ 的建表语句很长）。
func TestLocalPayloadOverflow(t *testing.T) {
	U := 512
	s := &StreamDB{usable: U}

	maxLocal := U - 35
	minLocal := (U-12)*32/255 - 23
	// 故意造一个必须走 overflow 的 payload
	plen := maxLocal*2 + 100
	orig := make([]byte, plen)
	for i := range orig {
		orig[i] = byte(i % 251)
	}
	local := minLocal + (plen-minLocal)%(U-4)
	if local > maxLocal {
		local = minLocal
	}
	if local >= plen || local > maxLocal {
		t.Fatalf("测试构造有误：local=%d plen=%d maxLocal=%d", local, plen, maxLocal)
	}

	// 把 payload 切成 local + 若干 overflow 页
	rest := orig[local:]
	cellBody := append([]byte(nil), orig[:local]...)

	pages := map[uint32][]byte{}
	var pgno uint32 = 10
	first := pgno
	for len(rest) > 0 {
		page := make([]byte, U)
		n := U - 4
		if len(rest) < n {
			n = len(rest)
		}
		if len(rest) > n {
			binary.BigEndian.PutUint32(page[0:4], pgno+1)
		}
		copy(page[4:], rest[:n])
		pages[pgno] = page
		rest = rest[n:]
		pgno++
	}
	var pb [4]byte
	binary.BigEndian.PutUint32(pb[:], first)
	cellBody = append(cellBody, pb[:]...)

	s.dec = &fakeReader{pages: pages, usable: U}
	got, err := s.localPayload(cellBody, plen)
	if err != nil {
		t.Fatalf("localPayload: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("overflow 拼接结果不一致：got %d 字节, want %d", len(got), len(orig))
	}
}

// TestLeafCellOffsets 校验 page 1 的 leaf 页头（前 100 字节是文件头）能正确
// 定位 cell 指针——NTQQ 的 sqlite_master 就在 page 1。
func TestLeafCellOffsets(t *testing.T) {
	U := 512
	p1 := make([]byte, U)
	copy(p1, "SQLite format 3\x00")
	// 文件头里声明页大小
	binary.BigEndian.PutUint16(p1[16:], uint16(U))
	p1[100] = 0x0d // leaf table，位于 100 字节文件头之后
	recs := [][]byte{makeRecord("c2c_msg_table", 5)}
	off := U - (1 + 1 + len(recs[0]))
	copy(p1[off:], encVarint(uint64(len(recs[0]))))
	copy(p1[off+1:], encVarint(1))
	copy(p1[off+2:], recs[0])
	binary.BigEndian.PutUint16(p1[100+3:], 1)
	binary.BigEndian.PutUint16(p1[100+8:], uint16(off))

	fr := &fakeReader{pages: map[uint32][]byte{1: p1}, usable: U}
	s := &StreamDB{dec: fr, usable: U, tables: map[string]tableInfo{}}
	var got []string
	if err := s.walkTable(1, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return err
		}
		got = append(got, cols[0].(string))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "c2c_msg_table" {
		t.Fatalf("page1 cell 解析 = %v", got)
	}
}

// buildPageInto 在 page 的 [hdr, len(page)) 区间内摆放 interior cell。
// page 可以是整页（hdr=0），也可以是 page 1（前 100 字节已被文件头占用）。
// cell = childPtr(4) + rowid(varint)。
func buildPageInto(page []byte, hdr int, children []uint32, right uint32) []byte {
	page[hdr] = 0x05 // interior table
	binary.BigEndian.PutUint32(page[hdr+8:], right)
	off := len(page)
	ptrs := make([]uint16, len(children))
	for i := len(children) - 1; i >= 0; i-- {
		cell := make([]byte, 4)
		binary.BigEndian.PutUint32(cell, children[i])
		cell = append(cell, encVarint(uint64(i+1))...)
		off -= len(cell)
		copy(page[off:], cell)
		ptrs[i] = uint16(off)
	}
	binary.BigEndian.PutUint16(page[hdr+3:], uint16(len(children)))
	for i, p := range ptrs {
		binary.BigEndian.PutUint16(page[hdr+12+2*i:], p)
	}
	return page
}

// buildInteriorPage 造一个独立（非 page 1）的 interior table 页。
func buildInteriorPage(usable int, children []uint32, right uint32) []byte {
	return buildPageInto(make([]byte, usable), 0, children, right)
}

// TestWalkInteriorPage1 覆盖 page 1 是 interior 页的情形：cell 指针从 hdr+12
// 开始（不是 leaf 的 hdr+8），子页号要能正确取出并继续遍历。
// 真实 nt_msg.db 的 page 1 就是 interior——旧实现按 leaf 偏移读，会拿到垃圾。
func TestWalkInteriorPage1(t *testing.T) {
	U := 512
	p1 := make([]byte, U)
	copy(p1, "SQLite format 3\x00")
	buildPageInto(p1, 100, []uint32{2}, 3)

	recs := func(name string) [][]byte { return [][]byte{makeRecord(name, 1)} }
	fr := &fakeReader{pages: map[uint32][]byte{
		1: p1,
		2: buildLeafPage(U, 0, recs("from_left")),
		3: buildLeafPage(U, 0, recs("from_right")),
	}, usable: U}
	s := &StreamDB{dec: fr, usable: U, pages: 3, tables: map[string]tableInfo{}}

	var got []string
	if err := s.walkTable(1, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return err
		}
		got = append(got, cols[0].(string))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "from_left" || got[1] != "from_right" {
		t.Fatalf("interior page1 遍历 = %v, want [from_left from_right]", got)
	}
}

// TestWalkInteriorDropsBadChild 验证越界子页号被丢弃，而不是拿去解密。
// 这是大库上真实出现过的故障形态：指针读错得到 2.1e9 之类的页号。
func TestWalkInteriorDropsBadChild(t *testing.T) {
	U := 512
	// root 页 1：一个正常子页 + 一个坏指针；最右子页也故意给个越界值。
	p1 := make([]byte, U)
	copy(p1, "SQLite format 3\x00")
	buildPageInto(p1, 100, []uint32{2, 2185409704}, 3999999999)
	fr := &fakeReader{pages: map[uint32][]byte{
		1: p1,
		2: buildLeafPage(U, 0, [][]byte{makeRecord("ok", 1)}),
	}, usable: U}
	s := &StreamDB{dec: fr, usable: U, pages: 2}

	var got []string
	if err := s.walkTable(1, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return err
		}
		got = append(got, cols[0].(string))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ok" {
		t.Fatalf("越界子页应被跳过，实得 %v", got)
	}
}
