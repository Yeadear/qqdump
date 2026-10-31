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
