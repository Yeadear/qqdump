package db

import (
	"bytes"
	"testing"
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
		0x7b,             // 123 as int8
		'h', 'i',         // text "hi"
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
