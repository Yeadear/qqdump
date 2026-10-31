package model

import "testing"

// TestIsPlaceholder 固定住"什么算占位空行"：
// nt_msg.db 里 40050=0 且无正文的行是删除/中断留下的空壳，必须丢弃；
// 但带了正文的零时间戳行要保留，避免误删旧库数据。
func TestIsPlaceholder(t *testing.T) {
	cases := []struct {
		name string
		m    Message
		want bool
	}{
		{"零时间无内容", Message{Timestamp: 0}, true},
		{"零时间有内容", Message{Timestamp: 0, Segments: []Segment{{Kind: SegText, Text: "hi"}}}, false},
		{"有时间无内容", Message{Timestamp: 1700000000}, false},
	}
	for _, c := range cases {
		if got := c.m.IsPlaceholder(); got != c.want {
			t.Errorf("%s: IsPlaceholder() = %v, want %v", c.name, got, c.want)
		}
	}
}
