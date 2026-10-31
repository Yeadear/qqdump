package db

import (
	"testing"

	"github.com/Yeadear/qqdump/model"
)

// TestInferPeerUIN 覆盖 40030 为空时的会话归属推导。
//
// 真机上确实存在 40030=0、但 40021/40027 指向群号的群系统消息；
// 若不做兜底，这些消息会流进一个不存在的 "0 号会话"。
func TestInferPeerUIN(t *testing.T) {
	cases := []struct {
		name     string
		m        model.Message
		chatType int
		want     int64
	}{
		{
			name:     "40030 有值时原样保留",
			m:        model.Message{PeerUIN: 123, PeerUID: "456", SessionID: 789},
			chatType: 2,
			want:     123,
		},
		{
			name:     "群系统消息回退到 40021",
			m:        model.Message{PeerUID: "1097140372", SessionID: 1097140372},
			chatType: 2,
			want:     1097140372,
		},
		{
			name:     "只有 40027 时用它",
			m:        model.Message{SessionID: 555},
			chatType: 2,
			want:     555,
		},
		{
			name:     "私聊最终可用发送者兜底",
			m:        model.Message{SenderUIN: 777},
			chatType: 1,
			want:     777,
		},
		{
			name:     "群表不用发送者兜底",
			m:        model.Message{SenderUIN: 777},
			chatType: 2,
			want:     0,
		},
		{
			name:     "全为空时保持 0",
			m:        model.Message{},
			chatType: 1,
			want:     0,
		},
	}
	for _, c := range cases {
		if got := inferPeerUIN(c.m, c.chatType); got != c.want {
			t.Errorf("%s: 得到 %d，期望 %d", c.name, got, c.want)
		}
	}
}
