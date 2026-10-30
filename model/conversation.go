package model

import "sort"

// Conversation 是一个会话及其消息，是导出层唯一的输入结构。
type Conversation struct {
	// 标识
	ID      int64  // 40027 本地会话键
	PeerUIN int64  // 40030 私聊对方 QQ 号 / 群号
	PeerUID string // 40021 对方 NT UID / 群 ID
	Type    int    // 40010 1=私聊 2=群聊

	// 展示名，按优先级取：群名/备注 > 昵称 > QQ 号
	Name string

	Messages []Message
}

// KindLabel 返回会话类型的英文名，用于文件命名。
func (c Conversation) KindLabel() string {
	if c.Type == ChatGroup {
		return "group"
	}
	return "c2c"
}

// Title 返回会话标题，保证非空。
func (c Conversation) Title() string {
	if c.Name != "" {
		return c.Name
	}
	if c.PeerUIN != 0 {
		return itoa(c.PeerUIN)
	}
	if c.PeerUID != "" {
		return c.PeerUID
	}
	return "未知会话"
}

// SortByTime 按时间升序排列消息（导出前的统一整理）。
func (c *Conversation) SortByTime() {
	sort.SliceStable(c.Messages, func(i, j int) bool {
		if c.Messages[i].Timestamp != c.Messages[j].Timestamp {
			return c.Messages[i].Timestamp < c.Messages[j].Timestamp
		}
		return c.Messages[i].ID < c.Messages[j].ID
	})
}

// SenderName 返回某条消息应显示的发送者名字。
// 群聊优先用群名片，其次昵称，最后 QQ 号。
func SenderName(m Message) string {
	if m.SenderCard != "" {
		return m.SenderCard
	}
	if m.SenderName != "" {
		return m.SenderName
	}
	if m.SenderUIN != 0 {
		return itoa(m.SenderUIN)
	}
	if m.SenderUID != "" {
		return m.SenderUID
	}
	return "未知"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
