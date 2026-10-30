package export

import (
	"fmt"
	"io"
	"strings"

	"github.com/Yeadear/qqdump/model"
)

// WriteMarkdown 把一个会话导出为 Markdown（纯文本，便于归档与搜索）。
func WriteMarkdown(w io.Writer, c model.Conversation) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# %s\n\n", c.Title())
	fmt.Fprintf(b, "- 类型：%s\n", kindName(c.Type))
	if c.PeerUIN != 0 {
		if c.Type == model.ChatGroup {
			fmt.Fprintf(b, "- 群号：%d\n", c.PeerUIN)
		} else {
			fmt.Fprintf(b, "- 对方 QQ：%d\n", c.PeerUIN)
		}
	}
	if c.PeerUID != "" {
		fmt.Fprintf(b, "- UID：%s\n", c.PeerUID)
	}
	fmt.Fprintf(b, "- 消息数：%d\n", len(c.Messages))
	if n := len(c.Messages); n > 0 {
		fmt.Fprintf(b, "- 时间范围：%s ~ %s\n",
			FmtDate(c.Messages[0].Timestamp), FmtDate(c.Messages[n-1].Timestamp))
	}
	b.WriteString("\n---\n")

	prevDate := ""
	for _, m := range c.Messages {
		if d := FmtDate(m.Timestamp); d != prevDate {
			fmt.Fprintf(b, "\n## %s\n\n", d)
			prevDate = d
		}
		// 系统提示没有发送者，单独呈现
		if m.IsSystem() {
			for _, s := range m.Segments {
				txt := s.SysContent
				if txt == "" {
					txt = s.Text
				}
				if txt == "" {
					txt = s.Plain()
				}
				fmt.Fprintf(b, "- `%s` *%s*\n", FmtClock(m.Timestamp), escapeMD(txt))
			}
			continue
		}

		who := SenderName(m)
		if m.IsSend() {
			who = "我"
		}
		fmt.Fprintf(b, "- `%s` **%s**：", FmtClock(m.Timestamp), who)
		renderSegmentsMD(b, m)
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// renderSegmentsMD 把一条消息的所有段写在同行或缩进行里。
func renderSegmentsMD(b *strings.Builder, m model.Message) {
	first := true
	for _, s := range m.Segments {
		if !first {
			b.WriteString(" ")
		}
		first = false
		switch s.Kind {
		case model.SegText, model.SegMarkdown:
			b.WriteString(escapeMD(s.Text))
		case model.SegImage:
			// 没有可用直链时退化成文字占位，不输出空链接
			if s.URL == "" {
				b.WriteString("[图片")
				if s.Width > 0 && s.Height > 0 {
					fmt.Fprintf(b, " %dx%d", s.Width, s.Height)
				}
				if s.FileSize > 0 {
					b.WriteString(" " + FmtSize(s.FileSize))
				}
				b.WriteString("]")
				break
			}
			b.WriteString("![图片](" + s.URL + ")")
		case model.SegVideo:
			b.WriteString("[视频")
			if s.Duration > 0 {
				fmt.Fprintf(b, " %s", FmtDuration(s.Duration))
			}
			b.WriteString("]")
		case model.SegFile:
			b.WriteString("[文件: " + escapeMD(s.FileName))
			if s.FileSize > 0 {
				b.WriteString(" " + FmtSize(s.FileSize))
			}
			b.WriteString("]")
		case model.SegVoice:
			b.WriteString("[语音")
			if s.Duration > 0 {
				b.WriteString(" " + FmtDuration(s.Duration))
			}
			b.WriteString("]")
		case model.SegFace:
			b.WriteString(escapeMD(s.FaceText))
		case model.SegReply:
			b.WriteString("> 引用 " + escapeMD(s.ReplyText))
		case model.SegGrayTip:
			b.WriteString("*" + escapeMD(s.SysContent) + "*")
		case model.SegRedBag:
			b.WriteString("[红包]")
		case model.SegArk:
			b.WriteString("[卡片]")
		case model.SegMarketFace:
			b.WriteString("[表情]")
		case model.SegLegacyForward:
			b.WriteString("[合并转发]")
		case model.SegLiveRecord:
			if s.CallDesc != "" {
				b.WriteString("[通话: " + escapeMD(s.CallDesc) + "]")
			} else {
				b.WriteString("[通话]")
			}
		default:
			if s.Text != "" {
				b.WriteString(escapeMD(s.Text))
			} else {
				b.WriteString("[" + s.KindName() + "]")
			}
		}
	}
	if len(m.Segments) == 0 {
		b.WriteString("*（无内容）*")
	}
}

// escapeMD 转义会破坏 Markdown 结构的字符，同时把换行压成空格，
// 保证一条消息在 Markdown 里只占一行。
func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "*", "\\*")
	s = strings.ReplaceAll(s, "_", "\\_")
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
}

// kindName 返回会话类型的中文名。
func kindName(t int) string {
	if t == model.ChatGroup {
		return "群聊"
	}
	return "私聊"
}
