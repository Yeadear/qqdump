package export

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Yeadear/qqdump/model"
)

// ConvStream 是单个会话的流式写出器：边收到消息边写，不缓存整段会话，
// 因此导出 6GB 级聊天库时内存只与"单条消息 + 当前文件"相关。
//
// 三种格式（json / markdown / html）各自包裹成合法的自包含文档。
type ConvStream struct {
	format     string
	w          io.Writer
	meta       model.Conversation
	enc        *json.Encoder
	first      bool
	count      int
	firstTS    int64
	lastTS     int64
	lastMDDate string // Markdown 按日期分组时记住上一个日期
}

// NewConvStream 创建会话流式写出器。meta 提供会话元数据（名称、peer、类型），
// 写头部时会用到；消息数 / 时间范围在写的过程中累积，写尾部落款。
func NewConvStream(format string, w io.Writer, meta model.Conversation) *ConvStream {
	cs := &ConvStream{format: format, w: w, meta: meta, first: true}
	switch format {
	case "json":
		cs.enc = json.NewEncoder(w)
		cs.enc.SetEscapeHTML(false)
		b := &strings.Builder{}
		b.WriteString("{")
		fmt.Fprintf(b, `"peer_uin":%d,`, meta.PeerUIN)
		fmt.Fprintf(b, `"kind":%q,`, meta.KindLabel())
		if meta.PeerUID != "" {
			fmt.Fprintf(b, `"peer_uid":%q,`, meta.PeerUID)
		}
		if t := meta.Title(); t != "" {
			fmt.Fprintf(b, `"name":%q,`, t)
		}
		b.WriteString(`"messages": [`)
		io.WriteString(w, b.String())
	case "markdown":
		cs.writeMarkdownHeader()
	case "html":
		cs.writeHTMLHeader()
	}
	return cs
}

// Write 写入一条消息。
func (c *ConvStream) Write(m model.Message) error {
	switch c.format {
	case "json":
		if !c.first {
			io.WriteString(c.w, ",")
		}
		c.first = false
		if err := c.enc.Encode(toJSONMsg(m)); err != nil {
			return err
		}
	case "markdown":
		if err := c.writeMarkdownMsg(m); err != nil {
			return err
		}
	case "html":
		if err := c.writeHTMLMsg(m); err != nil {
			return err
		}
	}
	c.count++
	if c.firstTS == 0 || m.Timestamp < c.firstTS {
		c.firstTS = m.Timestamp
	}
	if m.Timestamp > c.lastTS {
		c.lastTS = m.Timestamp
	}
	return nil
}

// Close 收尾（写数组/文档结尾与落款）。
func (c *ConvStream) Close() error {
	switch c.format {
	case "json":
		_, err := io.WriteString(c.w, "]}\n")
		return err
	case "markdown":
		b := &strings.Builder{}
		fmt.Fprintf(b, "\n\n---\n共 %d 条消息", c.count)
		if c.count > 0 {
			fmt.Fprintf(b, "，时间范围 %s ~ %s", FmtDate(c.firstTS), FmtDate(c.lastTS))
		}
		_, err := io.WriteString(c.w, b.String())
		return err
	case "html":
		_, err := io.WriteString(c.w, "</div></body></html>\n")
		return err
	}
	return nil
}

// Count 返回已写入的消息条数。
func (c *ConvStream) Count() int { return c.count }

func toJSONMsg(m model.Message) JSONMsg {
	jm := JSONMsg{
		ID:         m.ID,
		Time:       FmtTime(m.Timestamp),
		Timestamp:  m.Timestamp,
		IsSend:     m.IsSend(),
		Direction:  m.Direction,
		SenderUIN:  m.SenderUIN,
		SenderName: SenderName(m),
	}
	for _, s := range m.Segments {
		js := JSONSegment{
			Kind:      s.KindLabel(),
			KindID:    s.Kind,
			Text:      s.Text,
			FileName:  s.FileName,
			FileSize:  s.FileSize,
			MD5:       s.MD5,
			URL:       s.URL,
			Path:      firstPath(s),
			Width:     s.Width,
			Height:    s.Height,
			Duration:  s.Duration,
			FaceID:    s.FaceID,
			FaceText:  s.FaceText,
			ReplyTo:   s.ReplyTo,
			ReplyText: s.ReplyText,
			HasRaw:    len(s.Raw) > 0,
		}
		if s.FileSize > 0 {
			js.FileSizeHuman = FmtSize(s.FileSize)
		}
		jm.Segments = append(jm.Segments, js)
	}
	return jm
}

// ---- Markdown 流式 ----

func (c *ConvStream) writeMarkdownHeader() {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# %s\n\n", c.meta.Title())
	fmt.Fprintf(b, "- 类型：%s\n", kindName(c.meta.Type))
	if c.meta.PeerUIN != 0 {
		if c.meta.Type == model.ChatGroup {
			fmt.Fprintf(b, "- 群号：%d\n", c.meta.PeerUIN)
		} else {
			fmt.Fprintf(b, "- 对方 QQ：%d\n", c.meta.PeerUIN)
		}
	}
	if c.meta.PeerUID != "" {
		fmt.Fprintf(b, "- UID：%s\n", c.meta.PeerUID)
	}
	b.WriteString("\n---\n")
	io.WriteString(c.w, b.String())
}

func (c *ConvStream) writeMarkdownMsg(m model.Message) error {
	b := &strings.Builder{}
	if d := FmtDate(m.Timestamp); d != c.lastMDDate {
		fmt.Fprintf(b, "\n## %s\n\n", d)
		c.lastMDDate = d
	}
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
		_, err := io.WriteString(c.w, b.String())
		return err
	}
	who := SenderName(m)
	if m.IsSend() {
		who = "我"
	}
	fmt.Fprintf(b, "- `%s` **%s**：", FmtClock(m.Timestamp), who)
	renderSegmentsMD(b, m)
	b.WriteString("\n")
	_, err := io.WriteString(c.w, b.String())
	return err
}

// ---- HTML 流式 ----

func (c *ConvStream) writeHTMLHeader() {
	b := &strings.Builder{}
	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	fmt.Fprintf(b, "<title>%s</title>", escapeHTMLTitle(c.meta.Title()))
	b.WriteString("<style>")
	b.WriteString("body{font-family:system-ui,'PingFang SC',sans-serif;max-width:760px;margin:auto;padding:16px;background:#f5f5f5}")
	b.WriteString(".msg{display:flex;margin:8px 0}.msg.me{flex-direction:row-reverse}")
	b.WriteString(".bubble{max-width:70%;padding:8px 12px;border-radius:12px;background:#fff}")
	b.WriteString(".msg.me .bubble{background:#95ec69}.meta{font-size:12px;color:#888;margin:0 6px}")
	b.WriteString(".sys{text-align:center;color:#999;font-size:13px;margin:6px 0}img{max-width:240px;border-radius:8px}")
	b.WriteString("</style></head><body><div class=\"conv\">")
	io.WriteString(c.w, b.String())
}

func (c *ConvStream) writeHTMLMsg(m model.Message) error {
	if m.IsSystem() {
		txt := ""
		for _, s := range m.Segments {
			txt = s.SysContent
			if txt == "" {
				txt = s.Text
			}
			if txt == "" {
				txt = s.Plain()
			}
			break
		}
		_, err := fmt.Fprintf(c.w, "<div class=\"sys\">%s</div>\n", escapeHTMLText(txt))
		return err
	}
	who := SenderName(m)
	if m.IsSend() {
		who = "我"
	}
	b := &strings.Builder{}
	cls := ""
	if m.IsSend() {
		cls = " me"
	}
	fmt.Fprintf(b, "<div class=\"msg%s\"><div class=\"meta\">%s %s</div><div class=\"bubble\">",
		cls, escapeHTMLText(who), FmtClock(m.Timestamp))
	for _, s := range m.Segments {
		renderSegmentHTML(b, s)
	}
	if len(m.Segments) == 0 {
		b.WriteString("（无内容）")
	}
	b.WriteString("</div></div>\n")
	_, err := io.WriteString(c.w, b.String())
	return err
}

// escapeHTMLTitle 避免标题里的引号破坏 <title>。
func escapeHTMLTitle(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// escapeHTMLText 转义 HTML 文本节点。
func escapeHTMLText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
