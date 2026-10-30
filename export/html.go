package export

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/Yeadear/qqdump/model"
)

// css 是内嵌的页面样式：仿 QQ 的气泡会话，单文件自包含，不依赖任何外部资源。
const css = `:root{--bg:#f2f3f5;--line:#e4e6e8;--peer:#fff;--self:#95ec69;--text:#1a1a1a}
*{box-sizing:border-box}
body{margin:0;background:#e9eaec;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;font-size:15px;color:var(--text);line-height:1.6}
.wrap{max-width:860px;margin:0 auto;background:var(--bg);min-height:100vh;box-shadow:0 0 30px rgba(0,0,0,.07)}
header{padding:16px 20px;border-bottom:1px solid var(--line);background:#fbfbfc;position:sticky;top:0;z-index:2}
h1{margin:0;font-size:17px;font-weight:600}
.meta{margin-top:4px;color:#8b8b8b;font-size:12px}
.msgs{padding:14px 18px 48px}
.day{text-align:center;margin:16px 0 10px}
.day span{display:inline-block;background:#d6d8da;color:#fff;font-size:12px;padding:2px 10px;border-radius:4px}
.row{display:flex;align-items:flex-start;gap:10px;margin:8px 0}
.row.me{flex-direction:row-reverse}
.avatar{width:38px;height:38px;flex:0 0 38px;border-radius:5px;background:#c4c9ce;color:#fff;display:flex;align-items:center;justify-content:center;font-size:14px;overflow:hidden}
.row.me .avatar{background:#5b9bd5}
.bubble{max-width:64%;background:var(--peer);border-radius:7px;padding:7px 11px;box-shadow:0 1px 2px rgba(0,0,0,.07);word-break:break-word;overflow-wrap:anywhere}
.row.me .bubble{background:var(--self)}
.sender{font-size:11px;color:#9b9b9b;margin-bottom:3px}
.quote{border-left:3px solid #c9ccd0;background:rgba(0,0,0,.04);padding:4px 8px;margin:4px 0 6px;font-size:13px;color:#5a5a5a;border-radius:3px}
.media{font-size:13px;color:#4a6fa5}
.media a{color:#4a6fa5}
.sys,.tip{text-align:center;margin:12px 0}
.sys span,.tip span{display:inline-block;background:#d6d8da;color:#6c6c6c;font-size:12px;padding:3px 10px;border-radius:4px;max-width:80%}
.thumb{max-width:220px;max-height:220px;border-radius:4px;display:block;margin:4px 0}
footer{padding:14px 20px;border-top:1px solid var(--line);color:#9a9a9a;font-size:12px;text-align:center}
ul{border-top:1px solid var(--line)}
li{border-bottom:1px solid var(--line);padding:12px 20px;display:flex;justify-content:space-between;align-items:center;gap:12px}
li a{color:#1a1a1a;text-decoration:none;font-weight:500}
li a:hover{color:#4a6fa5}
.tag{font-size:12px;color:#8b8b8b;background:#e6e8ea;padding:2px 8px;border-radius:3px}
`

// WriteHTML 把一个会话导出为单文件 HTML 聊天记录。
func WriteHTML(w io.Writer, c model.Conversation) error {
	b := &strings.Builder{}
	esc := html.EscapeString

	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	fmt.Fprintf(b, "<title>%s</title>\n", esc(c.Title()))
	fmt.Fprintf(b, "<style>%s</style>\n</head>\n<body>\n<div class=\"wrap\">\n", css)

	fmt.Fprintf(b, "<header><h1>%s</h1>", esc(c.Title()))
	meta := []string{kindName(c.Type)}
	if c.PeerUIN != 0 {
		if c.Type == model.ChatGroup {
			meta = append(meta, fmt.Sprintf("群号 %d", c.PeerUIN))
		} else {
			meta = append(meta, fmt.Sprintf("QQ %d", c.PeerUIN))
		}
	}
	meta = append(meta, fmt.Sprintf("%d 条消息", len(c.Messages)))
	if n := len(c.Messages); n > 0 {
		meta = append(meta, fmt.Sprintf("%s ~ %s",
			FmtDate(c.Messages[0].Timestamp), FmtDate(c.Messages[n-1].Timestamp)))
	}
	fmt.Fprintf(b, "<div class=\"meta\">%s</div></header>\n<div class=\"msgs\">\n", esc(strings.Join(meta, " · ")))

	prevDate := ""
	for _, m := range c.Messages {
		if d := FmtDate(m.Timestamp); d != prevDate {
			fmt.Fprintf(b, "<div class=\"day\"><span>%s</span></div>\n", d)
			prevDate = d
		}

		if m.IsSystem() {
			// 系统灰条单独居中呈现，不进气泡
			for _, s := range m.Segments {
				txt := s.SysContent
				if txt == "" {
					txt = s.Text
				}
				if txt == "" {
					txt = s.Plain()
				}
				fmt.Fprintf(b, "<div class=\"sys\"><span>%s</span></div>\n", esc(txt))
			}
			continue
		}

		me := m.IsSend()
		cls := "row"
		if me {
			cls = "row me"
		}
		who := SenderName(m)
		if me {
			who = "我"
		}
		fmt.Fprintf(b, "<div class=\"%s\"><div class=\"avatar\">%s</div><div class=\"bubble\">", cls, esc(initial(who)))
		if c.Type == model.ChatGroup && !me {
			fmt.Fprintf(b, "<div class=\"sender\">%s</div>", esc(who))
		}

		for _, s := range m.Segments {
			renderSegmentHTML(b, s)
		}
		if len(m.Segments) == 0 {
			b.WriteString("<span class=\"media\">（无内容）</span>")
		}
		fmt.Fprintf(b, "<div class=\"sender\">%s</div>", esc(FmtClock(m.Timestamp)))
		b.WriteString("</div></div>\n")
	}

	b.WriteString("</div>\n<footer>由 qqdump 导出 · 仅供本人备份，请勿外传</footer>\n</div>\n</body>\n</html>\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// renderSegmentHTML 渲染一个消息段。
func renderSegmentHTML(b *strings.Builder, s model.Segment) {
	esc := html.EscapeString
	switch s.Kind {
	case model.SegText, model.SegMarkdown:
		b.WriteString(esc(s.Text))
	case model.SegImage:
		if s.URL != "" {
			fmt.Fprintf(b, "<a class=\"media\" href=\"%s\" target=\"_blank\" rel=\"noopener\">[图片", esc(s.URL))
		} else {
			b.WriteString("<span class=\"media\">[图片")
		}
		if s.Width > 0 && s.Height > 0 {
			fmt.Fprintf(b, " %dx%d", s.Width, s.Height)
		}
		if s.FileSize > 0 {
			b.WriteString(" " + FmtSize(s.FileSize))
		}
		if s.URL != "" {
			b.WriteString("]</a>")
		} else {
			b.WriteString("]</span>")
		}
	case model.SegVideo:
		b.WriteString("<span class=\"media\">[视频")
		if s.Duration > 0 {
			b.WriteString(" " + FmtDuration(s.Duration))
		}
		b.WriteString("]</span>")
	case model.SegVoice:
		b.WriteString("<span class=\"media\">[语音")
		if s.Duration > 0 {
			b.WriteString(" " + FmtDuration(s.Duration))
		}
		b.WriteString("]</span>")
	case model.SegFile:
		sz := ""
		if s.FileSize > 0 {
			sz = " " + FmtSize(s.FileSize)
		}
		if s.URL != "" {
			fmt.Fprintf(b, "<a class=\"media\" href=\"%s\">[文件 %s%s]</a>", esc(s.URL), esc(s.FileName), sz)
		} else {
			fmt.Fprintf(b, "<span class=\"media\">[文件 %s%s]</span>", esc(s.FileName), sz)
		}
	case model.SegFace:
		b.WriteString(esc(s.FaceText))
	case model.SegReply:
		if s.ReplyText != "" {
			fmt.Fprintf(b, "<div class=\"quote\">%s</div>", esc(s.ReplyText))
		}
		if s.Text != "" {
			b.WriteString(esc(s.Text))
		}
	case model.SegGrayTip:
		fmt.Fprintf(b, "<span class=\"media\">%s</span>", esc(s.SysContent))
	case model.SegRedBag:
		b.WriteString("<span class=\"media\">[红包]</span>")
	case model.SegArk:
		b.WriteString("<span class=\"media\">[卡片]</span>")
	case model.SegMarketFace:
		b.WriteString("<span class=\"media\">[表情]</span>")
	case model.SegLegacyForward:
		b.WriteString("<span class=\"media\">[合并转发]</span>")
	case model.SegLiveRecord:
		d := s.CallDesc
		if d == "" {
			d = "通话"
		}
		if s.CallDuration > 0 {
			d += " " + FmtDuration(s.CallDuration)
		}
		fmt.Fprintf(b, "<span class=\"media\">[%s]</span>", esc(d))
	default:
		if s.Text != "" {
			b.WriteString(esc(s.Text))
		} else {
			fmt.Fprintf(b, "<span class=\"media\">[%s]</span>", esc(s.KindName()))
		}
	}
}

// WriteIndexHTML 输出会话索引页，链接到各个会话的 HTML。
func WriteIndexHTML(w io.Writer, convs []model.Conversation) error {
	b := &strings.Builder{}
	esc := html.EscapeString
	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	b.WriteString("<title>QQ 聊天记录</title>\n")
	fmt.Fprintf(b, "<style>%s</style>\n</head>\n<body>\n<div class=\"wrap\">\n", css)
	b.WriteString("<header><h1>QQ 聊天记录</h1>")
	fmt.Fprintf(b, "<div class=\"meta\">共 %d 个会话</div></header>\n<ul>\n", len(convs))

	for _, c := range convs {
		fmt.Fprintf(b, "<li><a href=\"%s.html\">%s %s</a><span class=\"tag\">%s · %d 条</span></li>\n",
			esc(FileName(c)), esc(kindName(c.Type)), esc(c.Title()),
			esc(kindName(c.Type)), len(c.Messages))
	}
	b.WriteString("</ul>\n<footer>由 qqdump 导出 · 仅供本人备份，请勿外传</footer>\n</div>\n</body>\n</html>\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// initial 取显示名的首个字符作为头像文字。
func initial(name string) string {
	if name == "" {
		return "?"
	}
	for _, r := range name {
		return string(r)
	}
	return "?"
}
