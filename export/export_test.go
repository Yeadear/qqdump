package export

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Yeadear/qqdump/model"
)

func sampleConv() model.Conversation {
	return model.Conversation{
		ID: 5001, PeerUIN: 10001, PeerUID: "u_peer10001", Type: model.ChatC2C, Name: "小明",
		Messages: []model.Message{
			{
				ID: 1, Timestamp: 1700000000, Direction: model.DirRecv,
				SenderUIN: 10001, SenderName: "小明",
				Segments: []model.Segment{{Kind: model.SegText, Text: "你好"}},
			},
			{
				ID: 2, Timestamp: 1700000060, Direction: model.DirSend,
				SenderUIN: 10000, SenderName: "我",
				Segments: []model.Segment{{Kind: model.SegImage, FileName: "a.jpg", FileSize: 2048, Width: 800, Height: 600}},
			},
			{
				ID: 3, Timestamp: 1700100000, Direction: model.DirRecv,
				SenderUIN: 10001, SenderName: "小明",
				Segments: []model.Segment{{Kind: model.SegText, Text: "第二天"}},
			},
		},
	}
}

func TestWriteMarkdown(t *testing.T) {
	var b strings.Builder
	if err := WriteMarkdown(&b, sampleConv()); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	for _, want := range []string{"# 小明", "私聊", "10001", "## 2023-11-15", "## 2023-11-16", "你好"} {
		if !strings.Contains(out, want) {
			t.Errorf("Markdown 缺少 %q", want)
		}
	}
	// 图片没有直链时退化成文字占位，不能输出空的 ![图片]()
	if !strings.Contains(out, "[图片 800x600") {
		t.Errorf("图片占位不对：\n%s", out)
	}
	if strings.Contains(out, "![图片]()") {
		t.Error("不应输出空链接")
	}
}

// 系统消息没有发送者，不该显示"未知"。
func TestWriteMarkdownSystemMessage(t *testing.T) {
	c := model.Conversation{
		Type: model.ChatGroup, PeerUIN: 888, Name: "测试群",
		Messages: []model.Message{{
			ID: 1, Timestamp: 1700000000, Direction: model.DirSystem,
			Segments: []model.Segment{{Kind: model.SegGrayTip, SysContent: "小李 加入了群聊"}},
		}},
	}
	var b strings.Builder
	if err := WriteMarkdown(&b, c); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "小李 加入了群聊") {
		t.Errorf("系统消息内容丢失：\n%s", out)
	}
	if strings.Contains(out, "未知") {
		t.Errorf("系统消息不该显示发送者为未知：\n%s", out)
	}
}

func TestWriteJSON(t *testing.T) {
	var b strings.Builder
	if err := WriteJSON(&b, []model.Conversation{sampleConv()}, "test.db"); err != nil {
		t.Fatal(err)
	}

	var doc JSON
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("输出的 JSON 无法解析: %v", err)
	}
	if doc.Count != 1 {
		t.Errorf("conversation_count = %d, want 1", doc.Count)
	}
	if len(doc.Convers) != 1 {
		t.Fatalf("会话数 = %d", len(doc.Convers))
	}
	conv := doc.Convers[0]
	if conv.Name != "小明" || conv.PeerUIN != 10001 || conv.Kind != "c2c" {
		t.Errorf("会话头 = %+v", conv)
	}
	if len(conv.Messages) != 3 {
		t.Fatalf("消息数 = %d", len(conv.Messages))
	}
	if conv.Messages[0].SenderName != "小明" || conv.Messages[0].IsSend {
		t.Errorf("第 1 条 = %+v", conv.Messages[0])
	}
	if !conv.Messages[1].IsSend {
		t.Error("第 2 条应是本人发送")
	}
	if conv.Messages[0].Time != "2023-11-15 06:13:20" {
		t.Errorf("时间 = %q（应为 UTC+8）", conv.Messages[0].Time)
	}
	// 中文不能被转义成 \uXXXX
	if strings.Contains(b.String(), "\\u") {
		t.Error("中文被转义了，应保持原样")
	}
}

// 聊天内容是用户可控的，渲染成 HTML 必须转义，否则打开自己的备份就会被 XSS。
func TestWriteHTMLEscapes(t *testing.T) {
	c := model.Conversation{
		Type: model.ChatC2C, PeerUIN: 1, Name: `<script>alert("x")</script>`,
		Messages: []model.Message{{
			ID: 1, Timestamp: 1700000000, Direction: model.DirRecv, SenderName: "坏人",
			Segments: []model.Segment{{Kind: model.SegText, Text: `<script>alert(1)</script>`}},
		}},
	}
	var b strings.Builder
	if err := WriteHTML(&b, c); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<script>alert") {
		t.Error("HTML 没有转义，存在 XSS 风险")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("转义结果不对：\n%s", out)
	}
}

func TestWriteHTMLStructure(t *testing.T) {
	var b strings.Builder
	if err := WriteHTML(&b, sampleConv()); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	for _, want := range []string{
		"<!DOCTYPE html>", `lang="zh-CN"`, "<style>",
		"2023-11-15", "2023-11-16", "你好", "row me",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML 缺少 %q", want)
		}
	}
	// 单文件自包含：不能引用任何外部资源
	if strings.Contains(out, `src="http`) || strings.Contains(out, `href="http`) {
		t.Error("HTML 引用了外部资源，破坏了自包含")
	}
}

func TestWriteIndexHTML(t *testing.T) {
	var b strings.Builder
	if err := WriteIndexHTML(&b, []model.Conversation{sampleConv()}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "c2c_10001_小明.html") {
		t.Errorf("索引页没有链接到会话页：\n%s", out)
	}
	if !strings.Contains(out, "3 条") {
		t.Errorf("索引页缺少消息数：\n%s", out)
	}
}

func TestFileName(t *testing.T) {
	c := model.Conversation{Type: model.ChatC2C, PeerUIN: 123, Name: "张三"}
	if got := FileName(c); got != "c2c_123_张三" {
		t.Errorf("FileName = %q", got)
	}
	g := model.Conversation{Type: model.ChatGroup, PeerUIN: 456, Name: "家人群"}
	if got := FileName(g); !strings.HasPrefix(got, "group_456_") {
		t.Errorf("FileName = %q", got)
	}
}

// 会话名来自聊天数据，是不可信输入：绝不能让它逃出输出目录。
func TestSafeName(t *testing.T) {
	if got := SafeName("正常名字"); got != "正常名字" {
		t.Errorf("SafeName 不该改动正常名字: %q", got)
	}
	if got := SafeName(""); got != "unnamed" {
		t.Errorf("SafeName(\"\") = %q", got)
	}

	// 路径穿越与分隔符必须被清掉
	for _, in := range []string{
		"../../../etc/passwd", "..\\..\\x", "a/b", "/abs/path", "a/../../b", "///", "...",
	} {
		got := SafeName(in)
		if strings.Contains(got, "/") || strings.Contains(got, "\\") || strings.Contains(got, "..") {
			t.Errorf("SafeName(%q) = %q，仍然可以路径穿越", in, got)
		}
		if got == "" {
			t.Errorf("SafeName(%q) 返回空串", in)
		}
	}
}

// FileName 拼出的路径必须落在输出目录内。
func TestFileNameNoTraversal(t *testing.T) {
	c := model.Conversation{Type: model.ChatC2C, PeerUIN: 1, Name: "../../etc/passwd"}
	if got := FileName(c); strings.Contains(got, "..") {
		t.Errorf("FileName = %q，存在路径穿越", got)
	}
}

func TestFmtSize(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	}
	for _, c := range cases {
		if got := FmtSize(c.in); got != c.want {
			t.Errorf("FmtSize(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFmtDuration(t *testing.T) {
	if got := FmtDuration(15); got != "15秒" {
		t.Errorf("FmtDuration(15) = %q", got)
	}
	if got := FmtDuration(125); got != "2分05秒" {
		t.Errorf("FmtDuration(125) = %q", got)
	}
	if got := FmtDuration(0); got != "" {
		t.Errorf("FmtDuration(0) = %q, want 空", got)
	}
}
