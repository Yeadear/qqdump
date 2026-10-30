package msgproto

import (
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Yeadear/qqdump/model"
)

// marshal 用生成的代码构造一条 40800 内容，与线上协议完全一致。
func marshal(t *testing.T, segs ...*MsgContent) []byte {
	t.Helper()
	b := &MsgBody{Content: segs}
	data, err := proto.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func TestParseBodyText(t *testing.T) {
	raw := marshal(t, &MsgContent{MsgId: 1, ContentType: model.SegText, Text: []byte("你好，世界")})

	segs := ParseBody(raw)
	if len(segs) != 1 {
		t.Fatalf("段数 = %d, want 1", len(segs))
	}
	if segs[0].Kind != model.SegText {
		t.Errorf("Kind = %d, want %d", segs[0].Kind, model.SegText)
	}
	if segs[0].Text != "你好，世界" {
		t.Errorf("Text = %q, want %q", segs[0].Text, "你好，世界")
	}
	if segs[0].Plain() != "你好，世界" {
		t.Errorf("Plain = %q", segs[0].Plain())
	}
}

// 一条消息多段（图文混排）时必须保留段顺序，不能压成单个对象。
func TestParseBodyKeepsOrder(t *testing.T) {
	raw := marshal(t,
		&MsgContent{MsgId: 1, ContentType: model.SegText, Text: []byte("看看这张图")},
		&MsgContent{MsgId: 2, ContentType: model.SegImage, Filename: []byte("a.png"), ImgWidth: 800, ImgHeight: 600},
	)

	segs := ParseBody(raw)
	if len(segs) != 2 {
		t.Fatalf("段数 = %d, want 2", len(segs))
	}
	if segs[0].Kind != model.SegText || segs[1].Kind != model.SegImage {
		t.Fatalf("段顺序或类型不对: %d, %d", segs[0].Kind, segs[1].Kind)
	}
	if segs[1].FileName != "a.png" {
		t.Errorf("FileName = %q", segs[1].FileName)
	}
	if segs[1].Width != 800 || segs[1].Height != 600 {
		t.Errorf("尺寸 = %dx%d, want 800x600", segs[1].Width, segs[1].Height)
	}
}

func TestParseMediaFields(t *testing.T) {
	raw := marshal(t, &MsgContent{
		MsgId:       1,
		ContentType: model.SegFile,
		MediaSub:    model.MediaFile,
		Filename:    []byte("报告.pdf"),
		Filesize:    1048576,
		Md5Raw:      []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		CdnHost:     "gchat.qpic.cn",
		CdnUrl_1:    "download/abc",
	})

	segs := ParseBody(raw)
	if len(segs) != 1 {
		t.Fatalf("段数 = %d", len(segs))
	}
	s := segs[0]
	if s.FileName != "报告.pdf" {
		t.Errorf("FileName = %q", s.FileName)
	}
	if s.FileSize != 1048576 {
		t.Errorf("FileSize = %d", s.FileSize)
	}
	if s.MD5 != "00112233445566778899aabbccddeeff" {
		t.Errorf("MD5 = %q", s.MD5)
	}
	if s.URL != "https://gchat.qpic.cn/download/abc" {
		t.Errorf("URL = %q", s.URL)
	}
}

// 45101 是 bytes：即使内容实际是嵌套消息，也不能按嵌套消息解析而失败。
func TestParseTextAsBytesNotMessage(t *testing.T) {
	// 构造一段"看起来像嵌套消息"的字节，塞进 45101
	nested := &MsgContent{MsgId: 9, ContentType: model.SegText, Text: []byte("内层")}
	nestedBytes, err := proto.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}

	raw := marshal(t, &MsgContent{MsgId: 1, ContentType: model.SegText, Text: nestedBytes})
	segs := ParseBody(raw)
	if len(segs) != 1 {
		t.Fatalf("段数 = %d", len(segs))
	}
	if segs[0].Kind != model.SegText {
		t.Errorf("Kind = %d, want 文本段（不该被当成嵌套消息）", segs[0].Kind)
	}
	// 非法 UTF-8 的文本必然解码有损，原始字节必须另行保留
	if len(segs[0].Raw) != len(nestedBytes) {
		t.Errorf("原始字节没有保留：want %d 字节，得到 %d",
			len(nestedBytes), len(segs[0].Raw))
	}
}

// 解不开的内容必须保留原始字节，绝不静默丢弃。
func TestParseBodyKeepsRawOnFailure(t *testing.T) {
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	segs := ParseBody(garbage)
	if len(segs) != 1 {
		t.Fatalf("段数 = %d, want 1（保留原始字节）", len(segs))
	}
	if string(segs[0].Raw) != string(garbage) {
		t.Errorf("原始字节没有保留")
	}
	if segs[0].Kind != 0 {
		t.Errorf("Kind = %d, want 0（未知）", segs[0].Kind)
	}
}

// 少数库把 BLOB 落成 hex 文本存储，应还原后再解析。
func TestParseBodyFromHexText(t *testing.T) {
	raw := marshal(t, &MsgContent{MsgId: 1, ContentType: model.SegText, Text: []byte("hex 存储的文本")})
	asHex := []byte(hex.EncodeToString(raw))

	segs := ParseBody(asHex)
	if len(segs) != 1 {
		t.Fatalf("段数 = %d", len(segs))
	}
	if segs[0].Text != "hex 存储的文本" {
		t.Errorf("Text = %q", segs[0].Text)
	}
}

func TestParseBodyEmpty(t *testing.T) {
	if segs := ParseBody(nil); segs != nil {
		t.Errorf("nil 输入应返回 nil，得到 %v", segs)
	}
	if segs := ParseBody([]byte{}); segs != nil {
		t.Errorf("空输入应返回 nil，得到 %v", segs)
	}
}

// 非法 UTF-8 的文本要保留可解部分，而不是整段丢掉。
func TestDecodeTextLossy(t *testing.T) {
	got := decodeText([]byte("abc\xff\xfedef"))
	if !strings.Contains(got, "abc") || !strings.Contains(got, "def") {
		t.Errorf("decodeText = %q，应保留两端可解码部分", got)
	}
	if got := decodeText(nil); got != "" {
		t.Errorf("空输入应返回空串，得到 %q", got)
	}
}

func TestParseSingle(t *testing.T) {
	seg := &MsgContent{MsgId: 1, ContentType: model.SegVoice, Duration: 15}
	data, _ := proto.Marshal(seg)

	got := ParseSingle(data)
	if got.Kind != model.SegVoice {
		t.Errorf("Kind = %d, want %d", got.Kind, model.SegVoice)
	}
	if got.Duration != 15 {
		t.Errorf("Duration = %d", got.Duration)
	}
	if got.Plain() != "[语音]" {
		t.Errorf("Plain = %q", got.Plain())
	}
}

// 表情的外显文字（如 "/呲牙"）要能直接用于展示。
func TestFaceText(t *testing.T) {
	raw := marshal(t, &MsgContent{MsgId: 1, ContentType: model.SegFace, VideoFlag: 1, VideoText: []byte("/呲牙")})
	segs := ParseBody(raw)
	if segs[0].FaceText != "/呲牙" {
		t.Errorf("FaceText = %q", segs[0].FaceText)
	}
	if segs[0].Plain() != "/呲牙" {
		t.Errorf("Plain = %q, want /呲牙", segs[0].Plain())
	}
}

// 引用回复要拿到被引用内容的摘要。
func TestReply(t *testing.T) {
	raw := marshal(t, &MsgContent{
		MsgId: 1, ContentType: model.SegReply,
		ReplyMsgId: 1001, ReplySummary: "被回复的那条消息",
		Text: []byte("这是引用回复"),
	})
	segs := ParseBody(raw)
	if segs[0].ReplyTo != 1001 {
		t.Errorf("ReplyTo = %d", segs[0].ReplyTo)
	}
	if segs[0].ReplyText != "被回复的那条消息" {
		t.Errorf("ReplyText = %q", segs[0].ReplyText)
	}
}
