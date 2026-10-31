// Package model 定义 qqdump 的领域模型。
//
// 它是解密层（internal/cipher）、数据库层（internal/db）和导出层
// （internal/export）之间唯一的契约：db 层把 nt_msg.db 的原始行翻译成
// model.Message，export 层只认识 model.Message，不认识 SQL 列名。
package model

// 会话类型，取自 40010。
const (
	ChatC2C   = 1 // 私聊
	ChatGroup = 2 // 群聊
)

// 消息方向，取自 40013。
const (
	DirRecv   = 0 // 收到
	DirSend   = 1 // 本人发送
	DirSend2  = 2 // 本人发送（另一路径）
	DirSystem = 3 // 系统消息
)

// 消息段类型，取自 40800 内 MsgContent 的 45002（content_type）。
// 名称沿用 QQBackup/nt_msg_db_util 的 db_docs 结论。
const (
	SegText          = 1  // 文本
	SegImage         = 2  // 图片
	SegFile          = 3  // 文件
	SegVoice         = 4  // 语音
	SegVideo         = 5  // 短视频
	SegFace          = 6  // QQ 表情
	SegReply         = 7  // 引用回复块
	SegGrayTip       = 8  // 系统灰条
	SegRedBag        = 9  // 红包
	SegArk           = 10 // Ark 卡片
	SegMarketFace    = 11 // 商城表情
	SegMarkdown      = 14 // Markdown
	SegLegacyForward = 16 // 旧协议合并转发 XML
	SegMarkdownBtn   = 17 // Bot 按钮
	SegLiveRecord    = 21 // 视频/语音通话记录
)

// 媒体子类型，取自 45003。
const (
	MediaImage = 1
	MediaVoice = 2
	MediaVideo = 7
	MediaFile  = 11
)

// Message 是一行 c2c_msg_table / group_msg_table 的完整语义表示。
//
// 两张表共用这个结构：私聊时 PeerUIN 是对端 QQ 号、SessionID 是本地会话键；
// 群聊时 PeerUIN 是群号、GroupName 有值时表示群名、SenderCard 是群名片。
// 未识别的语义原始 BLOB 保留在 Raw* 字段里，便于后续补齐协议。
type Message struct {
	// ---- 标识 ----
	ID        int64 `json:"id"`         // 40001 全局消息 ID（主键）
	MsgRandom int64 `json:"msg_random"` // 40002 消息随机数
	Seq       int64 `json:"seq"`        // 40003 c2c: 全局倒序序号；group: 群内序号
	ClientSeq int64 `json:"client_seq"` // 40005
	ServerSeq int64 `json:"server_seq"` // 40006

	// ---- 会话定位 ----
	ChatType  int    `json:"chat_type"`          // 40010 1=私聊 2=群聊
	MsgType   int    `json:"msg_type"`           // 40011 外层消息类型
	SubType   int64  `json:"sub_type"`           // 40012 子类型位掩码
	SessionID int64  `json:"session_id"`         // 40027 本地会话键
	PeerUID   string `json:"peer_uid,omitempty"` // 40021 c2c: 对方 UID；group: 群 ID
	PeerUIN   int64  `json:"peer_uin"`           // 40030 c2c: 对方 QQ；group: 群号

	// ---- 发送者 ----
	SenderUID  string `json:"sender_uid,omitempty"`  // 40020 发送者 NT UID
	SenderUIN  int64  `json:"sender_uin"`            // 40033 发送者 QQ
	SenderName string `json:"sender_name,omitempty"` // 40093 昵称
	SenderCard string `json:"sender_card,omitempty"` // 40090 群名片（仅群聊）
	Direction  int    `json:"direction"`             // 40013 方向

	// ---- 时间 ----
	Timestamp int64 `json:"timestamp"` // 40050 Unix 秒
	DateIndex int64 `json:"-"`         // 40058 UTC+8 当日零点，导出时用不上

	// ---- 内容 ----
	Segments []Segment `json:"segments"`

	// ---- 关联 ----
	ReplySeq   int64 `json:"-"` // 40850 被回复消息的序号
	ReactionTs int64 `json:"-"` // 40851

	// ---- 未解析的原始内容（供后续补齐协议）----
	Raw40600 []byte `json:"-"`
	Raw40605 []byte `json:"-"`
	Raw40801 []byte `json:"-"`
	Raw40900 []byte `json:"-"`
}

// IsSend 报告这条消息是否由机主本人发出。
func (m Message) IsSend() bool { return m.Direction == DirSend || m.Direction == DirSend2 }

// IsSystem 报告这条消息是否是系统消息。
func (m Message) IsSystem() bool { return m.Direction == DirSystem }

// Text 把所有文本段拼接成一段纯文本，便于导出纯文本/搜索。
func (m Message) Text() string {
	var b []byte
	for _, s := range m.Segments {
		if s.Kind == SegText && s.Text != "" {
			b = append(b, s.Text...)
		}
	}
	return string(b)
}

// Plain 返回这条消息的可读摘要：未知类型退化为类型名，保证导出不会丢内容。
func (m Message) Plain() string {
	var parts []string
	for _, s := range m.Segments {
		if t := s.Plain(); t != "" {
			parts = append(parts, t)
		}
	}
	if len(parts) > 0 {
		return join(parts, " ")
	}
	return ""
}

func join(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}

// Segment 是 40800 中的一个 MsgContent 段。一条消息可以有多段（图文混排）。
type Segment struct {
	Kind int32 `json:"kind"` // 45002，取值见 Seg* 常量

	// 文本
	Text string `json:"text,omitempty"` // 45101

	// 媒体/文件
	FileName  string `json:"file_name,omitempty"`  // 45402
	FileSize  int64  `json:"file_size,omitempty"`  // 45405
	FileUUID  string `json:"file_uuid,omitempty"`  // 45503
	MD5       string `json:"md5,omitempty"`        // 45406（hex）
	LocalPath string `json:"local_path,omitempty"` // 45812 手机本地路径
	NTOSPath  string `json:"ntos_path,omitempty"`  // 45814 NTOS 路径
	URL       string `json:"url,omitempty"`        // 可用的 CDN 直链

	// 图片/视频
	Width    int32 `json:"width,omitempty"`    // 45411
	Height   int32 `json:"height,omitempty"`   // 45412
	Duration int32 `json:"duration,omitempty"` // 45410 秒

	// 表情
	FaceID   int32  `json:"face_id,omitempty"`   // 47601
	FaceText string `json:"face_text,omitempty"` // 47602 如 "/汪汪"

	// 引用回复
	ReplyTo   int64  `json:"reply_to,omitempty"`   // 47401 被引用消息 ID
	ReplyText string `json:"reply_text,omitempty"` // 47413 被引用内容摘要

	// 系统/通话/转发
	SysContent   string `json:"sys_content,omitempty"`   // 80900
	CallType     int32  `json:"call_type,omitempty"`     // 48151
	CallDuration int32  `json:"call_duration,omitempty"` // 48152
	CallDesc     string `json:"call_desc,omitempty"`     // 48153
	FwdToken     string `json:"fwd_token,omitempty"`     // 47902
	FwdUUID      string `json:"fwd_uuid,omitempty"`      // 47904

	// 位置/名片
	CardText string `json:"card_text,omitempty"` // 45923

	// 解析失败时保留原始字节，绝不静默丢弃内容
	Raw []byte `json:"-"`
}

// KindName 返回段类型的可读名，用于导出时展示未知类型。
func (s Segment) KindName() string {
	switch s.Kind {
	case SegText:
		return "文本"
	case SegImage:
		return "图片"
	case SegFile:
		return "文件"
	case SegVoice:
		return "语音"
	case SegVideo:
		return "视频"
	case SegFace:
		return "表情"
	case SegReply:
		return "引用"
	case SegGrayTip:
		return "系统提示"
	case SegRedBag:
		return "红包"
	case SegArk:
		return "卡片"
	case SegMarketFace:
		return "商城表情"
	case SegMarkdown:
		return "Markdown"
	case SegLegacyForward:
		return "合并转发"
	case SegMarkdownBtn:
		return "按钮"
	case SegLiveRecord:
		return "通话"
	default:
		return "未知类型"
	}
}

// Plain 返回该段的可读文本。未知类型返回 [类型名]，保证导出不丢内容。
func (s Segment) Plain() string {
	switch s.Kind {
	case SegText:
		return s.Text
	case SegImage, SegVideo:
		return "[图片]"
	case SegFile:
		return "[文件] " + s.FileName
	case SegVoice:
		return "[语音]"
	case SegFace:
		if s.FaceText != "" {
			return s.FaceText
		}
		return "[表情]"
	case SegReply:
		if s.ReplyText != "" {
			return "[引用] " + s.ReplyText
		}
		return "[引用]"
	case SegGrayTip:
		if s.SysContent != "" {
			return "[系统] " + s.SysContent
		}
		return "[系统提示]"
	case SegRedBag:
		return "[红包]"
	case SegArk:
		return "[卡片]"
	case SegMarketFace:
		return "[商城表情]"
	case SegMarkdown:
		return s.Text
	case SegLegacyForward:
		return "[合并转发]"
	case SegLiveRecord:
		if s.CallDesc != "" {
			return "[通话] " + s.CallDesc
		}
		return "[通话]"
	}
	if s.Text != "" {
		return s.Text
	}
	return "[" + s.KindName() + "]"
}

// KindLabel 用于 JSON 导出：段类型的稳定英文名。
func (s Segment) KindLabel() string {
	switch s.Kind {
	case SegText:
		return "text"
	case SegImage:
		return "image"
	case SegFile:
		return "file"
	case SegVoice:
		return "voice"
	case SegVideo:
		return "video"
	case SegFace:
		return "face"
	case SegReply:
		return "reply"
	case SegGrayTip:
		return "system"
	case SegRedBag:
		return "redbag"
	case SegArk:
		return "ark"
	case SegMarketFace:
		return "market_face"
	case SegMarkdown:
		return "markdown"
	case SegLegacyForward:
		return "forward"
	case SegMarkdownBtn:
		return "button"
	case SegLiveRecord:
		return "call"
	default:
		return "unknown"
	}
}

// IsPlaceholder 报告这条记录是否是库里的占位/残行。
//
// nt_msg.db 里存在 40050=0（时间戳为零）且没有正文的行——它们是删除、迁库、
// 或写入中断留下的空壳。真实消息一定有时间戳，把这类行当消息导出只会产出
// 一堆 "1970-01-01 未知 空内容"，所以统一在读取阶段丢弃。
func (m Message) IsPlaceholder() bool {
	if m.Timestamp != 0 {
		return false
	}
	// 时间戳为零但确实带了正文时保留（极少数旧库如此），避免误删。
	return len(m.Segments) == 0
}
