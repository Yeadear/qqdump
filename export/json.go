package export

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Yeadear/qqdump/model"
)

// JSON 是结构化中间格式：完整保留解析出的一切，供后续工具消费。
type JSON struct {
	GeneratedAt string     `json:"generated_at"`
	Tool        string     `json:"tool"`
	Source      string     `json:"source,omitempty"`
	Count       int        `json:"conversation_count"`
	Convers     []JSONConv `json:"conversations"`
}

// JSONConv 是一个会话。
type JSONConv struct {
	ID       int64     `json:"id"`
	Kind     string    `json:"kind"`
	PeerUIN  int64     `json:"peer_uin"`
	PeerUID  string    `json:"peer_uid,omitempty"`
	Name     string    `json:"name,omitempty"`
	Messages []JSONMsg `json:"messages"`
}

// JSONMsg 是一条消息。
type JSONMsg struct {
	ID         int64         `json:"id"`
	Time       string        `json:"time"`
	Timestamp  int64         `json:"timestamp"`
	IsSend     bool          `json:"is_send"`
	Direction  int           `json:"direction"`
	SenderUIN  int64         `json:"sender_uin"`
	SenderName string        `json:"sender_name,omitempty"`
	Segments   []JSONSegment `json:"segments"`
}

// JSONSegment 是一个消息段。
type JSONSegment struct {
	Kind          string `json:"kind"`
	KindID        int32  `json:"kind_id"`
	Text          string `json:"text,omitempty"`
	FileName      string `json:"file_name,omitempty"`
	FileSize      int64  `json:"file_size,omitempty"`
	FileSizeHuman string `json:"file_size_human,omitempty"`
	MD5           string `json:"md5,omitempty"`
	URL           string `json:"url,omitempty"`
	Path          string `json:"path,omitempty"`
	Width         int32  `json:"width,omitempty"`
	Height        int32  `json:"height,omitempty"`
	Duration      int32  `json:"duration,omitempty"`
	FaceID        int32  `json:"face_id,omitempty"`
	FaceText      string `json:"face_text,omitempty"`
	ReplyTo       int64  `json:"reply_to,omitempty"`
	ReplyText     string `json:"reply_text,omitempty"`
	HasRaw        bool   `json:"has_raw,omitempty"`
}

// WriteJSON 把会话导出为 JSON。
func WriteJSON(w io.Writer, convs []model.Conversation, source string) error {
	doc := JSON{
		GeneratedAt: time.Now().In(cst).Format("2006-01-02 15:04:05"),
		Tool:        "qqdump",
		Source:      source,
		Count:       len(convs),
		Convers:     make([]JSONConv, 0, len(convs)),
	}
	for _, c := range convs {
		jc := JSONConv{
			ID:       c.ID,
			Kind:     c.KindLabel(),
			PeerUIN:  c.PeerUIN,
			PeerUID:  c.PeerUID,
			Name:     c.Title(),
			Messages: make([]JSONMsg, 0, len(c.Messages)),
		}
		for _, m := range c.Messages {
			jm := JSONMsg{
				ID:         m.ID,
				Time:       FmtTime(m.Timestamp),
				Timestamp:  m.Timestamp,
				IsSend:     m.IsSend(),
				Direction:  m.Direction,
				SenderUIN:  m.SenderUIN,
				SenderName: SenderName(m),
				Segments:   make([]JSONSegment, 0, len(m.Segments)),
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
			jc.Messages = append(jc.Messages, jm)
		}
		doc.Convers = append(doc.Convers, jc)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // 中文与 URL 保持原样
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("export: 写 JSON: %w", err)
	}
	return nil
}

func firstPath(s model.Segment) string {
	if s.LocalPath != "" {
		return s.LocalPath
	}
	return s.NTOSPath
}
