// Package msgproto 把 nt_msg.db 的 40800 BLOB 解析成领域模型。
//
// 40800 的外层是 MsgBody{repeated MsgContent content = 40800}，一条消息可以
// 有多个段（图文混排），解析时必须保留段顺序。
//
// 解析策略是"尽力而为"：
//  1. 先按 proto3 强类型解码（生成的 nt_msg_40800.pb.go）；
//  2. 失败则退化为保留原始字节的单个 unknown 段；
//  3. 个别只有 varint 形态（wire key 40800-1）的老记录无法按本 schema 解码，
//     同样保留原始字节。
// 无论如何都不静默丢弃内容。
package msgproto

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/Yeadear/qqdump/internal/model"
)

// ParseBody 解析 40800 列的内容为消息段列表。
// raw 为 nil 或空时返回 nil。
func ParseBody(raw []byte) []model.Segment {
	if len(raw) == 0 {
		return nil
	}
	var body MsgBody
	if err := proto.Unmarshal(raw, &body); err != nil {
		return []model.Segment{{Raw: raw}}
	}
	if len(body.GetContent()) == 0 {
		// 老 wire 形态（40800 以 varint 出现）会走到这里：拿不到 MsgContent，
		// 但原始字节还在，不丢内容。
		return []model.Segment{{Raw: raw}}
	}
	segs := make([]model.Segment, 0, len(body.GetContent()))
	for _, c := range body.GetContent() {
		segs = append(segs, convert(c))
	}
	return segs
}

// ParseSingle 解析单个 MsgContent 的原始字节，用于 40900 等内嵌快照。
func ParseSingle(raw []byte) model.Segment {
	if len(raw) == 0 {
		return model.Segment{}
	}
	var c MsgContent
	if err := proto.Unmarshal(raw, &c); err != nil {
		return model.Segment{Raw: raw}
	}
	return convert(&c)
}

func convert(c *MsgContent) model.Segment {
	s := model.Segment{Kind: c.GetContentType()}

	s.Text = decodeText(c.GetText())
	s.FileName = decodeText(c.GetFilename())
	s.FileSize = c.GetFilesize()
	s.FileUUID = c.GetFileUuid()
	s.MD5 = hex.EncodeToString(c.GetMd5Raw())
	s.LocalPath = c.GetLocalPath()
	s.NTOSPath = c.GetNtosPath()
	s.URL = pickURL(c)

	s.Width = c.GetImgWidth()
	s.Height = c.GetImgHeight()
	s.Duration = c.GetDuration()

	s.FaceID = c.GetVideoFlag()
	s.FaceText = string(c.GetVideoText())

	s.ReplyTo = c.GetReplyMsgId()
	s.ReplyText = c.GetReplySummary()

	s.SysContent = c.GetSysContent()
	s.CallType = c.GetCallType()
	s.CallDuration = c.GetCallDuration()
	s.CallDesc = c.GetCallDesc()
	s.FwdToken = c.GetFwdToken()
	s.FwdUUID = c.GetFwdUuid()

	s.CardText = c.GetNcText()

	return s
}

// pickURL 选出一条可用的媒体直链。
// 优先拼接 CDN host + 主 URL；其次是本地路径；最后是 NTOS 路径。
func pickURL(c *MsgContent) string {
	host := strings.TrimSuffix(c.GetCdnHost(), "/")
	for _, u := range []string{c.GetCdnUrl_1(), c.GetCdnUrl_2(), c.GetCdnUrl_3()} {
		if u == "" {
			continue
		}
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return u
		}
		if host != "" {
			return "https://" + host + "/" + strings.TrimPrefix(u, "/")
		}
	}
	if p := c.GetLocalPath(); p != "" {
		return p
	}
	return c.GetNtosPath()
}

// decodeText 把 45101/45402 等原始字节按 UTF-8 解码成文本。
//
// 这些字段在协议里是 bytes：文档明确指出少数字节序列会被动态解析器误判成
// 子消息，因此必须优先按原始 bytes 解码，而不是按嵌套消息解析。
// 非法 UTF-8 时逐字节保留可打印部分，不做整体丢弃。
func decodeText(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) {
		return strings.TrimRight(string(b), "\x00")
	}
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			continue
		}
		if c < 0x80 {
			sb.WriteByte(c)
		} else {
			sb.WriteRune('\uFFFD')
		}
	}
	return strings.TrimRight(sb.String(), "\x00")
}
