package db

import (
	"fmt"
	"strings"

	"github.com/Yeadear/qqdump/internal/model"
	"github.com/Yeadear/qqdump/internal/msgproto"
)

// 列名常量。它们是协议字段编号，不是人为取的名字。
const (
	ColID         = "40001"
	ColMsgRandom  = "40002"
	ColSeq        = "40003"
	ColClientSeq  = "40005"
	ColServerSeq  = "40006"
	ColChatType   = "40010"
	ColMsgType    = "40011"
	ColSubType    = "40012"
	ColDirection  = "40013"
	ColSenderUID  = "40020"
	ColPeerUID    = "40021"
	ColSessionID  = "40027"
	ColPeerUIN    = "40030"
	ColSenderUIN  = "40033"
	ColTimestamp  = "40050"
	ColDateIndex  = "40058"
	ColSenderCard = "40090"
	ColSenderName = "40093"
	Col40600      = "40600"
	Col40605      = "40605"
	ColBody       = "40800"
	Col40801      = "40801"
	ColReplySeq   = "40850"
	ColReactTs    = "40851"
	Col40900      = "40900"
)

// 读取顺序固定：缺失的列用 NULL 占位，这样 Scan 的位置永远对得上，
// 不同 QQ 版本的库不需要各自的分支。
var readOrder = []string{
	ColID, ColMsgRandom, ColSeq, ColClientSeq, ColServerSeq,
	ColChatType, ColMsgType, ColSubType, ColDirection,
	ColSenderUID, ColPeerUID, ColSessionID, ColPeerUIN, ColSenderUIN,
	ColSenderCard, ColSenderName,
	ColTimestamp, ColDateIndex,
	ColBody, Col40600, Col40605, Col40801, Col40900,
	ColReplySeq, ColReactTs,
}

// Filter 描述一次消息读取的筛选条件。零值表示不限。
type Filter struct {
	SessionID int64 // 按 40027 精确筛选
	PeerUIN   int64 // 按 40030 精确筛选（私聊对方 QQ / 群号）
	Since     int64 // 起始时间戳（含）
	Until     int64 // 结束时间戳（含）
	Limit     int   // 最多返回多少条，0 表示不限
	Offset    int   // 偏移量
	Desc      bool  // 按时间倒序
}

// ReadMessages 读取一个表里的消息，按时间排序。
func (d *DB) ReadMessages(table string, f Filter) ([]model.Message, error) {
	selects := make([]string, 0, len(readOrder))
	for _, c := range readOrder {
		if d.Has(table, c) {
			selects = append(selects, quote(c))
		} else {
			selects = append(selects, "NULL")
		}
	}

	q := fmt.Sprintf(`SELECT %s FROM %s`, strings.Join(selects, ", "), quote(table))

	var where []string
	var args []any
	if f.SessionID != 0 && d.Has(table, ColSessionID) {
		where = append(where, quote(ColSessionID)+" = ?")
		args = append(args, f.SessionID)
	}
	if f.PeerUIN != 0 && d.Has(table, ColPeerUIN) {
		where = append(where, quote(ColPeerUIN)+" = ?")
		args = append(args, f.PeerUIN)
	}
	if f.Since > 0 && d.Has(table, ColTimestamp) {
		where = append(where, quote(ColTimestamp)+" >= ?")
		args = append(args, f.Since)
	}
	if f.Until > 0 && d.Has(table, ColTimestamp) {
		where = append(where, quote(ColTimestamp)+" <= ?")
		args = append(args, f.Until)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}

	if d.Has(table, ColTimestamp) {
		if f.Desc {
			q += " ORDER BY " + quote(ColTimestamp) + " DESC, " + quote(ColID) + " DESC"
		} else {
			q += " ORDER BY " + quote(ColTimestamp) + " ASC, " + quote(ColID) + " ASC"
		}
	} else if d.Has(table, ColID) {
		q += " ORDER BY " + quote(ColID) + " ASC"
	}

	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
		if f.Offset > 0 {
			q += fmt.Sprintf(" OFFSET %d", f.Offset)
		}
	}

	rows, err := d.DB.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("db: 读取 %s: %w", table, err)
	}
	defer rows.Close()

	var out []model.Message
	for rows.Next() {
		slots := make([]any, len(readOrder))
		vals := make([]any, len(readOrder))
		for i := range vals {
			slots[i] = &vals[i]
		}
		if err := rows.Scan(slots...); err != nil {
			return nil, fmt.Errorf("db: 扫描 %s 的一行: %w", table, err)
		}
		out = append(out, fill(vals, chatTypeOf(table)))
	}
	return out, rows.Err()
}

// fill 把一行按 readOrder 填入 Message。
func fill(vals []any, chatType int) model.Message {
	m := model.Message{ChatType: chatType}
	for i, col := range readOrder {
		v := vals[i]
		switch col {
		case ColID:
			m.ID = toInt64(v)
		case ColMsgRandom:
			m.MsgRandom = toInt64(v)
		case ColSeq:
			m.Seq = toInt64(v)
		case ColClientSeq:
			m.ClientSeq = toInt64(v)
		case ColServerSeq:
			m.ServerSeq = toInt64(v)
		case ColChatType:
			if n := toInt64(v); n != 0 {
				m.ChatType = int(n)
			}
		case ColMsgType:
			m.MsgType = int(toInt64(v))
		case ColSubType:
			m.SubType = toInt64(v)
		case ColDirection:
			m.Direction = int(toInt64(v))
		case ColSenderUID:
			m.SenderUID = toText(v)
		case ColPeerUID:
			m.PeerUID = toText(v)
		case ColSessionID:
			m.SessionID = toInt64(v)
		case ColPeerUIN:
			m.PeerUIN = toInt64(v)
		case ColSenderUIN:
			m.SenderUIN = toInt64(v)
		case ColSenderCard:
			m.SenderCard = toText(v)
		case ColSenderName:
			m.SenderName = toText(v)
		case ColTimestamp:
			m.Timestamp = toInt64(v)
		case ColDateIndex:
			m.DateIndex = toInt64(v)
		case ColBody:
			m.Segments = parseSegments(v)
		case Col40600:
			m.Raw40600 = toBytes(v)
		case Col40605:
			m.Raw40605 = toBytes(v)
		case Col40801:
			m.Raw40801 = toBytes(v)
		case Col40900:
			m.Raw40900 = toBytes(v)
		case ColReplySeq:
			m.ReplySeq = toInt64(v)
		case ColReactTs:
			m.ReactionTs = toInt64(v)
		}
	}
	if m.SenderName == "" {
		m.SenderName = m.SenderCard
	}
	return m
}

// parseSegments 解析 40800 消息体。解析失败时 msgproto 会保留原始字节，
// 这里不做任何兜底丢弃。
func parseSegments(v any) []model.Segment {
	return msgproto.ParseBody(toBytes(v))
}

func toText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	case int64:
		return fmt.Sprint(t)
	}
	return ""
}

func toBytes(v any) []byte {
	switch t := v.(type) {
	case nil:
		return nil
	case []byte:
		return t
	case string:
		return []byte(t)
	}
	return nil
}
