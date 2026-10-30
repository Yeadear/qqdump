package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Yeadear/qqdump/model"
	"github.com/Yeadear/qqdump/msgproto"
)

// newPlainDB 建一个含指定列的明文库并打开它。
// cols 是列名（协议字段编号），刻意允许只给一部分，用来验证缺失列的兜底。
func newPlainDB(t *testing.T, table string, cols []string) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = quote(c)
	}
	if _, err := raw.Exec(fmt.Sprintf(`CREATE TABLE %s (%s)`, quote(table), strings.Join(quoted, ", "))); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// body 构造一条 40800 的内容。
func body(t *testing.T, text string) []byte {
	t.Helper()
	data, err := proto.Marshal(&msgproto.MsgBody{
		Content: []*msgproto.MsgContent{
			{MsgId: 1, ContentType: model.SegText, Text: []byte(text)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReadMessages(t *testing.T) {
	cols := []string{ColID, ColTimestamp, ColDirection, ColSenderUIN,
		ColPeerUIN, ColSenderName, ColBody}
	d := newPlainDB(t, TableC2C, cols)

	insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?,?,?,?,?)`,
		quote(TableC2C), strings.Join(quoteAll(cols), ", "))
	if _, err := d.DB.Exec(insert, 1, 1700000000, 0, 10001, 10001, "小明", body(t, "你好")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DB.Exec(insert, 2, 1700000060, 1, 10000, 10001, "我", body(t, "在的")); err != nil {
		t.Fatal(err)
	}

	msgs, err := d.ReadMessages(TableC2C, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("读到 %d 条, want 2", len(msgs))
	}

	m := msgs[0]
	if m.ID != 1 || m.Timestamp != 1700000000 {
		t.Errorf("ID/时间 = %d/%d", m.ID, m.Timestamp)
	}
	if m.SenderUIN != 10001 || m.PeerUIN != 10001 {
		t.Errorf("发送者/对方 = %d/%d", m.SenderUIN, m.PeerUIN)
	}
	if m.SenderName != "小明" {
		t.Errorf("SenderName = %q", m.SenderName)
	}
	if m.IsSend() {
		t.Error("Direction=0 不该被当成本人发送")
	}
	if len(m.Segments) != 1 || m.Segments[0].Text != "你好" {
		t.Errorf("消息段解析失败：%+v", m.Segments)
	}
	if m.ChatType != model.ChatC2C {
		t.Errorf("ChatType = %d, want 私聊", m.ChatType)
	}

	second := msgs[1]
	if !second.IsSend() {
		t.Error("Direction=1 应是本人发送")
	}
}

// 真实库里不同 QQ 版本的列集合并不一致，缺的列必须能兜住而不是报错。
func TestReadMessagesWithMissingColumns(t *testing.T) {
	// 只给三列，其余全部缺失
	cols := []string{ColID, ColTimestamp, ColBody}
	d := newPlainDB(t, TableC2C, cols)

	insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?)`,
		quote(TableC2C), strings.Join(quoteAll(cols), ", "))
	if _, err := d.DB.Exec(insert, 7, 1700000000, body(t, "只有三列")); err != nil {
		t.Fatal(err)
	}

	msgs, err := d.ReadMessages(TableC2C, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("读到 %d 条, want 1", len(msgs))
	}
	m := msgs[0]
	if m.ID != 7 {
		t.Errorf("ID = %d, want 7", m.ID)
	}
	if m.SenderUIN != 0 || m.PeerUIN != 0 || m.SenderName != "" {
		t.Errorf("缺失列应取零值，得到 %d/%d/%q", m.SenderUIN, m.PeerUIN, m.SenderName)
	}
	if len(m.Segments) != 1 || m.Segments[0].Text != "只有三列" {
		t.Errorf("消息段解析失败：%+v", m.Segments)
	}
}

func TestReadMessagesFilter(t *testing.T) {
	cols := []string{ColID, ColTimestamp, ColPeerUIN, ColBody}
	d := newPlainDB(t, TableC2C, cols)

	insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?,?)`,
		quote(TableC2C), strings.Join(quoteAll(cols), ", "))
	for i, p := range []int64{10001, 10001, 10002} {
		if _, err := d.DB.Exec(insert, i+1, int64(1700000000+i), p, body(t, "m")); err != nil {
			t.Fatal(err)
		}
	}

	msgs, err := d.ReadMessages(TableC2C, Filter{PeerUIN: 10002})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].PeerUIN != 10002 {
		t.Errorf("按会话筛选失败：%+v", msgs)
	}

	msgs, err = d.ReadMessages(TableC2C, Filter{Since: 1700000002})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Errorf("按时间筛选得到 %d 条, want 1", len(msgs))
	}

	msgs, err = d.ReadMessages(TableC2C, Filter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Errorf("Limit 生效失败，得到 %d 条", len(msgs))
	}
}

func TestSessions(t *testing.T) {
	cols := []string{ColID, ColTimestamp, ColPeerUIN, ColSessionID, ColBody}
	d := newPlainDB(t, TableC2C, cols)

	insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?,?,?)`,
		quote(TableC2C), strings.Join(quoteAll(cols), ", "))
	for i, p := range []int64{10001, 10001, 10002} {
		sid := int64(5001)
		if p == 10002 {
			sid = 5002
		}
		if _, err := d.DB.Exec(insert, i+1, int64(1700000000+i), p, sid, body(t, "m")); err != nil {
			t.Fatal(err)
		}
	}

	sessions, err := d.Sessions(TableC2C)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("会话数 = %d, want 2", len(sessions))
	}
	count := map[int64]int{}
	for _, s := range sessions {
		count[s.PeerUIN] = int(s.Count)
	}
	if count[10001] != 2 || count[10002] != 1 {
		t.Errorf("各会话消息数 = %v", count)
	}
}

func TestOpenRejectsNonMessageDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE unrelated (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("不含消息表的库应当报错")
	}
}

// 群聊与私聊共用读取逻辑，但表类型要区分开。
func TestGroupTable(t *testing.T) {
	cols := []string{ColID, ColTimestamp, ColDirection, ColSenderUIN,
		ColPeerUIN, ColSenderName, ColSenderCard, ColBody}
	d := newPlainDB(t, TableGroup, cols)

	insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?,?,?,?,?,?)`,
		quote(TableGroup), strings.Join(quoteAll(cols), ", "))
	if _, err := d.DB.Exec(insert, 1, 1700000000, 0, 20001, 888888, "老王", "群里的老王", body(t, "大家好")); err != nil {
		t.Fatal(err)
	}

	msgs, err := d.ReadMessages(TableGroup, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("读到 %d 条", len(msgs))
	}
	if msgs[0].ChatType != model.ChatGroup {
		t.Errorf("ChatType = %d, want 群聊", msgs[0].ChatType)
	}
	if msgs[0].SenderCard != "群里的老王" {
		t.Errorf("群名片 = %q", msgs[0].SenderCard)
	}
}
