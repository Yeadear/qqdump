package qqdump

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Yeadear/qqdump/db"
	"github.com/Yeadear/qqdump/model"
	"github.com/Yeadear/qqdump/msgproto"
)

// cols 是建测试明文库用的列，刻意只取协议里最关键的几个。
var cols = []string{
	db.ColID, db.ColTimestamp, db.ColDirection, db.ColSenderUIN,
	db.ColPeerUIN, db.ColSessionID, db.ColSenderName, db.ColBody,
}

// newPlain 建一个明文库，往里塞 n 条消息，返回库路径。
//
// 这条链路不需要密钥，因此也可以用来验证"拿着别人给的明文库直接读"。
func newPlain(t *testing.T, table string, rows []testRow) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plain.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = fmt.Sprintf(`"%s"`, c)
	}
	if _, err := raw.Exec(fmt.Sprintf(`CREATE TABLE %s (%s)`, table, strings.Join(quoted, ", "))); err != nil {
		t.Fatal(err)
	}

	insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?,?,?,?,?,?)`, table, strings.Join(quoted, ", "))
	for _, r := range rows {
		body, err := proto.Marshal(&msgproto.MsgBody{
			Content: []*msgproto.MsgContent{
				{MsgId: 1, ContentType: model.SegText, Text: []byte(r.text)},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(insert, r.id, r.ts, r.dir, r.sender, r.peer, r.session, r.name, body); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()
	return path
}

type testRow struct {
	id      int64
	ts      int64
	dir     int
	sender  int64
	peer    int64
	session int64
	name    string
	text    string
}

func TestLoadC2C(t *testing.T) {
	rows := []testRow{
		{1, 1700000000, 0, 10001, 10001, 5001, "小明", "你好"},
		{2, 1700000060, 1, 10000, 10001, 5001, "我", "在的"},
		{3, 1700000120, 0, 10002, 10002, 5002, "小红", "另一段对话"},
	}
	path := newPlain(t, db.TableC2C, rows)

	convs, err := Load(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 2 {
		t.Fatalf("会话数 = %d, want 2（10001 和 10002）", len(convs))
	}

	// 会话按对方 QQ 排序，私聊的展示名应该取对方的昵称
	first := convs[0]
	if first.PeerUIN != 10001 {
		t.Errorf("第 1 个会话 = %d, want 10001", first.PeerUIN)
	}
	if first.Name != "小明" {
		t.Errorf("会话名 = %q, want 小明", first.Name)
	}
	if first.Type != model.ChatC2C {
		t.Errorf("类型 = %d, want 私聊", first.Type)
	}
	if len(first.Messages) != 2 {
		t.Fatalf("消息数 = %d, want 2", len(first.Messages))
	}
	// 消息必须按时间升序
	if first.Messages[0].ID != 1 || first.Messages[1].ID != 2 {
		t.Errorf("消息顺序 = %d, %d", first.Messages[0].ID, first.Messages[1].ID)
	}
	if !first.Messages[1].IsSend() {
		t.Error("第 2 条应是本人发送")
	}
	if first.Messages[0].Text() != "你好" {
		t.Errorf("文本 = %q", first.Messages[0].Text())
	}
}

func TestLoadGroup(t *testing.T) {
	rows := []testRow{
		{1, 1700000000, 0, 20001, 888888, 9001, "老王", "大家好"},
	}
	path := newPlain(t, db.TableGroup, rows)

	convs, err := Load(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 1 {
		t.Fatalf("会话数 = %d", len(convs))
	}
	if convs[0].Type != model.ChatGroup {
		t.Errorf("类型 = %d, want 群聊", convs[0].Type)
	}
}

// 只要 c2c 或只要 group 时，另一类不该出现。
func TestLoadKindFilter(t *testing.T) {
	// 同一个明文库里放两张表
	c2cRows := []testRow{{1, 1700000000, 0, 10001, 10001, 5001, "小明", "私聊消息"}}
	groupRows := []testRow{{1, 1700000000, 0, 20001, 888888, 9001, "老王", "群消息"}}

	path := newPlain(t, db.TableC2C, c2cRows)
	// 往同一个库里再建一张群表
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	qcols := make([]string, len(cols))
	for i, c := range cols {
		qcols[i] = fmt.Sprintf(`"%s"`, c)
	}
	if _, err := raw.Exec(fmt.Sprintf(`CREATE TABLE %s (%s)`, db.TableGroup, strings.Join(qcols, ", "))); err != nil {
		t.Fatal(err)
	}
	for _, r := range groupRows {
		body, _ := proto.Marshal(&msgproto.MsgBody{
			Content: []*msgproto.MsgContent{
				{MsgId: 1, ContentType: model.SegText, Text: []byte(r.text)},
			},
		})
		if _, err := raw.Exec(fmt.Sprintf(`INSERT INTO %s (%s) VALUES (?,?,?,?,?,?,?,?)`,
			db.TableGroup, strings.Join(qcols, ", ")),
			r.id, r.ts, r.dir, r.sender, r.peer, r.session, r.name, body); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	convs, err := Load(path, Options{Kinds: []string{"c2c"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 1 || convs[0].Type != model.ChatC2C {
		t.Errorf("kind=c2c 的筛选结果 = %+v", convs)
	}

	convs, err = Load(path, Options{Kinds: []string{"group"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 1 || convs[0].Type != model.ChatGroup {
		t.Errorf("kind=group 的筛选结果 = %+v", convs)
	}

	convs, err = Load(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 2 {
		t.Errorf("不筛选时应读到 2 个会话，得到 %d", len(convs))
	}
}

// 按对方 QQ 精确导出单个会话。
func TestLoadPeerFilter(t *testing.T) {
	rows := []testRow{
		{1, 1700000000, 0, 10001, 10001, 5001, "小明", "a"},
		{2, 1700000060, 0, 10002, 10002, 5002, "小红", "b"},
	}
	path := newPlain(t, db.TableC2C, rows)

	convs, err := Load(path, Options{Peers: []int64{10002}})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 1 || convs[0].PeerUIN != 10002 {
		t.Errorf("筛选结果 = %+v", convs)
	}
}

func TestLoadTimeFilter(t *testing.T) {
	rows := []testRow{
		{1, 1700000000, 0, 10001, 10001, 5001, "小明", "旧"},
		{2, 1700001000, 0, 10001, 10001, 5001, "小明", "新"},
	}
	path := newPlain(t, db.TableC2C, rows)

	convs, err := Load(path, Options{Since: 1700000500})
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 1 {
		t.Fatalf("会话数 = %d", len(convs))
	}
	if len(convs[0].Messages) != 1 || convs[0].Messages[0].ID != 2 {
		t.Errorf("时间筛选结果 = %+v", convs[0].Messages)
	}
}

// 拿到明文库后不需要密钥，让工具直接在上面读。
func TestLoadNeedsNoKey(t *testing.T) {
	path := newPlain(t, db.TableC2C, []testRow{{1, 1700000000, 0, 10001, 10001, 5001, "小明", "x"}})
	if _, err := Load(path, Options{}); err != nil {
		t.Errorf("明文读取不该要密钥: %v", err)
	}
}

// 密钥和 UID 都没给时，应该明确报错而不是拿空密钥去试。
func TestDumpRequiresKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.db")
	// 造一个够长的假文件，好让它走到密钥检查那一步
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Dump(path, Options{})
	if err == nil {
		t.Fatal("既没有 Key 也没有 UID 时应当报错")
	}
	if !strings.Contains(err.Error(), "密钥") && !strings.Contains(err.Error(), "Key") {
		t.Errorf("错误信息没说清缺的是什么：%v", err)
	}
}
