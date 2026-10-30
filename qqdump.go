// Package qqdump 是一个纯 Go 的安卓 QQ（NT）聊天记录导出器。
//
// 它既是命令行工具（cmd/qqdump），也是可以直接 import 的库：
//
//	convs, err := qqdump.Dump("nt_msg.db", qqdump.Options{UID: "u_xxx"})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	export.WriteJSON(os.Stdout, convs, "nt_msg.db")
//
// 完整链路是四步，每一步都可以单独使用：
//
//  1. account：扫描 QQ 数据目录定位 nt_msg.db，从 1024 字节头读出 rand
//  2. cipher：剥掉自定义头，用 md5(md5(uid)+rand) 解密 SQLCipher
//  3. db + msgproto：读出原始行，把 40800 的 Protobuf 解析成消息段
//  4. export：渲染成 JSON / Markdown / HTML
package qqdump

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Yeadear/qqdump/account"
	"github.com/Yeadear/qqdump/cipher"
	"github.com/Yeadear/qqdump/db"
	"github.com/Yeadear/qqdump/model"
)

// Options 描述一次导出的输入与筛选条件。
type Options struct {
	// Key 是直接给出的数据库密钥（32 位 hex）。给了它就不再从 UID 派生。
	Key string
	// UID 是账号的 NT UID，与库头的 rand 一起派生密钥。Key 为空时必需。
	UID string

	// PlainPath 指定解密后的明文库落在哪里。为空时用临时文件，读完即删。
	// 想留着明文库方便别的工具查看，就把这里填上。
	PlainPath string

	// Since / Until 是按消息时间戳（Unix 秒）筛选的范围，0 表示不限。
	Since int64
	Until int64

	// Limit 是每个会话最多读多少条，0 表示不限。
	Limit int

	// Kinds 限定要读的会话类型：c2c、group。为空表示都要。
	Kinds []string

	// Peers 限定只导出这些会话（私聊填对方 QQ 号，群聊填群号）。为空表示全部。
	Peers []int64
}

// Dump 一步完成"解密 → 读取 → 组装会话"。
//
// src 是加密的 nt_msg.db（含 1024 字节自定义头）。它不会修改源文件。
func Dump(src string, opt Options) ([]model.Conversation, error) {
	key := opt.Key
	if key == "" {
		if opt.UID == "" {
			return nil, fmt.Errorf("qqdump: 需要密钥：请给出 Key，或给出 UID 由库头 rand 派生")
		}
		head, err := account.ParseHead(src)
		if err != nil {
			return nil, fmt.Errorf("qqdump: 读取 %s 的头部失败: %w", src, err)
		}
		if head == nil || head.Rand == "" {
			return nil, fmt.Errorf("qqdump: %s 的头部里没有 rand，无法派生密钥，请直接给出 Key", src)
		}
		key = account.DeriveKey(opt.UID, head.Rand)
	}

	plain := opt.PlainPath
	tmp := ""
	if plain == "" {
		f, err := os.CreateTemp("", "qqdump-plain-*.db")
		if err != nil {
			return nil, fmt.Errorf("qqdump: 创建临时文件失败: %w", err)
		}
		tmp = f.Name()
		plain = tmp
		f.Close()
	}
	if tmp != "" {
		defer os.Remove(tmp)
	}

	if err := cipher.DecryptNTQQFile(src, plain, key); err != nil {
		return nil, err
	}
	return Load(plain, opt)
}

// Load 从一个已经解密的明文 SQLite 库读出会话。
//
// 明文库可以直接由 Dump 产出，也可以来自其他解密工具，因此拿到明文后
// 不需要再碰密钥。
func Load(plainPath string, opt Options) ([]model.Conversation, error) {
	d, err := db.Open(plainPath)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	var out []model.Conversation
	for _, table := range d.Tables() {
		kind := tableKind(table)
		if !wantKind(opt.Kinds, kind) {
			continue
		}

		sessions, err := d.Sessions(table)
		if err != nil {
			return nil, err
		}
		for _, s := range sessions {
			if !wantPeer(opt.Peers, s.PeerUIN) {
				continue
			}
			msgs, err := d.ReadMessages(table, db.Filter{
				PeerUIN: s.PeerUIN,
				Since:   opt.Since,
				Until:   opt.Until,
				Limit:   opt.Limit,
			})
			if err != nil {
				return nil, err
			}
			if len(msgs) == 0 {
				continue
			}
			c := model.Conversation{
				ID:       s.ID,
				PeerUIN:  s.PeerUIN,
				PeerUID:  s.PeerUID,
				Type:     kind,
				Name:     inferName(msgs, kind),
				Messages: msgs,
			}
			c.SortByTime()
			out = append(out, c)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].PeerUIN < out[j].PeerUIN
	})
	return out, nil
}

// tableKind 判断表对应私聊还是群聊。
func tableKind(table string) int {
	if table == db.TableGroup {
		return model.ChatGroup
	}
	return model.ChatC2C
}

func wantKind(kinds []string, kind int) bool {
	if len(kinds) == 0 {
		return true
	}
	want := "c2c"
	if kind == model.ChatGroup {
		want = "group"
	}
	for _, k := range kinds {
		if strings.EqualFold(k, want) {
			return true
		}
	}
	return false
}

func wantPeer(peers []int64, uin int64) bool {
	if len(peers) == 0 {
		return true
	}
	for _, p := range peers {
		if p == uin {
			return true
		}
	}
	return false
}

// inferName 推断会话的展示名。
//
// 私聊取对方最近一次使用的昵称（收到的消息里发的那条）；群聊没有群名可用，
// 就用群号。宁可显示号码，也不留空。
func inferName(msgs []model.Message, kind int) string {
	if kind == model.ChatGroup {
		for _, m := range msgs {
			if m.PeerUIN != 0 {
				return fmt.Sprintf("群 %d", m.PeerUIN)
			}
		}
		return "群聊"
	}
	// 私聊：对方就是"收到"的那些消息的发送者
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if m.Direction == model.DirRecv && m.SenderName != "" {
			return m.SenderName
		}
	}
	for _, m := range msgs {
		if m.SenderName != "" {
			return m.SenderName
		}
	}
	for _, m := range msgs {
		if m.PeerUIN != 0 {
			return fmt.Sprint(m.PeerUIN)
		}
	}
	return "私聊"
}

// WritePlain 只做解密这一步：把加密的 nt_msg.db 解成明文 SQLite。
// 想用别的工具直接查看数据库时用这个。
func WritePlain(src, dst, key string) error {
	return cipher.DecryptNTQQFile(src, dst, key)
}

// Accounts 扫描一个 QQ 数据根目录，返回找到的账号及其密钥。
//
// 根目录可以是手机上的 /data/data/com.tencent.mobileqq、adb pull 出来的
// 目录，或用户自己拷贝出来的任意一层目录。
func Accounts(root string) ([]account.Account, error) {
	s := &account.Scanner{Root: root}
	return s.Accounts()
}

// Head 读取一个 nt_msg.db 的自定义头。
func Head(path string) (*account.HeadInfo, error) {
	return account.ParseHead(path)
}

// BaseName 返回去掉常见数据库扩展名后的文件名，用于输出命名。
func BaseName(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
