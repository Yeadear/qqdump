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
//  1. account：按固定布局定位 nt_msg.db，从 1024 字节头读出 rand
//  2. cipher：剥掉自定义头，用 md5(md5(uid)+rand) 解密 SQLCipher
//  3. db + msgproto：读出原始行，把 40800 的 Protobuf 解析成消息段
//  4. export：渲染成 JSON / Markdown / HTML
package qqdump

import (
	"fmt"
	"log"
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

	// Tolerant 开启时，解密遇到个别坏页会跳过（写入零页占位）而非整体失败，
	// 读取阶段某张表/某个会话因坏页读不出时也会跳过而非整体失败——尽力导出
	// 其余数据。适用于源 db 仅有零散坏页的场景。
	Tolerant bool
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

	if opt.Tolerant {
		bad, derr := cipher.DecryptNTQQFileTolerant(src, plain, key)
		if derr != nil {
			return nil, derr
		}
		if len(bad) > 0 {
			log.Printf("警告: %s 解密时有 %d 个坏页（已跳过占位）：%v", src, len(bad), bad)
		}
	} else {
		if derr := cipher.DecryptNTQQFile(src, plain, key); derr != nil {
			return nil, derr
		}
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
			if opt.Tolerant {
				log.Printf("警告: 表 %s 读取会话列表失败（可能受坏页影响），跳过该表: %v", table, err)
				continue
			}
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
				if opt.Tolerant {
					log.Printf("警告: 会话 %d（表 %s）读取失败（可能受坏页影响），跳过: %v", s.PeerUIN, table, err)
					continue
				}
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

// Accounts 定位一个 QQ 数据目录下的账号，返回它们及其密钥。
//
// nt_msg.db 的路径是固定的（.../databases/nt_db/nt_qq_{hash}/nt_msg.db），
// 所以这里按布局拼路径、不遍历磁盘：根路径给 /、/data、QQ 数据目录、
// nt_db 目录或 nt_qq_{hash} 目录都能直接命中，耗时与设备上文件多少无关。
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

// StreamHandler 描述流式导出的三个回调。
//
// 流式导出的核心保证：磁盘上不产生明文库，内存里不积攒整库消息——
// 逐页解密、逐条回调，内存占用与库大小无关。
type StreamHandler struct {
	// Conversation 在每个会话开始导出时调用一次，用来决定输出文件名和格式。
	// meta 只带会话元数据，Messages 为空。
	Conversation func(meta model.Conversation) error

	// Message 每读到一条消息回调一次，调用方应立即写出，不要攒。
	Message func(m model.Message) error

	// Done 在一个会话读完时调用，用来收尾（关文件、写落款）。
	Done func(meta model.Conversation, count int) error
}

// DumpStream 流式导出：边解密边解析边回调，不落明文、不整库载入内存。
//
// 与 Dump 的区别只在内存与磁盘：Dump 会先解密成明文库、再用 SQL 把整表读进
// []Conversation；DumpStream 直接逐页解析 b-tree，磁盘永不出现明文副本，
// 内存峰值只有"单页 + 单条消息"。代价是会话顺序按库内物理顺序、
// 且消息按库内顺序（非严格时间序）回调。
func DumpStream(src string, opt Options, h StreamHandler) error {
	key := opt.Key
	if key == "" {
		if opt.UID == "" {
			return fmt.Errorf("qqdump: 需要密钥：请给出 Key，或给出 UID 由库头 rand 派生")
		}
		head, err := account.ParseHead(src)
		if err != nil {
			return fmt.Errorf("qqdump: 读取 %s 的头部失败: %w", src, err)
		}
		if head == nil || head.Rand == "" {
			return fmt.Errorf("qqdump: %s 的头部里没有 rand，无法派生密钥，请直接给出 Key", src)
		}
		key = account.DeriveKey(opt.UID, head.Rand)
	}

	sdb, err := db.OpenEncryptedStream(src, key, opt.Tolerant)
	if err != nil {
		return err
	}
	defer sdb.Close()

	for _, table := range sdb.Tables() {
		kind := tableKind(table)
		if !wantKind(opt.Kinds, kind) {
			continue
		}

		var sessions []db.Session
		serr := sdb.StreamSessions(table, func(s db.Session) error {
			if !wantPeer(opt.Peers, s.PeerUIN) {
				return nil
			}
			sessions = append(sessions, s)
			return nil
		})
		if serr != nil {
			if opt.Tolerant {
				log.Printf("警告: 表 %s 列举会话失败，跳过: %v", table, serr)
				continue
			}
			return serr
		}
		sort.SliceStable(sessions, func(i, j int) bool { return sessions[i].PeerUIN < sessions[j].PeerUIN })

		// 单遍扇出：一次遍历把这张表里所有会话的消息分别写出去。
		// 早先是"每个会话各扫一遍全表"，6.6GB 的库有 200+ 会话时，
		// 相当于把 1.6TB 的密文解密一遍，慢到不可用。
		sinks := make([]*db.FanoutSink, 0, len(sessions))
		for _, ss := range sessions {
			m := model.Conversation{
				ID:      ss.ID,
				PeerUIN: ss.PeerUIN,
				PeerUID: ss.PeerUID,
				Type:    kind,
				Name:    inferNameFromSession(ss, kind),
			}
			sinks = append(sinks, &db.FanoutSink{
				Peer: ss.PeerUIN,
				Conversation: func() error {
					if h.Conversation != nil {
						return h.Conversation(m)
					}
					return nil
				},
				Message: func(msg model.Message) error {
					if h.Message != nil {
						return h.Message(msg)
					}
					return nil
				},
				Done: func(count int) error {
					if h.Done != nil {
						return h.Done(m, count)
					}
					return nil
				},
			})
		}

		ferr := sdb.StreamFanout(table, sinks, db.Filter{
			Since: opt.Since,
			Until: opt.Until,
			Limit: opt.Limit,
		}, db.FanoutWindow)
		if ferr != nil {
			if opt.Tolerant {
				log.Printf("警告: 表 %s 读取中断（可能受坏页影响），已导出部分会话: %v", table, ferr)
			} else {
				return ferr
			}
		}
	}
	if n := sdb.Skipped(); n > 0 {
		log.Printf("提示: 有 %d 条记录因源库坏页/结构异常未能读取（其余已正常导出）", n)
	}
	return nil
}

// inferNameFromSession 用会话概要里的名字推断展示名，取不到就退回号码。
func inferNameFromSession(s db.Session, kind int) string {
	if s.Name != "" {
		return s.Name
	}
	if kind == model.ChatGroup && s.PeerUIN != 0 {
		return fmt.Sprintf("群 %d", s.PeerUIN)
	}
	return ""
}

// ReplaySession 重新读一遍指定会话并逐条回调，用于一次遍历同时产出多种格式。
//
// 它只为这种场景存在：流式导出时，第一个格式是边读边写的，其余格式需要再次
// 顺序读同一会话。第二次读依旧逐页解密、逐条回调，内存仍与库大小无关。
func ReplaySession(src string, opt Options, meta model.Conversation, cb func(model.Message) error) error {
	key := opt.Key
	if key == "" {
		return fmt.Errorf("qqdump: ReplaySession 需要 opt.Key（密钥已由调用方解析）")
	}
	sdb, err := db.OpenEncryptedStream(src, key, opt.Tolerant)
	if err != nil {
		return err
	}
	defer sdb.Close()

	table := db.TableC2C
	if meta.Type == model.ChatGroup {
		table = db.TableGroup
	}
	return sdb.StreamSessionMessages(table, meta.PeerUIN, db.Filter{
		Since: opt.Since,
		Until: opt.Until,
		Limit: opt.Limit,
	}, cb)
}
