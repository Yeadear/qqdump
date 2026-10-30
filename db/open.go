// Package db 读取解密后的 nt_msg.db 明文 SQLite 库。
//
// nt_msg.db 的列名是协议字段编号（40001、40050、40800 ...），且不同 QQ 版本
// 的列集合并不一致。因此这里不写死列名，而是先探测表与列，再按实际存在的列
// 动态拼 SQL，缺失的列按零值处理——这样拿到任何一个版本的库都不会直接报错。
package db

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // 纯 Go 驱动，注册驱动名 "sqlite"
)

// 已知的消息表名。
const (
	TableC2C   = "c2c_msg_table"
	TableGroup = "group_msg_table"
)

// DB 是一个已打开的明文库，附带探测到的表/列信息。
type DB struct {
	*sql.DB
	path   string
	tables []string        // 按 C2C、Group 固定顺序
	cols   map[string][]string
}

// Open 打开一个明文 SQLite 库并探测其消息表结构。
func Open(path string) (*DB, error) {
	sdb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db: 打开 %s: %w", path, err)
	}
	// 解密产物是只读的，且 natsort 无意义；单连接即可，避免锁争用。
	sdb.SetMaxOpenConns(1)

	d := &DB{DB: sdb, path: path, cols: map[string][]string{}}
	if err := d.probe(); err != nil {
		sdb.Close()
		return nil, err
	}
	return d, nil
}

// Path 返回库文件路径。
func (d *DB) Path() string { return d.path }

// probe 探测存在哪些消息表以及各自的列。
func (d *DB) probe() error {
	for _, t := range []string{TableC2C, TableGroup} {
		ok, err := d.hasTable(t)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		cols, err := d.columns(t)
		if err != nil {
			return err
		}
		d.tables = append(d.tables, t)
		d.cols[t] = cols
	}
	if len(d.tables) == 0 {
		return fmt.Errorf("db: %s 里没有找到 %s 或 %s，这不是一个 nt_msg 明文库", d.path, TableC2C, TableGroup)
	}
	return nil
}

func (d *DB) hasTable(name string) (bool, error) {
	var one int
	err := d.DB.QueryRow(`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("db: 查询表 %s: %w", name, err)
	}
	return true, nil
}

func (d *DB) columns(table string) ([]string, error) {
	rows, err := d.DB.Query(fmt.Sprintf("PRAGMA table_info(%s)", quote(table)))
	if err != nil {
		return nil, fmt.Errorf("db: 读取 %s 表结构: %w", table, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// Tables 返回库中存在的消息表名。
func (d *DB) Tables() []string { return d.tables }

// Columns 返回指定表探测到的列名。
func (d *DB) Columns(table string) []string { return d.cols[table] }

// Has 报告表中是否存在某列。
func (d *DB) Has(table, col string) bool {
	for _, c := range d.cols[table] {
		if c == col {
			return true
		}
	}
	return false
}

// Sessions 列出库中的全部会话，用于按会话分别导出。
//
// 私聊以 40030（对方 QQ）为键，群聊以 40030（群号）为键。
func (d *DB) Sessions(table string) ([]Session, error) {
	keys := []string{ColPeerUIN, ColSessionID}
	var have []string
	for _, k := range keys {
		if d.Has(table, k) {
			have = append(have, k)
		}
	}
	if len(have) == 0 {
		return nil, fmt.Errorf("db: %s 缺少会话列", table)
	}

	sel := make([]string, 0, len(have)+3)
	sel = append(sel, have...)
	if d.Has(table, ColPeerUID) {
		sel = append(sel, ColPeerUID)
	}
	if d.Has(table, ColChatType) {
		sel = append(sel, ColChatType)
	}
	if d.Has(table, ColSenderName) {
		sel = append(sel, ColSenderName)
	}
	sel = append(sel, "COUNT(*)")

	groupBy := strings.Join(quoteAll(have), ", ")
	q := fmt.Sprintf(`SELECT %s FROM %s GROUP BY %s ORDER BY MAX(%s) DESC`,
		strings.Join(quoteAll(sel), ", "), quote(table), groupBy, quote(ColPeerUIN))

	rows, err := d.DB.Query(q)
	if err != nil {
		return nil, fmt.Errorf("db: 列举 %s 会话: %w", table, err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		dest := make([]any, len(sel))
		vals := make([]any, len(sel))
		for i := range vals {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		s := Session{Table: table}
		for i, col := range sel {
			v := vals[i]
			switch col {
			case ColPeerUIN:
				s.PeerUIN = toInt64(v)
			case ColSessionID:
				s.ID = toInt64(v)
			case ColPeerUID:
				s.PeerUID, _ = v.(string)
			case ColChatType:
				s.ChatType = int(toInt64(v))
			case ColSenderName:
				s.Name, _ = v.(string)
			case "COUNT(*)":
				s.Count = toInt64(v)
			}
		}
		if s.ChatType == 0 {
			s.ChatType = chatTypeOf(table)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func chatTypeOf(table string) int {
	if table == TableGroup {
		return 2
	}
	return 1
}

// Session 是一个会话的概要。
type Session struct {
	Table    string // 来源表
	ID       int64  // 40027 本地会话键
	PeerUIN  int64  // 40030 c2c: 对方 QQ；group: 群号
	PeerUID  string // 40021
	Name     string // 最近一条消息的 40093（仅作显示回退）
	ChatType int    // 40010
	Count    int64  // 消息条数
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case nil:
		return 0
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case string:
		var n int64
		fmt.Sscanf(t, "%d", &n)
		return n
	case []byte:
		var n int64
		fmt.Sscanf(string(t), "%d", &n)
		return n
	}
	return 0
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = quote(s)
	}
	return out
}
