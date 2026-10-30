// Package account 定位 QQ NT 的消息数据库并算出它的密钥。
//
// 安卓（NTQQ）上的聊天数据库位于
//
//	/data/data/com.tencent.mobileqq/databases/nt_db/nt_qq_{hash}/nt_msg.db
//
// 其中 hash = md5( md5(uid) + "nt_kernel" )，uid 来自同一 QQ 数据目录下的
//
//	files/uid/{uin}###{uid}
//
// root 直取、adb pull、用户自己拷贝出来的目录，落到磁盘上都是同一套布局，
// 所以三种数据来源统一为同一种操作：给定一个根路径，找出所有 nt_msg.db
// 并算出各自密钥。
//
// 每个 nt_msg.db 前面有 1024 字节自定义头。"QQ_NT DB" 标记之后是一个
// 长度前缀 + 一段 Protobuf，形如
//
//	field 2 → rand（8 位随机串）
//	field 3 → 版本（如 1.1.0.1）
//	field 4 → HMAC 算法（如 HMAC_SHA1）
//
// 数据库密钥是 md5( md5(uid) + rand )，32 位 hex 字符串，作为 SQLCipher 的
// passphrase 使用。
package account

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- QQ NT 的密钥算法就是 MD5，无法替换
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/Yeadear/qqdump/cipher"
)

// DefaultDBName 是 QQ NT 消息库的约定文件名。
const DefaultDBName = "nt_msg.db"

// HeaderSize 是 nt_msg.db 前面自定义头的长度。
const HeaderSize = cipher.HeaderSize // 1024

// 头部 Protobuf 的字段号。
const (
	fieldRand    = 2
	fieldVersion = 3
	fieldHMAC    = 4
)

// DBInfo 是一个找到的（仍是加密的）消息数据库。
type DBInfo struct {
	Path    string    // nt_msg.db 的完整路径
	Account string    // 路径里的 nt_qq_{hash} 账号哈希，没有则为空
	Head    *HeadInfo // 解析出的头部信息，解析失败则为 nil
}

// HeadInfo 是 1024 字节自定义头里有用的部分。
type HeadInfo struct {
	Rand     string // rand 随机串，与 uid 一起派生密钥
	Version  string // 头部记录的版本，如 1.1.0.1
	HMACAlgo string // cipher_hmac_algorithm 提示，如 HMAC_SHA1
	Raw      bool   // true 表示走的是兜底正则解析，不是结构化 Protobuf
}

// Account 是一个完整的 QQ 账号，含定位数据库与解密所需的一切。
type Account struct {
	User     string // Android 多用户 ID，如 0
	UIN      string // QQ 号
	UID      string // NT UID
	UIDHash  string // md5(uid)
	PathHash string // md5(uid_hash + "nt_kernel")
	DBPath   string // nt_msg.db 路径
	Rand     string
	HMACAlgo string
	Key      string // md5(uid_hash + rand)，即数据库密钥
}

// Scanner 在根目录下寻找 QQ NT 的消息数据库。
type Scanner struct {
	Root   string // 扫描根目录：安卓 root 路径、adb pull 目标、或用户拷贝的目录
	DBName string // 要匹配的消息库文件名，默认 nt_msg.db
}

func (s *Scanner) dbName() string {
	if s.DBName == "" {
		return DefaultDBName
	}
	return s.DBName
}

// Scan 返回根目录下找到的所有消息数据库。
func (s *Scanner) Scan() ([]DBInfo, error) {
	name := s.dbName()
	var out []DBInfo
	err := filepath.WalkDir(s.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != name {
			return nil
		}
		info := DBInfo{Path: path, Account: accountFromPath(path)}
		if hi, herr := ParseHead(path); herr == nil {
			info.Head = hi
		}
		out = append(out, info)
		return nil
	})
	return out, err
}

// Accounts 扫描根目录下的 QQ 账号，返回带 uid、数据库路径和密钥的完整记录。
//
// 它优先走结构化的 uid 目录（files/uid/{uin}###{uid}）；找不到时退化为
// 直接扫 nt_msg.db，此时记录里没有 uid，Key 为空，需要调用方另行提供。
func (s *Scanner) Accounts() ([]Account, error) {
	uids, err := s.findUIDDirs()
	if err != nil {
		return nil, err
	}

	byPath := map[string]Account{}
	var out []Account

	for _, u := range uids {
		uidHash := md5Hex(u.uid)
		pathHash := md5Hex(uidHash + "nt_kernel")
		dbPath := filepath.Join(u.qqDir, "databases", "nt_db", "nt_qq_"+pathHash, s.dbName())

		a := Account{
			User:     u.user,
			UIN:      u.uin,
			UID:      u.uid,
			UIDHash:  uidHash,
			PathHash: pathHash,
			DBPath:   dbPath,
		}
		if fi, err := os.Stat(dbPath); err == nil && !fi.IsDir() {
			if hi, herr := ParseHead(dbPath); herr == nil && hi != nil {
				a.Rand = hi.Rand
				a.HMACAlgo = hi.HMACAlgo
				a.Key = DeriveKey(u.uid, a.Rand)
			}
		}
		out = append(out, a)
		byPath[dbPath] = a
	}

	// 不在已知账号目录下的孤立库（例如用户只拷出了 nt_msg.db）也要报告，
	// 这样调用方至少知道有这么个文件，可以另行传入 uid 或 key。
	dbs, err := s.Scan()
	if err != nil {
		return out, nil
	}
	for _, db := range dbs {
		if _, ok := byPath[db.Path]; ok {
			continue
		}
		a := Account{DBPath: db.Path}
		if db.Head != nil {
			a.Rand = db.Head.Rand
			a.HMACAlgo = db.Head.HMACAlgo
		}
		out = append(out, a)
	}
	return out, nil
}

type uidDir struct {
	user  string
	uin   string
	uid   string
	qqDir string
}

// qqPkgName 是 QQ 的 Android 包名。
const qqPkgName = "com.tencent.mobileqq"

// findUIDDirs 找出形如 .../com.tencent.mobileqq/files/uid/{uin}###{uid} 的目录。
//
// 这里用遍历而不是 Glob：Glob 的 ** 并不递归，而用户的根目录可以是任意一层
// （/、/data、/data/data，或者 adb pull 出来的任意目录），深度不确定。
// 一旦定位到 QQ 的包目录就停下去，不再往里钻，避免扫遍整机。
func (s *Scanner) findUIDDirs() ([]uidDir, error) {
	var out []uidDir

	handle := func(qqDir string) {
		entries, err := os.ReadDir(filepath.Join(qqDir, "files", "uid"))
		if err != nil {
			return
		}
		for _, e := range entries {
			uin, uid, ok := splitUIDName(e.Name())
			if !ok {
				continue
			}
			out = append(out, uidDir{user: userOf(qqDir), uin: uin, uid: uid, qqDir: qqDir})
		}
	}

	// 用户可能直接把根目录指到 QQ 的包目录上
	if filepath.Base(s.Root) == qqPkgName {
		handle(s.Root)
	}

	err := filepath.WalkDir(s.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil // 权限不足或不是目录，跳过继续扫
		}
		if d.Name() != qqPkgName {
			return nil
		}
		if path != s.Root {
			handle(path)
		}
		return filepath.SkipDir
	})
	return out, err
}

// splitUIDName 解析 "{uin}###{uid}" 形式的目录名。
func splitUIDName(name string) (uin, uid string, ok bool) {
	i := strings.Index(name, "###")
	if i <= 0 {
		return "", "", false
	}
	uin, uid = name[:i], name[i+3:]
	if uin == "" || uid == "" {
		return "", "", false
	}
	return uin, uid, true
}

// userOf 取出 Android 多用户 ID（.../data/user/{user}/com.tencent.mobileqq）。
// 不在多用户目录下时返回空，不强猜。
func userOf(qqDir string) string {
	parent := filepath.Dir(qqDir)
	if filepath.Base(filepath.Dir(parent)) != "user" {
		return ""
	}
	return filepath.Base(parent)
}

// accountFromPath 从路径里提取 nt_qq_{hash} 或 u_ 开头的账号标识。
func accountFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, p := range parts {
		if strings.HasPrefix(p, "nt_qq_") && len(p) > len("nt_qq_") {
			return strings.TrimPrefix(p, "nt_qq_")
		}
	}
	for _, p := range parts {
		if strings.HasPrefix(p, "u_") {
			return p
		}
	}
	return ""
}

var qqntMarker = []byte("QQ_NT DB")

// ParseHead 读取 nt_msg.db 的自定义头，取出 rand / 版本 / HMAC 算法。
//
// 头的结构是：可打印标记 "QQ_NT DB"，紧跟一个小端 uint32 长度，然后是一段
// 该长度的 Protobuf。先按这个结构解析；任何一步对不上就退化为在标记之后
// 扫描可读字符串，保证旧版本或不常见布局也能拿到 rand。
func ParseHead(path string) (*HeadInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, HeaderSize)
	if _, err := io.ReadFull(f, head); err != nil {
		return nil, err
	}
	return parseHeadBytes(head), nil
}

// ParseHeadBytes 是 ParseHead 的内存版，便于测试与直接从字节流处理。
func ParseHeadBytes(head []byte) *HeadInfo { return parseHeadBytes(head) }

func parseHeadBytes(head []byte) *HeadInfo {
	if len(head) < HeaderSize {
		return nil
	}
	i := bytes.Index(head, qqntMarker)
	if i < 0 {
		return nil
	}

	// 结构化路径：标记 + u32 长度 + Protobuf
	if i+12 <= len(head) {
		n := int(binary.LittleEndian.Uint32(head[i+8 : i+12]))
		if n > 0 && i+12+n <= len(head) {
			if hi := parseMeta(head[i+12 : i+12+n]); hi != nil {
				return hi
			}
		}
	}
	return parseMetaFallback(head[i+len(qqntMarker):])
}

// parseMeta 逐字段读取头部 Protobuf，遇到无法解析的部分就停下。
func parseMeta(b []byte) *HeadInfo {
	hi := &HeadInfo{}
	got := 0
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		rest := b[n:]

		if typ != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, typ, rest)
			if m < 0 {
				break
			}
			b = rest[m:]
			continue
		}
		v, m := protowire.ConsumeBytes(rest)
		if m < 0 {
			break
		}
		b = rest[m:]
		switch num {
		case fieldRand:
			hi.Rand = string(v)
			got++
		case fieldVersion:
			hi.Version = string(v)
			got++
		case fieldHMAC:
			hi.HMACAlgo = string(v)
			got++
		default:
			got++
		}
	}
	if hi.Rand == "" && hi.HMACAlgo == "" {
		return nil
	}
	return hi
}

// parseMetaFallback 在长度前缀缺失时，直接在标记之后扫描可读串。
func parseMetaFallback(b []byte) *HeadInfo {
	hi := &HeadInfo{Raw: true}
	// 逐个切出可打印片段
	fields := bytes.FieldsFunc(b, func(r rune) bool { return r < 0x20 || r > 0x7e })
	for _, f := range fields {
		s := string(f)
		switch {
		case strings.HasPrefix(s, "HMAC_"):
			hi.HMACAlgo = s
		case hi.Rand == "" && isRandLike(s):
			hi.Rand = s
		case hi.Version == "" && isVersionLike(s):
			hi.Version = s
		}
	}
	if hi.Rand == "" && hi.HMACAlgo == "" {
		return nil
	}
	return hi
}

func isRandLike(s string) bool {
	if len(s) < 6 || len(s) > 16 {
		return false
	}
	for _, c := range s {
		if !isAlnum(byte(c)) {
			return false
		}
	}
	return true
}

func isVersionLike(s string) bool {
	return strings.Count(s, ".") >= 2 && len(s) <= 16
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// DeriveKey 计算 NTQQ 的数据库密钥 md5( md5(uid) + rand )，返回 32 位 hex。
// uid 是账号原始 uid（不是它的 md5），rand 来自 ParseHead。
func DeriveKey(uid, rand string) string {
	uidHash := md5Hex(uid)
	sum := md5.Sum([]byte(uidHash + rand)) // #nosec G401 -- 协议规定
	return hex.EncodeToString(sum[:])
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401 -- 协议规定
	return hex.EncodeToString(sum[:])
}
