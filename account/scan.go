// Package account 定位 QQ NT 的消息数据库并算出它的密钥。
//
// 安卓（NTQQ）的消息库路径是固定的：
//
//	/data/user/0/com.tencent.mobileqq/databases/nt_db/nt_qq_{hash}/nt_msg.db
//
// 所以这里不做任何磁盘遍历——只按已知布局拼路径、检查存在性。给一个根路径
// （Android 根 /、QQ 数据目录、nt_db 目录，或 adb pull 出来的任意一层），
// 直接解析到 nt_db，再列出其中每个 nt_qq_{hash} 下的 nt_msg.db。这样无论
// 设备上有多少文件，耗时都是常数级。
//
// 每个 nt_msg.db 前面有 1024 字节自定义头。"QQ_NT DB" 标记之后是一个
// 长度前缀 + 一段 Protobuf，形如
//
//	field 2 → rand（8 位随机串）
//	field 3 → 版本（如 1.1.0.1）
//	field 4 → HMAC 算法（如 HMAC_SHA1）
//
// 数据库密钥是 md5( md5(uid) + rand )，32 位 hex 字符串，作为 SQLCipher 的
// passphrase 使用。uid 来自同一数据目录下的 files/uid/{uin}###{uid}；拿不到
// uid 时库照样能列出（含 rand），只是算不出密钥，需要调用方另行提供。
package account

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- QQ NT 的密钥算法就是 MD5，无法替换
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

// QQ 数据目录下的固定子路径。
const (
	pkgName     = "com.tencent.mobileqq" // QQ 包名
	databasesEl = "databases"            // QQ 数据目录/databases
	ntDBSubdir  = "nt_db"                // databases/nt_db
	ntDBPrefix  = "nt_qq_"               // 账号目录 nt_qq_{hash}
	uidDirEl    = "files"                // QQ 数据目录/files/uid
	uidSubEl    = "uid"
)

// DBInfo 是一个找到的（仍是加密的）消息数据库。
type DBInfo struct {
	Path    string    // nt_msg.db 的完整路径
	Account string    // 所在目录名 nt_qq_{hash} 里的 {hash}
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

// Scanner 定位 QQ NT 的消息数据库。
type Scanner struct {
	Root   string // 根路径：Android 根 /、QQ 数据目录、nt_db 目录，或拷贝出来的任意一层
	DBName string // 要匹配的消息库文件名，默认 nt_msg.db
}

func (s *Scanner) dbName() string {
	if s.DBName == "" {
		return DefaultDBName
	}
	return s.DBName
}

// ResolveQQDir 把任意根路径解析成 QQ 数据目录（含 databases/nt_db 的那一层）。
//
// 只按已知布局拼路径并检查存在性，不遍历磁盘。根路径可以是：
//   - Android 根 / 或 /data：会自动补上 data/user/0/com.tencent.mobileqq
//   - QQ 数据目录本身：/data/user/0/com.tencent.mobileqq
//   - nt_db 目录本身：.../databases/nt_db
//   - adb pull 出来的目录，只要里面含有上述任一层
func ResolveQQDir(root string) (string, bool) {
	root = filepath.Clean(root)
	candidates := []string{root}
	for _, rel := range []string{
		"data/user/0/" + pkgName,
		"data/user/10/" + pkgName,
		"data/data/" + pkgName,
		pkgName,
	} {
		candidates = append(candidates, filepath.Join(root, filepath.FromSlash(rel)))
	}
	base := filepath.Base(root)
	switch {
	case base == ntDBSubdir:
		// .../{qqDir}/databases/nt_db
		candidates = append(candidates, filepath.Dir(filepath.Dir(root)))
	case strings.HasPrefix(base, ntDBPrefix):
		// .../{qqDir}/databases/nt_db/nt_qq_{hash}
		candidates = append(candidates, filepath.Dir(filepath.Dir(filepath.Dir(root))))
	}

	for _, c := range candidates {
		if isDir(filepath.Join(c, databasesEl, ntDBSubdir)) {
			return c, true
		}
	}
	return "", false
}

// NtDBDir 返回 QQ 数据目录下的账号库目录 databases/nt_db。
func NtDBDir(qqDir string) string {
	if filepath.Base(qqDir) == ntDBSubdir {
		return qqDir
	}
	return filepath.Join(qqDir, databasesEl, ntDBSubdir)
}

// FindDBs 列出 QQ 数据目录下所有账号的消息库：
// {qqDir}/databases/nt_db/nt_qq_{hash}/nt_msg.db。
//
// 只读取 nt_db 这一层目录，不递归。
func (s *Scanner) FindDBs(qqDir string) []DBInfo {
	name := s.dbName()
	entries, err := os.ReadDir(NtDBDir(qqDir))
	if err != nil {
		return nil
	}
	var out []DBInfo
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), ntDBPrefix) {
			continue
		}
		p := filepath.Join(NtDBDir(qqDir), e.Name(), name)
		if !isFile(p) {
			continue
		}
		info := DBInfo{
			Path:    p,
			Account: strings.TrimPrefix(e.Name(), ntDBPrefix),
		}
		if hi, herr := ParseHead(p); herr == nil {
			info.Head = hi
		}
		out = append(out, info)
	}
	return out
}

// Scan 列出根路径下所有 QQ NT 消息库。它解析根目录后只读 nt_db 一层，
// 不做任何递归遍历。
func (s *Scanner) Scan() ([]DBInfo, error) {
	qqDir, ok := ResolveQQDir(s.Root)
	if !ok {
		return nil, fmt.Errorf("account: %s 下没有 QQ NT 数据目录（期望 .../%s/%s/%s*/）",
			s.Root, pkgName, databasesEl, ntDBSubdir)
	}
	return s.FindDBs(qqDir), nil
}

// Accounts 返回根路径下的 QQ 账号，带 uid、数据库路径和密钥。
//
// uid 来自 {qqDir}/files/uid/{uin}###{uid}。账号与库的配对优先按路径哈希
// md5(md5(uid)+"nt_kernel")；推算不出（或该目录下只有一个库）时也能配对上。
// 没有 uid 目录时库照样列出（含 rand），只是算不出密钥。
func (s *Scanner) Accounts() ([]Account, error) {
	qqDir, ok := ResolveQQDir(s.Root)
	if !ok {
		return nil, fmt.Errorf("account: %s 下没有 QQ NT 数据目录（期望 .../%s/%s/%s*/）",
			s.Root, pkgName, databasesEl, ntDBSubdir)
	}

	dbs := s.FindDBs(qqDir)
	if len(dbs) == 0 {
		return nil, fmt.Errorf("account: %s 下没有找到任何 %s", NtDBDir(qqDir), s.dbName())
	}

	uids := findUIDs(qqDir)
	user := userOf(qqDir)

	dbByHash := make(map[string]string, len(dbs))
	for _, d := range dbs {
		dbByHash[d.Account] = d.Path
	}

	var out []Account
	paired := map[string]bool{}

	for _, u := range uids {
		uidHash := md5Hex(u.uid)
		pathHash := md5Hex(uidHash + "nt_kernel")
		a := Account{
			User:     user,
			UIN:      u.uin,
			UID:      u.uid,
			UIDHash:  uidHash,
			PathHash: pathHash,
		}
		if p, ok := dbByHash[pathHash]; ok {
			a.DBPath = p
		} else if len(dbs) == 1 {
			// 推算的哈希对不上但只有一个库：认定就是它，避免漏掉整个账号
			a.DBPath = dbs[0].Path
			a.PathHash = dbs[0].Account
		}
		if a.DBPath != "" {
			paired[a.DBPath] = true
			if hi, herr := ParseHead(a.DBPath); herr == nil && hi != nil {
				a.Rand = hi.Rand
				a.HMACAlgo = hi.HMACAlgo
				if a.Rand != "" {
					a.Key = DeriveKey(u.uid, a.Rand)
				}
			}
		}
		out = append(out, a)
	}

	// 没配上的库（没有 uid 目录，或多账号里哈希推算失败）也要报告出来，
	// 调用方至少知道有这个文件，可以另行传入 uid 或密钥。
	for _, d := range dbs {
		if paired[d.Path] {
			continue
		}
		a := Account{User: user, PathHash: d.Account, DBPath: d.Path}
		if d.Head != nil {
			a.Rand = d.Head.Rand
			a.HMACAlgo = d.Head.HMACAlgo
		}
		out = append(out, a)
	}
	return out, nil
}

type uidDir struct {
	uin string
	uid string
}

// findUIDs 读取 {qqDir}/files/uid 下的 {uin}###{uid} 目录。
// 只读这一层，不递归。没有该目录时返回空。
func findUIDs(qqDir string) []uidDir {
	entries, err := os.ReadDir(filepath.Join(qqDir, uidDirEl, uidSubEl))
	if err != nil {
		return nil
	}
	var out []uidDir
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		uin, uid, ok := splitUIDName(e.Name())
		if !ok {
			continue
		}
		out = append(out, uidDir{uin: uin, uid: uid})
	}
	return out
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

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
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
