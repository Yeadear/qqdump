package account

import (
	"crypto/md5" // #nosec G501 -- 协议就是 MD5
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildHead 构造一个与真机一致的 1024 字节自定义头。
//
// 布局：前 100 字节伪装成 SQLite 页头，第 32 字节起是 "QQ_NT DB" 标记，
// 然后是 u32 长度 + 一段 Protobuf（field2=rand, field3=版本, field4=HMAC）。
func buildHead(rand, version, hmac string) []byte {
	meta := []byte{}
	appendStr := func(field protowire.Number, v string) {
		meta = protowire.AppendTag(meta, field, protowire.BytesType)
		meta = protowire.AppendBytes(meta, []byte(v))
	}
	appendStr(fieldRand, rand)
	appendStr(fieldVersion, version)
	appendStr(fieldHMAC, hmac)

	head := make([]byte, HeaderSize)
	copy(head, []byte("SQLite header 3\x00"))
	copy(head[32:], qqntMarker)
	binary.LittleEndian.PutUint32(head[40:], uint32(len(meta)))
	copy(head[44:], meta)
	return head
}

func TestParseHeadStructured(t *testing.T) {
	head := buildHead("vCsg8neC", "1.1.0.1", "HMAC_SHA1")

	hi := parseHeadBytes(head)
	if hi == nil {
		t.Fatal("解析返回 nil")
	}
	if hi.Rand != "vCsg8neC" {
		t.Errorf("Rand = %q, want vCsg8neC", hi.Rand)
	}
	if hi.Version != "1.1.0.1" {
		t.Errorf("Version = %q, want 1.1.0.1", hi.Version)
	}
	if hi.HMACAlgo != "HMAC_SHA1" {
		t.Errorf("HMACAlgo = %q, want HMAC_SHA1", hi.HMACAlgo)
	}
	if hi.Raw {
		t.Error("走了兜底路径，应该用结构化 Protobuf 解析")
	}
}

// 头部没有标准长度前缀时，也要能拿到 rand。
func TestParseHeadFallback(t *testing.T) {
	head := make([]byte, HeaderSize)
	copy(head[32:], qqntMarker)
	// 标记后面直接跟可读串，没有 u32 长度
	offset := 32 + len(qqntMarker)
	copy(head[offset:], []byte("\x00vCsg8neC\x001.1.0.1\x00HMAC_SHA1"))

	hi := parseHeadBytes(head)
	if hi == nil {
		t.Fatal("解析返回 nil")
	}
	if hi.Rand != "vCsg8neC" {
		t.Errorf("Rand = %q, want vCsg8neC", hi.Rand)
	}
	if hi.HMACAlgo != "HMAC_SHA1" {
		t.Errorf("HMACAlgo = %q, want HMAC_SHA1", hi.HMACAlgo)
	}
	if !hi.Raw {
		t.Error("应该标记为兜底解析")
	}
}

func TestParseHeadNoMarker(t *testing.T) {
	head := make([]byte, HeaderSize)
	if got := parseHeadBytes(head); got != nil {
		t.Errorf("没有 QQ_NT DB 标记时应返回 nil，得到 %+v", got)
	}
}

// 密钥算法必须与 QQ NT 一致：md5( md5(uid) 的 hex + rand ) 的 hex。
func TestDeriveKey(t *testing.T) {
	const uid = "u_test1234abcd"
	const rand = "vCsg8neC"

	want := func() string {
		uidSum := md5.Sum([]byte(uid))
		uidHash := hex.EncodeToString(uidSum[:])
		sum := md5.Sum([]byte(uidHash + rand))
		return hex.EncodeToString(sum[:])
	}()

	got := DeriveKey(uid, rand)
	if got != want {
		t.Errorf("DeriveKey = %q, want %q", got, want)
	}
	if len(got) != 32 {
		t.Errorf("密钥长度 = %d, want 32", len(got))
	}
	if DeriveKey(uid, rand) != got {
		t.Error("密钥推导不稳定")
	}
}

// 扫描真实布局的目录树：files/uid/{uin}###{uid} + nt_db/nt_qq_{hash}/nt_msg.db
func TestAccounts(t *testing.T) {
	const uid = "u_abc123def456"
	const uin = "10000"
	const rand = "vCsg8neC"

	root := t.TempDir()
	qqDir := filepath.Join(root, "data", "user", "0", "com.tencent.mobileqq")
	uidDir := filepath.Join(qqDir, "files", "uid", uin+"###"+uid)
	if err := os.MkdirAll(uidDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 路径哈希必须与 QQ NT 的算法一致
	uidSum := md5.Sum([]byte(uid))
	uidHash := hex.EncodeToString(uidSum[:])
	pathSum := md5.Sum([]byte(uidHash + "nt_kernel"))
	pathHash := hex.EncodeToString(pathSum[:])

	dbDir := filepath.Join(qqDir, "databases", "nt_db", "nt_qq_"+pathHash)
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dbDir, DefaultDBName)
	head := buildHead(rand, "1.1.0.1", "HMAC_SHA1")
	if err := os.WriteFile(dbPath, append(head, make([]byte, 4096)...), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{Root: root}
	accounts, err := s.Accounts()
	if err != nil {
		t.Fatal(err)
	}

	var a Account
	for _, x := range accounts {
		if x.UID == uid {
			a = x
		}
	}
	if a.UID == "" {
		t.Fatalf("没有找到 uid=%s 的账号，扫到：%+v", uid, accounts)
	}
	if a.UIN != uin {
		t.Errorf("UIN = %q, want %q", a.UIN, uin)
	}
	if a.PathHash != pathHash {
		t.Errorf("PathHash = %q, want %q", a.PathHash, pathHash)
	}
	if a.DBPath != dbPath {
		t.Errorf("DBPath = %q, want %q", a.DBPath, dbPath)
	}
	if a.Rand != rand {
		t.Errorf("Rand = %q, want %q", a.Rand, rand)
	}
	if a.Key != DeriveKey(uid, rand) {
		t.Errorf("Key = %q, want %q", a.Key, DeriveKey(uid, rand))
	}
}

// 没有 files/uid（拿不到 uid）时，库照样要列出来，只是算不出密钥。
// 调用方可以据此另行传入 uid 或密钥。
func TestAccountWithoutUIDDir(t *testing.T) {
	root := t.TempDir()
	qqDir := filepath.Join(root, pkgName)
	dbDir := filepath.Join(qqDir, databasesEl, ntDBSubdir, ntDBPrefix+"15f44a365337b095c1025182df6a2f3f")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dbDir, DefaultDBName)
	head := buildHead("vCsg8neC", "1.1.0.1", "HMAC_SHA1")
	if err := os.WriteFile(dbPath, append(head, make([]byte, 4096)...), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{Root: qqDir}
	dbs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 1 {
		t.Fatalf("列出 %d 个库, want 1", len(dbs))
	}
	if dbs[0].Account != "15f44a365337b095c1025182df6a2f3f" {
		t.Errorf("Account = %q，应该是目录名里的哈希", dbs[0].Account)
	}
	if dbs[0].Head == nil || dbs[0].Head.Rand != "vCsg8neC" {
		t.Errorf("头部解析失败：%+v", dbs[0].Head)
	}

	accounts, err := s.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("列出 %d 个账号, want 1", len(accounts))
	}
	if accounts[0].Rand != "vCsg8neC" {
		t.Errorf("Rand = %q, want vCsg8neC", accounts[0].Rand)
	}
	if accounts[0].Key != "" {
		t.Errorf("没有 uid 时不该算出密钥，got %q", accounts[0].Key)
	}
}

// 定位只按固定布局拼路径，不遍历磁盘：放在别处的 nt_msg.db 不该被找到，
// 否则扫大目录（甚至 /）会因为全盘遍历而慢到像卡死。
func TestScanDoesNotWalkDisk(t *testing.T) {
	root := t.TempDir()
	qqDir := filepath.Join(root, pkgName)
	ntDB := filepath.Join(qqDir, databasesEl, ntDBSubdir, ntDBPrefix+"aaaa")
	if err := os.MkdirAll(ntDB, 0o755); err != nil {
		t.Fatal(err)
	}
	head := buildHead("vCsg8neC", "1.1.0.1", "HMAC_SHA1")
	real := filepath.Join(ntDB, DefaultDBName)
	if err := os.WriteFile(real, append(head, make([]byte, 4096)...), 0o644); err != nil {
		t.Fatal(err)
	}

	// 陷阱：根目录下任意位置再放一个，不该被计入
	trap := filepath.Join(root, "somewhere", "deep", DefaultDBName)
	if err := os.MkdirAll(filepath.Dir(trap), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trap, append(head, make([]byte, 4096)...), 0o644); err != nil {
		t.Fatal(err)
	}

	dbs, err := (&Scanner{Root: root}).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 1 {
		t.Fatalf("列出 %d 个库, want 1（只认 nt_db 下的）", len(dbs))
	}
	if dbs[0].Path != real {
		t.Errorf("Path = %q, want %q", dbs[0].Path, real)
	}
}

// 根路径可以是任意一层：Android 根、QQ 数据目录、nt_db 目录本身。
func TestResolveQQDir(t *testing.T) {
	root := t.TempDir()
	qqDir := filepath.Join(root, "data", "user", "0", pkgName)
	ntDB := filepath.Join(qqDir, databasesEl, ntDBSubdir)
	if err := os.MkdirAll(ntDB, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		root:  qqDir, // Android 根：自动补 data/user/0
		qqDir: qqDir, // 直接指到 QQ 数据目录
		ntDB:  qqDir, // 直接指到 nt_db
	}
	for in, want := range cases {
		got, ok := ResolveQQDir(in)
		if !ok {
			t.Errorf("ResolveQQDir(%q) 未命中", in)
			continue
		}
		if got != want {
			t.Errorf("ResolveQQDir(%q) = %q, want %q", in, got, want)
		}
	}

	if _, ok := ResolveQQDir(filepath.Join(root, "nope")); ok {
		t.Error("没有 QQ 数据目录时不该命中")
	}
}

func TestSplitUIDName(t *testing.T) {
	uin, uid, ok := splitUIDName("10000###u_abc")
	if !ok || uin != "10000" || uid != "u_abc" {
		t.Errorf("splitUIDName = %q, %q, %v", uin, uid, ok)
	}
	if _, _, ok := splitUIDName("没有分隔符"); ok {
		t.Error("没有 ### 时应返回 false")
	}
	if _, _, ok := splitUIDName("###u_abc"); ok {
		t.Error("缺少 uin 时应返回 false")
	}
}
