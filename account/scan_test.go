package account

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestScanFindsDBAndAccount(t *testing.T) {
	dir := t.TempDir()
	// Mimic the real Android layout: .../nt_db/nt_qq_{hash}/nt_msg.db
	hash := "b69bfb8e74137f4e4253d1af3e99493a"
	target := filepath.Join(dir, "data", "com.tencent.mobileqq", "databases", "nt_db", "nt_qq_"+hash, "nt_msg.db")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, make([]byte, HeaderSize+1024), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{Root: dir}
	dbs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 1 {
		t.Fatalf("want 1 db, got %d", len(dbs))
	}
	if dbs[0].Account != hash {
		t.Fatalf("account = %q, want %q", dbs[0].Account, hash)
	}
}

func TestParseHead(t *testing.T) {
	head := make([]byte, HeaderSize)
	copy(head, []byte("junkQQ_NT DBabcdefg\x00HMAC_SHA1more"))
	path := filepath.Join(t.TempDir(), DefaultDBName)
	if err := os.WriteFile(path, head, 0o644); err != nil {
		t.Fatal(err)
	}
	hi, err := ParseHead(path)
	if err != nil {
		t.Fatal(err)
	}
	if hi.Rand != "abcdefg" {
		t.Fatalf("rand = %q, want abcdefg", hi.Rand)
	}
	if hi.HMACAlgo != "HMAC_SHA1" {
		t.Fatalf("hmac = %q, want HMAC_SHA1", hi.HMACAlgo)
	}
}

// TestDeriveKey verifies the documented chain key = md5( md5(uid) + rand ).
// The public example uses uid whose md5 hex is 255c42fc0f4d295678e6ff0135fcf5dd,
// so we pass that as the uid here and recompute the expected value directly.
func TestDeriveKey(t *testing.T) {
	uid, rand := "255c42fc0f4d295678e6ff0135fcf5dd", "6tPaJ9GP"
	want := func() string {
		h1 := md5.Sum([]byte(uid))
		base := hex.EncodeToString(h1[:]) + rand
		h2 := md5.Sum([]byte(base))
		return hex.EncodeToString(h2[:])
	}()
	if got := DeriveKey(uid, rand); got != want {
		t.Fatalf("DeriveKey = %q, want %q", got, want)
	}
}
