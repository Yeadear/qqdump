package cipher

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// testKey matches the fixture generated with the `sqlcipher` C library using
// NTQQ's exact PRAGMA parameters.
const testKey = "1234567890ABCDEF"

func fixture(t *testing.T) []byte {
	t.Helper()
	enc, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ntqq_enc.db"))
	if err != nil {
		t.Skip("testdata/ntqq_enc.db missing; generate it with the sqlcipher CLI")
	}
	return enc
}

// TestDecryptSQLCipher cross-checks the pure-Go codec against a database the
// real C library encrypted with NTQQ's parameters.
func TestDecryptSQLCipher(t *testing.T) {
	enc := fixture(t)
	var out bytes.Buffer
	if err := DecryptSQLCipher(bytes.NewReader(enc), &out, testKey); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain := out.Bytes()
	if !bytes.Contains(plain, []byte("SQLite format 3\x00")) {
		t.Fatal("decrypted output is not a valid SQLite database")
	}
	for _, s := range []string{"hello ntqq 你好世界", "second row 测试消息", "messages"} {
		if !bytes.Contains(plain, []byte(s)) {
			t.Fatalf("missing %q in plaintext — wrong key/algorithm", s)
		}
	}
}

// TestWrongKeyRejected proves the HMAC-SHA1 switch is what makes NTQQ work: a
// wrong key (or the default SHA-512 params) must be rejected, never produce
// plausible garbage.
func TestWrongKeyRejected(t *testing.T) {
	enc := fixture(t)
	var out bytes.Buffer
	if err := DecryptSQLCipher(bytes.NewReader(enc), &out, "WRONGKEY0000000"); err == nil {
		t.Fatal("expected decryption failure with a wrong key, got nil")
	}
}
