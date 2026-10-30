// Package cipher 解密 NTQQ（QQ NT）的 SQLCipher 数据库。
//
// nt_msg.db 是一个 SQLCipher 加密的 SQLite 库，前面还垫了 1024 字节自定义头，
// 解密前必须先剥掉。NTQQ 用的是一套"混合"参数（已对 C 库 sqlcipher 与
// QQBackup/nt_msg_db_util 交叉验证）：
//
//	cipher_page_size      = 4096
//	kdf_iter             = 4000
//	cipher_hmac_algorithm = HMAC_SHA1   （HMAC 槽补到 32 字节，reserve 48）
//	cipher_kdf_algorithm  = PBKDF2_HMAC_SHA512
//	key                   = md5(md5(uid) + rand) 的 32 位 hex 字符串，passphrase 形式
//
// 页校验密钥仍然用 PBKDF2-HMAC-SHA512 在 masked salt 上派生 2 轮，与 NTQQ 的
// cipher_kdf_algorithm 一致。
package cipher

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	sqlcipher "github.com/Yeadear/sqlcipher"
)

// HeaderSize 是 nt_msg.db 前面自定义头的长度。
const HeaderSize = 1024

// PageSize 是 NTQQ 的 cipher_page_size。
const PageSize = 4096

// KeyLen 是密钥字符串的期望长度：md5 的 32 位 hex。
const KeyLen = 32

// DefaultKDFIter 是 NTQQ 的 PBKDF2 迭代次数。
const DefaultKDFIter = 4000

// sqliteMagic 是解密后 page 1 的开头。它是校验密钥是否正确的判据。
var sqliteMagic = []byte("SQLite format 3\x00")

// ErrKey 报告密钥不对（或页面已损坏）。两者在 SQLCipher 里无法区分。
var ErrKey = sqlcipher.ErrKey

func params(iter int) sqlcipher.Params {
	if iter == 0 {
		iter = DefaultKDFIter
	}
	return sqlcipher.Params{PageSize: PageSize, Iter: iter, HMAC: sqlcipher.HMACSHA1}
}

// DecryptSQLCipher 解密一个裸 SQLCipher 流（不含 NTQQ 头）成明文 SQLite 流。
//
// key 是 32 位 hex 字符串。若它解不开，会再试一次"把这段 hex 还原成 16 个原始
// 字节后当 passphrase"——两种材料都能派生出密钥，取决于 QQ 版本把哪一种喂给了
// SQLCipher，试一次就能确定，代价只是一次 4000 轮 PBKDF2。
func DecryptSQLCipher(r io.Reader, w io.Writer, key string) error {
	if key == "" {
		return errors.New("cipher: 密钥为空")
	}

	// 先取出 page 1 用于试密钥；后面会把它拼回流里，不丢数据。
	page1 := make([]byte, PageSize)
	if _, err := io.ReadFull(r, page1); err != nil {
		return fmt.Errorf("cipher: 读取第 1 页: %w", err)
	}
	salt, err := sqlcipher.FileSalt(page1)
	if err != nil {
		return fmt.Errorf("cipher: 读取 salt: %w", err)
	}

	k, err := probeKey(key, salt, page1)
	if err != nil {
		return err
	}

	src := io.MultiReader(bytes.NewReader(page1), r)
	if err := sqlcipher.DecryptFile(w, src, k, params(0)); err != nil {
		return fmt.Errorf("cipher: 解密: %w", err)
	}
	return nil
}

// probeKey 在候选密钥形式里挑出能解开 page 1 的那个。
func probeKey(key string, salt, page1 []byte) (sqlcipher.Key, error) {
	var lastErr error
	for _, c := range keyCandidates(key) {
		codec, err := sqlcipher.NewCodec(c, salt, params(0))
		if err != nil {
			lastErr = err
			continue
		}
		plain, err := codec.Decrypt(1, page1)
		if err != nil {
			lastErr = err
			continue
		}
		if bytes.HasPrefix(plain, sqliteMagic) {
			return c, nil
		}
		lastErr = sqlcipher.ErrKey
	}
	if lastErr == nil {
		lastErr = sqlcipher.ErrKey
	}
	return sqlcipher.Key{}, fmt.Errorf("cipher: 密钥不正确或文件已损坏: %w", lastErr)
}

// keyCandidates 列出给定密钥串可能的喂法。
func keyCandidates(key string) []sqlcipher.Key {
	out := []sqlcipher.Key{sqlcipher.Passphrase(key)}
	// 32 位 hex 也可以还原成 16 个原始字节再当 passphrase。
	if len(key) == KeyLen {
		if raw, err := hex.DecodeString(key); err == nil {
			out = append(out, sqlcipher.Passphrase(string(raw)))
		}
	}
	return out
}

// DecryptNTQQ 解密一个 NTQQ nt_msg.db 流：先剥掉 1024 字节自定义头，
// 再解密底下的 SQLCipher 负载。
func DecryptNTQQ(r io.Reader, w io.Writer, key string) error {
	if _, err := io.CopyN(io.Discard, r, HeaderSize); err != nil {
		return fmt.Errorf("cipher: 文件不足 %d 字节，不是 NTQQ 数据库", HeaderSize)
	}
	return DecryptSQLCipher(r, w, key)
}

// DecryptNTQQFile 是 DecryptNTQQ 的文件版。
func DecryptNTQQFile(src, dst, key string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := DecryptNTQQ(in, out, key); err != nil {
		return err
	}
	return out.Close()
}
