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
//
// 同一个 QQ 安装里的库参数应当一致，但不同版本/账号偶见差异。DecryptNTQQFile
// 会在解密前先用第 1 页试出正确的 HMAC 算法与迭代次数，做到参数自适应。
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

// 解密时试的 HMAC 算法与迭代次数组合。第一项就是 NTQQ 的常见配置，
// 放在最前，绝大多数库一次命中。
var (
	probeHMAC = []sqlcipher.HMACAlgo{sqlcipher.HMACSHA1, sqlcipher.HMACSHA512}
	probeIter = []int{4000, 64000, 256000}
)

func params(iter int, h sqlcipher.HMACAlgo) sqlcipher.Params {
	if iter == 0 {
		iter = DefaultKDFIter
	}
	return sqlcipher.Params{PageSize: PageSize, Iter: iter, HMAC: h}
}

// DecryptSQLCipher 解密一个裸 SQLCipher 流（不含 NTQQ 头）成明文 SQLite 流。
//
// key 是 32 位 hex 字符串。若它解不开，会再试一次"把这段 hex 还原成 16 个原始
// 字节后当 passphrase"——两种材料都能派生出密钥，取决于 QQ 版本把哪一种喂给了
// SQLCipher，试一次就能确定，代价只是一次 4000 轮 PBKDF2。
//
// 这个流式版本只尝试一组参数（因为 io.Reader 不可回退）；需要参数自适应请用
// DecryptNTQQFile（基于可随机读的文件）。
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

	k, err := probeKey(key, salt, page1, params(0, sqlcipher.HMACSHA1))
	if err != nil {
		return err
	}

	src := io.MultiReader(bytes.NewReader(page1), r)
	if err := sqlcipher.DecryptFile(w, src, k, params(0, sqlcipher.HMACSHA1)); err != nil {
		return fmt.Errorf("cipher: 解密: %w", err)
	}
	return nil
}

// probeKey 在候选密钥形式里挑出能解开 page 1 的那个（给定一组参数）。
func probeKey(key string, salt, page1 []byte, p sqlcipher.Params) (sqlcipher.Key, error) {
	var lastErr error
	for _, c := range keyCandidates(key) {
		codec, err := sqlcipher.NewCodec(c, salt, p)
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
// 再解密底下的 SQLCipher 负载。流式版本只尝试一组参数，详见 DecryptSQLCipher。
func DecryptNTQQ(r io.Reader, w io.Writer, key string) error {
	if _, err := io.CopyN(io.Discard, r, HeaderSize); err != nil {
		return fmt.Errorf("cipher: 文件不足 %d 字节，不是 NTQQ 数据库", HeaderSize)
	}
	return DecryptSQLCipher(r, w, key)
}

// DecryptNTQQFile 是 DecryptNTQQ 的文件版：基于可随机读的文件做参数自适应。
//
// 先用第 1 页（含剥掉的 NTQQ 头）试出正确的 HMAC 算法与迭代次数组合，再用它
// 一次性解密整库。这样即便个别库用了不同的 cipher 参数也能自动适配，而不必
// 在 page 1 之后才因算法不对而失败。
func DecryptNTQQFile(src, dst, key string) error {
	if key == "" {
		return errors.New("cipher: 密钥为空")
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	k, p, err := probeParams(in, key)
	if err != nil {
		return err
	}

	if _, err := in.Seek(HeaderSize, io.SeekStart); err != nil {
		return fmt.Errorf("cipher: 定位到 SQLCipher 负载失败: %w", err)
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if err := sqlcipher.DecryptFile(out, in, k, p); err != nil {
		// 第 1 页能过说明密钥正确，中途某页 HMAC 失败几乎都是源文件本身
		// 不完整——典型是导出时 QQ 正在写这个库，或文件被拷贝截断。
		if errors.Is(err, sqlcipher.ErrKey) {
			return fmt.Errorf("cipher: 解密: %w（第 1 页能解开，说明密钥正确；"+
				"中途页面校验失败通常是源 db 不完整——请关闭 QQ 后重新导出，"+
				"或复制一份干净的 db 再用 -i 单独导出）", err)
		}
		return fmt.Errorf("cipher: 解密: %w", err)
	}
	return out.Close()
}

// probeParams 用第 1 页试出能解开的正确参数组合。只对第 1 页做，开销极小。
// 命中时返回对应的密钥材料与参数；都不行则报密钥/损坏错误。
func probeParams(in *os.File, key string) (sqlcipher.Key, sqlcipher.Params, error) {
	if _, err := in.Seek(HeaderSize, io.SeekStart); err != nil {
		return sqlcipher.Key{}, sqlcipher.Params{}, fmt.Errorf("cipher: 定位到第 1 页失败: %w", err)
	}
	page1 := make([]byte, PageSize)
	if _, err := io.ReadFull(in, page1); err != nil {
		return sqlcipher.Key{}, sqlcipher.Params{}, fmt.Errorf("cipher: 读取第 1 页: %w", err)
	}
	salt, err := sqlcipher.FileSalt(page1)
	if err != nil {
		return sqlcipher.Key{}, sqlcipher.Params{}, fmt.Errorf("cipher: 读取 salt: %w", err)
	}

	var lastErr error
	for _, h := range probeHMAC {
		for _, it := range probeIter {
			p := params(it, h)
			for _, c := range keyCandidates(key) {
				codec, err := sqlcipher.NewCodec(c, salt, p)
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
					return c, p, nil
				}
				lastErr = sqlcipher.ErrKey
			}
		}
	}
	if lastErr == nil {
		lastErr = sqlcipher.ErrKey
	}
	return sqlcipher.Key{}, sqlcipher.Params{}, fmt.Errorf("cipher: 密钥不正确或文件已损坏: %w", lastErr)
}

// DiagnoseNTQQ 与 DecryptNTQQFile 同样的参数试探后，逐页调用 Codec.Decrypt
// 统计 HMAC 校验失败的页码。用于判断源 db 是单页损坏还是整段损坏——
// 单页可容错跳过，整段（如文件从某偏移起错位）则需要换一份干净的 db。
func DiagnoseNTQQ(src, key string) (bad []uint32, err error) {
	if key == "" {
		return nil, errors.New("cipher: 密钥为空")
	}
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	k, p, err := probeParams(in, key)
	if err != nil {
		return nil, err
	}
	if _, err := in.Seek(HeaderSize, io.SeekStart); err != nil {
		return nil, fmt.Errorf("cipher: 定位到第 1 页失败: %w", err)
	}
	page1 := make([]byte, PageSize)
	if _, err := io.ReadFull(in, page1); err != nil {
		return nil, fmt.Errorf("cipher: 读取第 1 页: %w", err)
	}
	salt, err := sqlcipher.FileSalt(page1)
	if err != nil {
		return nil, err
	}
	codec, err := sqlcipher.NewCodec(k, salt, p)
	if err != nil {
		return nil, err
	}

	if _, err := in.Seek(HeaderSize, io.SeekStart); err != nil {
		return nil, err
	}
	page := make([]byte, PageSize)
	var pgno uint32 = 1
	for {
		n, rerr := io.ReadFull(in, page)
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return bad, fmt.Errorf("cipher: 读取第 %d 页: %w", pgno, rerr)
		}
		if n != len(page) {
			break
		}
		if _, derr := codec.Decrypt(pgno, page); derr != nil {
			bad = append(bad, pgno)
		}
		pgno++
	}
	return bad, nil
}

// DecryptNTQQFileTolerant 与 DecryptNTQQFile 逻辑相同，但某页 HMAC 校验失败时
// 不再整体失败，而是写入等长的零页占位（保持页对齐），并把这些坏页页码返回。
// 适用于源 db 仅有个别页损坏、希望尽力导出其余数据的场景。坏页所在的 b-tree
// 子树在随后的读取阶段仍可能读不出，调用方应做好逐表/逐会话容错。
func DecryptNTQQFileTolerant(src, dst, key string) (bad []uint32, err error) {
	if key == "" {
		return nil, errors.New("cipher: 密钥为空")
	}
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	k, p, err := probeParams(in, key)
	if err != nil {
		return nil, err
	}
	if _, err := in.Seek(HeaderSize, io.SeekStart); err != nil {
		return nil, fmt.Errorf("cipher: 定位到 SQLCipher 负载失败: %w", err)
	}
	page1 := make([]byte, PageSize)
	if _, err := io.ReadFull(in, page1); err != nil {
		return nil, fmt.Errorf("cipher: 读取第 1 页: %w", err)
	}
	salt, err := sqlcipher.FileSalt(page1)
	if err != nil {
		return nil, err
	}
	codec, err := sqlcipher.NewCodec(k, salt, p)
	if err != nil {
		return nil, err
	}

	out, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()

	page := make([]byte, PageSize)
	var pgno uint32 = 1
	for {
		n, rerr := io.ReadFull(in, page)
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return bad, fmt.Errorf("cipher: 读取第 %d 页: %w", pgno, rerr)
		}
		if n != len(page) {
			if _, werr := out.Write(page[:n]); werr != nil {
				return bad, werr
			}
			break
		}
		plain, derr := codec.Decrypt(pgno, page)
		if derr != nil {
			bad = append(bad, pgno)
			if _, werr := out.Write(make([]byte, PageSize)); werr != nil {
				return bad, werr
			}
		} else {
			if _, werr := out.Write(plain); werr != nil {
				return bad, werr
			}
		}
		pgno++
	}
	return bad, nil
}

// Decrypter 封装一个加密 nt_msg.db 的"按需逐页解密"。
//
// 它和 DecryptNTQQFile 不同：不把整个库解密到磁盘，也不整库载入内存，
// 而是每次只取调用方需要的那一页。这正好对接 SQLite 的随机页访问模型——
// 读消息时顺着 b-tree 走到哪页才解哪页，因此磁盘上不出现明文副本，
// 内存里也只有当前页，CPU 也只解密真正被读到的页。
type Decrypter struct {
	f          *os.File
	codec      *sqlcipher.Codec
	pageSize   int
	reserve    int
	headerSize int
	pages      uint32 // 文件里实际存在的页数，用于挡住越界页号
	tolerant   bool
}

// reserveOf 由 Params 的 HMAC 算法推导每页保留区大小（IV || HMAC 槽）。
// HMAC_SHA1 → 16+32=48，HMAC_SHA512 → 16+64=80。sqlcipher.Params.reserve()
// 是包内未导出方法，这里用等价的公开字段重算。
func reserveOf(p sqlcipher.Params) int {
	if p.HMAC == sqlcipher.HMACSHA1 {
		return sqlcipher.IVSize + 32
	}
	return sqlcipher.IVSize + 64
}

// NewDecrypter 打开一个加密的 nt_msg.db 并探测正确的解密参数，但不解密任何页。
func NewDecrypter(src, key string, tolerant bool) (*Decrypter, error) {
	if key == "" {
		return nil, errors.New("cipher: 密钥为空")
	}
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	k, p, err := probeParams(in, key)
	if err != nil {
		in.Close()
		return nil, err
	}
	// probeParams 已把指针移到 SQLCipher 负载第 1 页；重新读取 salt 并建 codec。
	if _, err := in.Seek(HeaderSize, io.SeekStart); err != nil {
		in.Close()
		return nil, fmt.Errorf("cipher: 定位到第 1 页失败: %w", err)
	}
	page1 := make([]byte, PageSize)
	if _, err := io.ReadFull(in, page1); err != nil {
		in.Close()
		return nil, fmt.Errorf("cipher: 读取第 1 页: %w", err)
	}
	salt, err := sqlcipher.FileSalt(page1)
	if err != nil {
		in.Close()
		return nil, err
	}
	codec, err := sqlcipher.NewCodec(k, salt, p)
	if err != nil {
		in.Close()
		return nil, err
	}
	st, err := in.Stat()
	if err != nil {
		in.Close()
		return nil, err
	}
	pages := uint32(0)
	if size := st.Size() - HeaderSize; size > 0 {
		pages = uint32(size / PageSize)
	}
	return &Decrypter{
		f:          in,
		codec:      codec,
		pageSize:   PageSize,
		reserve:    reserveOf(p),
		headerSize: HeaderSize,
		pages:      pages,
		tolerant:   tolerant,
	}, nil
}

// Close 释放底层文件句柄。
func (d *Decrypter) Close() error { return d.f.Close() }

// PageSize 是加密页（含 reserve 尾部）的字节数。
func (d *Decrypter) PageSize() int { return d.pageSize }

// PageCount 是文件里实际存在的页数。调用方在跟着 b-tree 指针走时可以先用它
// 挡掉越界页号——页号一旦越界说明指针被读坏了，此时返回 sql.ErrNoRows 之类的
// 错误没有意义，直接跳过更稳。
func (d *Decrypter) PageCount() uint32 { return d.pages }

// UsableSize 是每页可被 SQLite 使用的字节数（pageSize - reserve）。
func (d *Decrypter) UsableSize() int { return d.pageSize - d.reserve }

// ErrCorruptPage 表示某一页 HMAC 校验失败。仅在容错模式下由 DecryptPage 返回，
// 调用方应跳过该页的 cell 并继续后续页。
var ErrCorruptPage = errors.New("cipher: 坏页（HMAC 校验失败）")

// ErrPageOutOfRange 表示页号超出了文件实际页数。正常库里不会出现，
// 一旦出现必然是上层把指针读坏了（或文件被截断）。
var ErrPageOutOfRange = errors.New("cipher: 页号超出文件范围")

// DecryptPage 解密第 pgno 页（1-based），返回该页的 SQLite 内容区
// （已去掉 IV+HMAC 保留尾部）。容错模式下遇到坏页会返回
// (全零内容, ErrCorruptPage)，由调用方决定如何跳过。
func (d *Decrypter) DecryptPage(pgno uint32) ([]byte, error) {
	if pgno == 0 {
		return nil, fmt.Errorf("cipher: 页号从 1 开始")
	}
	if d.pages > 0 && pgno > d.pages {
		return nil, fmt.Errorf("%w: 第 %d 页，文件只有 %d 页", ErrPageOutOfRange, pgno, d.pages)
	}
	off := int64(d.headerSize) + int64(pgno-1)*int64(d.pageSize)
	buf := make([]byte, d.pageSize)
	n, err := d.f.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != d.pageSize {
		return nil, fmt.Errorf("%w: 第 %d 页不足 %d 字节（只有 %d）",
			ErrPageOutOfRange, pgno, d.pageSize, n)
	}
	plain, err := d.codec.Decrypt(pgno, buf)
	if err != nil {
		if d.tolerant {
			return make([]byte, d.UsableSize()), ErrCorruptPage
		}
		return nil, err
	}
	return plain[:d.UsableSize()], nil
}
