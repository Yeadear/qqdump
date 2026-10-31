// Command qqdump 导出安卓 QQ（NT）的聊天记录。
//
// 三个主命令：
//
//	qqdump keys     定位 QQ 数据目录下的账号库，算出数据库密钥
//	qqdump decrypt  把加密的 nt_msg.db 解成明文 SQLite
//	qqdump export   解密并导出为 JSON / Markdown / HTML
//
// 数据可以是安卓 root 直接读到的路径、adb pull 出来的目录，或者用户自己
// 拷贝出来的任意一层目录——三者的目录布局是一样的。nt_msg.db 的路径是固定的
// （.../databases/nt_db/nt_qq_{hash}/nt_msg.db），所以定位按固定布局拼路径，
// 不遍历磁盘。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Yeadear/qqdump"
	"github.com/Yeadear/qqdump/account"
	"github.com/Yeadear/qqdump/export"
	"github.com/Yeadear/qqdump/model"
)

const usageText = `qqdump — 安卓 QQ(NT) 聊天记录导出器

用法:
  qqdump info    -i <nt_msg.db>                        查看数据库头部（rand / HMAC 算法）
  qqdump keys    -r <QQ数据目录>                        列出账号库并算出密钥
  qqdump decrypt -i <nt_msg.db> -k <密钥> -o <明文.db>  只解密，不做导出
  qqdump export  -i <nt_msg.db> -k <密钥> -o <输出目录>  解密并导出聊天记录
  qqdump export  -r <QQ数据目录> -o <输出目录>           定位账号、算密钥、导出全部账号

  -r 可以是任意一层：/、/data、/data/user/0/com.tencent.mobileqq、
  .../databases/nt_db、.../nt_qq_{hash}，按固定布局解析，不扫描磁盘。

密钥（二选一，export/decrypt 必填其一）:
  -k <hex>   直接给出 32 位 hex 数据库密钥
  -u <uid>   给出账号的 NT UID，由库头的 rand 自动派生密钥

export 选项:
  -o <dir>      输出目录（默认 ./qqdump-out）
  -f <格式>     输出格式，逗号分隔：json,html,md（默认 html,md,json）
  -a <QQ号>     按 QQ 号筛选账号（-r 模式）
  -kind <类型>  只导出 c2c 或 group
  -since <时间> 起始时间，2006-01-02 或 Unix 秒
  -until <时间> 结束时间，同上
  -n <条数>     每个会话最多导出多少条（0 为不限）
  -keep         保留解密出的明文库

例子:
  # 手机上 root 后直接扫，导出全部会话
  qqdump export -r /data/data/com.tencent.mobileqq -o ./backup

  # 只有一个库文件，手上有密钥
  qqdump export -i nt_msg.db -k 0123456789abcdef0123456789abcdef -o ./out

  # 只知道 UID，让工具自己从库头取 rand 算密钥
  qqdump export -i nt_msg.db -u u_abcd1234 -o ./out
`

// cst 是 UTC+8，中国用户看到的时间才有意义。
var cst = time.FixedZone("CST", 8*60*60)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "keys":
		err = cmdKeys(os.Args[2:])
	case "info":
		err = cmdInfo(os.Args[2:])
	case "decrypt":
		err = cmdDecrypt(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return
	case "version":
		fmt.Println("qqdump dev")
		return
	default:
		fmt.Fprintf(os.Stderr, "qqdump: 未知命令 %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---- keys ----

func cmdKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	root := fs.String("r", "", "QQ 数据目录（/、QQ 数据目录、nt_db、nt_qq_xxx 均可）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" {
		return fmt.Errorf("keys: 需要 -r <QQ数据目录>")
	}

	accounts, err := qqdump.Accounts(*root)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return fmt.Errorf("keys: 在 %s 下没有找到 QQ NT 的数据库或账号目录", *root)
	}

	// 没有 uid 就算不出密钥，把怎么拿 uid 直接讲清楚，省得用户去猜。
	missing := 0
	for _, a := range accounts {
		if a.Key == "" {
			missing++
		}
	}
	if missing > 0 {
		fmt.Fprintf(os.Stderr,
			"提示：%d 个账号没有密钥（找不到 %s），需要 uid 才能算出密钥。\n"+
				"uid 在数据目录的 files/uid/{QQ号}###{uid} 下：\n"+
				"  adb shell ls /data/user/0/com.tencent.mobileqq/files/uid/\n"+
				"拿到 uid 后：qqdump export -i <nt_msg.db> -u <uid> -o <输出目录>\n\n",
			missing, filepath.Join("files", "uid"))
	}

	type row struct {
		UIN      string `json:"uin,omitempty"`
		UID      string `json:"uid,omitempty"`
		UIDHash  string `json:"uid_hash,omitempty"`
		PathHash string `json:"path_hash,omitempty"`
		DB       string `json:"db"`
		Rand     string `json:"rand,omitempty"`
		HMAC     string `json:"hmac,omitempty"`
		Key      string `json:"key,omitempty"`
	}
	rows := make([]row, 0, len(accounts))
	for _, a := range accounts {
		rows = append(rows, row{
			UIN: a.UIN, UID: a.UID, UIDHash: a.UIDHash, PathHash: a.PathHash,
			DB: a.DBPath, Rand: a.Rand, HMAC: a.HMACAlgo, Key: a.Key,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

// ---- info ----

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	in := fs.String("i", "", "nt_msg.db 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("info: 需要 -i <nt_msg.db>")
	}
	head, err := qqdump.Head(*in)
	if err != nil {
		return err
	}
	if head == nil {
		return fmt.Errorf("info: %s 不是 NTQQ 数据库（没有 QQ_NT DB 头标记）", *in)
	}
	fmt.Printf("文件:      %s\n", *in)
	fmt.Printf("rand:      %s\n", head.Rand)
	fmt.Printf("版本:      %s\n", head.Version)
	fmt.Printf("HMAC 算法: %s\n", head.HMACAlgo)
	if head.Raw {
		fmt.Printf("解析方式:  兜底扫描（头部没有标准长度前缀）\n")
	} else {
		fmt.Printf("解析方式:  结构化 Protobuf\n")
	}
	return nil
}

// ---- decrypt ----

func cmdDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	in := fs.String("i", "", "nt_msg.db 路径")
	out := fs.String("o", "nt_msg_plain.db", "输出的明文库路径")
	key := fs.String("k", "", "32 位 hex 密钥")
	uid := fs.String("u", "", "NT UID（用于派生密钥）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("decrypt: 需要 -i <nt_msg.db>")
	}
	if *out == "" {
		return fmt.Errorf("decrypt: 需要 -o <输出文件>")
	}

	k, err := resolveKey(*in, *key, *uid)
	if err != nil {
		return err
	}
	log.Printf("解密 %s → %s", *in, *out)
	if err := qqdump.WritePlain(*in, *out, k); err != nil {
		return err
	}
	log.Printf("完成：%s 可用任意 SQLite 工具直接打开", *out)
	return nil
}

// ---- export ----

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	in := fs.String("i", "", "nt_msg.db 路径")
	root := fs.String("r", "", "QQ 数据目录（/、QQ 数据目录、nt_db、nt_qq_xxx 均可）")
	outDir := fs.String("o", "qqdump-out", "输出目录")
	formats := fs.String("f", "html,md,json", "输出格式，逗号分隔")
	key := fs.String("k", "", "32 位 hex 密钥")
	uid := fs.String("u", "", "NT UID")
	only := fs.String("a", "", "只导出该 QQ 号的账号")
	kinds := fs.String("kind", "", "只导出 c2c 或 group")
	since := fs.String("since", "", "起始时间")
	until := fs.String("until", "", "结束时间")
	limit := fs.Int("n", 0, "每个会话最多条数")
	keep := fs.Bool("keep", false, "保留明文库")
	if err := fs.Parse(args); err != nil {
		return err
	}

	jobs, err := collectJobs(*in, *root, *key, *uid, *only)
	if err != nil {
		return err
	}

	wantFormats := parseFormats(*formats)
	if len(wantFormats) == 0 {
		return fmt.Errorf("export: -f 至少要包含 json、html 或 md 之一")
	}

	sinceTS, err := parseTime(*since)
	if err != nil {
		return fmt.Errorf("export: -since: %w", err)
	}
	untilTS, err := parseTime(*until)
	if err != nil {
		return fmt.Errorf("export: -until: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("export: 创建输出目录失败: %w", err)
	}

	for _, j := range jobs {
		dir := *outDir
		if len(jobs) > 1 && j.label != "" {
			dir = filepath.Join(*outDir, sanitize(j.label))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}

		opt := qqdump.Options{Key: j.key, Since: sinceTS, Until: untilTS, Limit: *limit}
		if *kinds != "" {
			opt.Kinds = strings.Split(*kinds, ",")
		}
		if *keep {
			opt.PlainPath = filepath.Join(dir, "nt_msg_plain.db")
		}

		log.Printf("解密并读取 %s", j.db)
		convs, err := qqdump.Dump(j.db, opt)
		if err != nil {
			return err
		}
		total := 0
		for _, c := range convs {
			total += len(c.Messages)
		}
		log.Printf("共 %d 个会话 / %d 条消息", len(convs), total)

		if err := writeOutputs(dir, convs, j.db, wantFormats); err != nil {
			return err
		}
		log.Printf("已导出到 %s", dir)
	}
	return nil
}

// ---- 共用 ----

type exportJob struct {
	db    string
	key   string
	label string
}

// collectJobs 根据 -i 或 -r 收集要处理的数据库及其密钥。
func collectJobs(in, root, key, uid, only string) ([]exportJob, error) {
	var jobs []exportJob

	switch {
	case in != "":
		k, err := resolveKey(in, key, uid)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, exportJob{db: in, key: k})

	case root != "":
		accounts, err := qqdump.Accounts(root)
		if err != nil {
			return nil, err
		}
		if len(accounts) == 0 {
			return nil, fmt.Errorf("export: 在 %s 下没有找到 QQ NT 数据库", root)
		}
		for _, a := range accounts {
			if only != "" && a.UIN != only && a.UID != only {
				continue
			}
			if a.Key == "" {
				log.Printf("跳过 %s：缺少 uid，无法派生密钥（可改用 -i 加 -u 单独导出）", a.DBPath)
				continue
			}
			label := a.UIN
			if label == "" {
				label = a.UID
			}
			jobs = append(jobs, exportJob{db: a.DBPath, key: a.Key, label: label})
		}
		if len(jobs) == 0 {
			return nil, fmt.Errorf("export: 没有可解密的数据库（缺少 uid，请用 -u 指定）")
		}

	default:
		return nil, fmt.Errorf("export: 需要 -i <nt_msg.db> 或 -r <QQ数据根目录>")
	}
	return jobs, nil
}

// resolveKey 确定密钥：优先用直接给的，其次用 uid 从库头派生。
func resolveKey(dbPath, key, uid string) (string, error) {
	if key != "" {
		return key, nil
	}
	if uid == "" {
		return "", fmt.Errorf("需要密钥：用 -k 直接给密钥，或用 -u 给出 uid 由库头 rand 派生")
	}
	head, err := qqdump.Head(dbPath)
	if err != nil {
		return "", err
	}
	if head == nil || head.Rand == "" {
		return "", fmt.Errorf("%s 的头部没有 rand，无法派生密钥，请用 -k 直接给密钥", dbPath)
	}
	return account.DeriveKey(uid, head.Rand), nil
}

// writeOutputs 按请求的格式写出所有产物。
func writeOutputs(dir string, convs []model.Conversation, source string, formats map[string]bool) error {
	if formats["json"] {
		if err := writeFile(filepath.Join(dir, "messages.json"), func(f *os.File) error {
			return export.WriteJSON(f, convs, source)
		}); err != nil {
			return err
		}
	}
	if formats["html"] || formats["md"] {
		for _, c := range convs {
			name := export.FileName(c)
			if formats["html"] {
				p := filepath.Join(dir, name+".html")
				if err := writeFile(p, func(f *os.File) error { return export.WriteHTML(f, c) }); err != nil {
					return err
				}
			}
			if formats["md"] {
				p := filepath.Join(dir, name+".md")
				if err := writeFile(p, func(f *os.File) error { return export.WriteMarkdown(f, c) }); err != nil {
					return err
				}
			}
		}
		if formats["html"] {
			p := filepath.Join(dir, "index.html")
			if err := writeFile(p, func(f *os.File) error { return export.WriteIndexHTML(f, convs) }); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func parseFormats(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "json":
			out["json"] = true
		case "html":
			out["html"] = true
		case "md", "markdown":
			out["md"] = true
		}
	}
	return out
}

// parseTime 解析 "2006-01-02" 之类的日期或 Unix 秒。
func parseTime(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	for _, layout := range []string{"2006-01-02", "2006-01-02 15:04:05", "2006/01/02", "20060102"} {
		if t, err := time.ParseInLocation(layout, s, cst); err == nil {
			return t.Unix(), nil
		}
	}
	return 0, fmt.Errorf("无法解析 %q（用 2006-01-02 或 Unix 秒）", s)
}

// sanitize 把账号标识转成安全的目录名。
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		}
		return r
	}, s)
}
