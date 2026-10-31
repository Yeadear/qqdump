// Command qqdump 导出安卓 QQ（NT）的聊天记录。
//
// 三个主命令：
//
//	qqdump keys     定位 QQ 数据目录下的账号库，算出数据库密钥
//	qqdump decrypt  把加密的 nt_msg.db 解成明文 SQLite
//	qqdump export   解密并导出为 JSON / Markdown / HTML
//
// 数据目录用 -d/--data 指定，默认是安卓上的固定位置
// /data/user/0/com.tencent.mobileqq。nt_msg.db 的路径也是固定的
// （.../databases/nt_db/nt_qq_{hash}/nt_msg.db），所以定位按布局拼路径、
// 只读 nt_db 和 files/uid 这两层目录，不遍历磁盘：给一个目录就能自动找出
// 全部账号、算出各自密钥、解密导出，不需要手工填 uid。
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
	"github.com/Yeadear/qqdump/cipher"
	"github.com/Yeadear/qqdump/db"
	"github.com/Yeadear/qqdump/export"
	"github.com/Yeadear/qqdump/model"
)

const usageText = `qqdump — 安卓 QQ(NT) 聊天记录导出器

用法:
  qqdump keys    [--data <QQ数据目录>]                    列出账号并算出密钥
  qqdump info    --input <nt_msg.db>                      查看库头（rand / HMAC 算法）
  qqdump decrypt --input <nt_msg.db> --key <密钥> --output <明文.db>
  qqdump export  [--data <QQ数据目录>] [--output <目录>]    自动找账号、算密钥、导出全部

全局参数:
  -d, --data <dir>  QQ 数据目录，默认 /data/user/0/com.tencent.mobileqq

密钥（export/decrypt 单库时二选一；用 --data 时自动算，不需要填）:
  -k, --key <hex>  直接给出 32 位 hex 数据库密钥
  -u, --uid <uid>  给出账号的 NT UID，由库头的 rand 自动派生密钥

export 选项:
  -i, --input <file>  只导出这一个 nt_msg.db
  -o, --output <dir>  输出目录（默认 ./qqdump-out）
  -f, --format <列表> 输出格式，逗号分隔：json,html,md（默认 html,md,json）
  -a, --account <QQ号> 只导出该 QQ 号
  --kind <类型>       只导出 c2c 或 group
  --since <时间>      起始时间，2006-01-02 或 Unix 秒
  --until <时间>      结束时间，同上
  -n, --limit <条数>  每个会话最多导出多少条（0 为不限）
  --keep              保留解密出的明文库（会关闭流式）
  --tolerant          解密遇到坏页时跳过并尽力导出其余数据（默认开启）
  --stream            流式导出：边解密边写出，不落明文、不整库载入内存（默认开启）

例子:
  # 手机上 root 后直接跑，自动找全部账号并导出
  qqdump export -o ./backup

  # 指定数据目录（-d 可以放在子命令前后任意位置）
  qqdump export -d /data/user/0/com.tencent.mobileqq -o ./backup

  # 只有一个库文件，手上有密钥
  qqdump export -i nt_msg.db -k 0123456789abcdef0123456789abcdef -o ./out

  # 只知道 UID，让工具自己从库头取 rand 算密钥
  qqdump export -i nt_msg.db -u u_abcd1234 -o ./out
`

// cst 是 UTC+8，中国用户看到的时间才有意义。
var cst = time.FixedZone("CST", 8*60*60)

// Go 的 flag 只认 -name / --name，-d 这种短名要单独注册。下面三个 helper
// 同时注册短名和长名，短名优先，这样 -o 和 --output 都能用。
// short 为空表示该参数只有长名（flag 不接受空名字，得跳过注册）。
func flagStr(fs *flag.FlagSet, short, long string, def, usage string) func() string {
	lv := fs.String(long, def, usage)
	if short == "" {
		return func() string { return *lv }
	}
	sv := fs.String(short, "", "")
	return func() string {
		if *sv != "" {
			return *sv
		}
		return *lv
	}
}

func flagInt(fs *flag.FlagSet, short, long string, def int, usage string) func() int {
	lv := fs.Int(long, def, usage)
	if short == "" {
		return func() int { return *lv }
	}
	sv := fs.Int(short, 0, "")
	return func() int {
		if *sv != 0 {
			return *sv
		}
		return *lv
	}
}

func flagBool(fs *flag.FlagSet, short, long string, def bool, usage string) func() bool {
	lv := fs.Bool(long, def, usage)
	if short == "" {
		return func() bool { return *lv }
	}
	sv := fs.Bool(short, false, "")
	return func() bool { return *sv || *lv }
}

// dataDir 取 --data 的值。它是全局参数，允许放在子命令前后任意位置，
// 所以既看本子命令解析到的，也在整个命令行里找一遍。
func dataDir(local string) string {
	if local != "" {
		return local
	}
	args := os.Args[1:]
	for i, a := range args {
		switch {
		case a == "-d" || a == "--data":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "-d="):
			return a[len("-d="):]
		case strings.HasPrefix(a, "--data="):
			return a[len("--data="):]
		}
	}
	return account.DefaultDataDir
}

// resolveDataDir 校验并解析 QQ 数据目录。-d 只接受真正的 QQ 数据目录。
func resolveDataDir(dir string) (string, error) {
	qqDir, ok := account.ResolveQQDir(dir)
	if !ok {
		return "", fmt.Errorf("不是 QQ 数据目录：%s\n-d/--data 只接受 %s（或其等价的 /data/data/com.tencent.mobileqq）",
			dir, account.DefaultDataDir)
	}
	return qqDir, nil
}

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
	case "diagnose":
		err = cmdDiagnose(os.Args[2:])
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
	d := flagStr(fs, "d", "data", "", "QQ 数据目录")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := resolveDataDir(dataDir(d()))
	if err != nil {
		return err
	}

	accounts, err := qqdump.Accounts(root)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return fmt.Errorf("keys: 在 %s 下没有找到 QQ NT 的数据库或账号目录", root)
	}

	// 没有 uid 就算不出密钥，把怎么拿 uid 直接讲清楚，省得用户去猜。
	missing := 0
	for _, a := range accounts {
		if a.Key == "" {
			missing++
		}
	}
	if missing > 0 {
		// 把读 uid 时到底为什么失败讲清楚，省得用户去猜
		why := ""
		if _, uerr := account.UIDInfo(root); uerr != nil {
			why = "（" + uerr.Error() + "）"
		}
		fmt.Fprintf(os.Stderr,
			"提示：%d 个账号没有密钥——没读到 files/uid %s\n"+
				"uid 目录应当是 %s，形如 {QQ号}###{uid}\n"+
				"确认一下：adb shell su -c 'ls /data/data/com.tencent.mobileqq/files/uid/'\n"+
				"也可以只导单个库：qqdump export -i <nt_msg.db> -u <uid> -o <输出目录>\n\n",
			missing, why, filepath.Join(root, "files", "uid"))
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
	in := flagStr(fs, "i", "input", "", "nt_msg.db 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if in() == "" {
		return fmt.Errorf("info: 需要 -i/--input <nt_msg.db>")
	}
	head, err := qqdump.Head(in())
	if err != nil {
		return err
	}
	if head == nil {
		return fmt.Errorf("info: %s 不是 NTQQ 数据库（没有 QQ_NT DB 头标记）", in())
	}
	fmt.Printf("文件:      %s\n", in())
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
	in := flagStr(fs, "i", "input", "", "nt_msg.db 路径")
	out := flagStr(fs, "o", "output", "nt_msg_plain.db", "输出的明文库路径")
	key := flagStr(fs, "k", "key", "", "32 位 hex 密钥")
	uid := flagStr(fs, "u", "uid", "", "NT UID（用于派生密钥）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if in() == "" {
		return fmt.Errorf("decrypt: 需要 -i/--input <nt_msg.db>")
	}

	k, err := resolveKey(in(), key(), uid())
	if err != nil {
		return err
	}
	log.Printf("解密 %s → %s", in(), out())
	if err := qqdump.WritePlain(in(), out(), k); err != nil {
		return err
	}
	log.Printf("完成：%s 可用任意 SQLite 工具直接打开", out())
	return nil
}

// ---- export ----

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	in := flagStr(fs, "i", "input", "", "只导出这一个 nt_msg.db")
	d := flagStr(fs, "d", "data", "", "QQ 数据目录")
	outDir := flagStr(fs, "o", "output", "qqdump-out", "输出目录")
	formats := flagStr(fs, "f", "format", "html,md,json", "输出格式，逗号分隔")
	key := flagStr(fs, "k", "key", "", "32 位 hex 密钥")
	uid := flagStr(fs, "u", "uid", "", "NT UID")
	only := flagStr(fs, "a", "account", "", "只导出该 QQ 号的账号")
	kinds := flagStr(fs, "", "kind", "", "只导出 c2c 或 group")
	since := flagStr(fs, "", "since", "", "起始时间")
	until := flagStr(fs, "", "until", "", "结束时间")
	limit := flagInt(fs, "n", "limit", 0, "每个会话最多条数")
	keep := flagBool(fs, "", "keep", false, "保留明文库")
	tolerant := flagBool(fs, "", "tolerant", true, "解密遇到坏页时跳过并尽力导出其余数据")
	stream := flagBool(fs, "", "stream", true, "流式导出：不落明文、不整库载入内存（默认开启）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// -d 默认就是安卓上的固定位置，所以不带任何参数也能直接跑
	root := ""
	if in() == "" {
		var err error
		root, err = resolveDataDir(dataDir(d()))
		if err != nil {
			return err
		}
	}

	jobs, err := collectJobs(in(), root, key(), uid(), only())
	if err != nil {
		return err
	}

	wantFormats := parseFormats(formats())
	if len(wantFormats) == 0 {
		return fmt.Errorf("export: -f/--format 至少要包含 json、html 或 md 之一")
	}

	sinceTS, err := parseTime(since())
	if err != nil {
		return fmt.Errorf("export: --since: %w", err)
	}
	untilTS, err := parseTime(until())
	if err != nil {
		return fmt.Errorf("export: --until: %w", err)
	}

	if err := os.MkdirAll(outDir(), 0o755); err != nil {
		return fmt.Errorf("export: 创建输出目录失败: %w", err)
	}

	// 单个账号失败不中断整个导出：记下来，最后汇总，让用户至少拿到其余账号。
	var failed []exportJob
	for _, j := range jobs {
		dir := outDir()
		if len(jobs) > 1 && j.label != "" {
			dir = filepath.Join(outDir(), sanitize(j.label))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}

		opt := qqdump.Options{Key: j.key, Since: sinceTS, Until: untilTS, Limit: limit(), Tolerant: tolerant()}
		if kinds() != "" {
			opt.Kinds = strings.Split(kinds(), ",")
		}
		if keep() {
			opt.PlainPath = filepath.Join(dir, "nt_msg_plain.db")
		}

		if stream() && !keep() {
			log.Printf("流式导出 %s（不落明文）", j.db)
			texts, count, err := exportStream(j.db, dir, opt, wantFormats)
			if err != nil {
				log.Printf("跳过 %s：%v", j.db, err)
				failed = append(failed, j)
				continue
			}
			log.Printf("共 %d 个会话 / %d 条消息", texts, count)
			log.Printf("已导出到 %s", dir)
			continue
		}

		log.Printf("解密并读取 %s", j.db)
		convs, err := qqdump.Dump(j.db, opt)
		if err != nil {
			log.Printf("跳过 %s：%v", j.db, err)
			failed = append(failed, j)
			continue
		}
		total := 0
		for _, c := range convs {
			total += len(c.Messages)
		}
		log.Printf("共 %d 个会话 / %d 条消息", len(convs), total)

		if err := writeOutputs(dir, convs, j.db, wantFormats); err != nil {
			log.Printf("跳过 %s：写出失败 %v", j.db, err)
			failed = append(failed, j)
			continue
		}
		log.Printf("已导出到 %s", dir)
	}

	if len(failed) > 0 {
		return fmt.Errorf("export: %d/%d 个账号导出失败（其余已正常导出，见上方日志）：%s",
			len(failed), len(jobs), firstFailed(failed))
	}
	return nil
}

// firstFailed 取第一个失败账号的库路径，便于在汇总错误里直接看到。
func firstFailed(js []exportJob) string {
	if len(js) == 0 {
		return ""
	}
	return js[0].db
}

// exportStream 流式导出：不落明文库，逐页解密、逐条消息写出。
// 返回（会话数, 消息数, error）。
//
// 一个会话同时打开所请求的全部格式（html / md / json）的 writer，一次遍历
// 全部写完，因此不会为每种格式重复解密。JSON 在流式模式下按会话分文件
// （conversations/<会话>.json）：把所有会话汇成一个大 JSON 数组必须把全部
// 消息留在内存里，与"流式"的初衷相违。
func exportStream(src, dir string, opt qqdump.Options, formats map[string]bool) (int, int, error) {
	if opt.Key == "" {
		return 0, 0, fmt.Errorf("流式导出需要密钥")
	}

	// 每个会话的输出目标：格式 → (文件, 流式 writer)。
	type sink struct {
		f  *os.File
		cs *export.ConvStream
	}
	var (
		convs      int
		msgs       int
		sinks      []sink
		closeSinks = func() error {
			var first error
			for _, s := range sinks {
				if s.cs != nil {
					if err := s.cs.Close(); err != nil && first == nil {
						first = err
					}
				}
				if s.f != nil {
					if err := s.f.Close(); err != nil && first == nil {
						first = err
					}
				}
			}
			sinks = nil
			return first
		}
	)

	if formats["json"] {
		if err := os.MkdirAll(filepath.Join(dir, "conversations"), 0o755); err != nil {
			return 0, 0, err
		}
	}

	h := qqdump.StreamHandler{
		Conversation: func(meta model.Conversation) error {
			if err := closeSinks(); err != nil {
				return err
			}
			convs++
			name := export.FileName(meta)
			open := func(format, path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				sinks = append(sinks, sink{f: f, cs: export.NewConvStream(format, f, meta)})
				return nil
			}
			if formats["html"] {
				if err := open("html", filepath.Join(dir, name+".html")); err != nil {
					return err
				}
			}
			if formats["md"] {
				if err := open("markdown", filepath.Join(dir, name+".md")); err != nil {
					return err
				}
			}
			if formats["json"] {
				if err := open("json", filepath.Join(dir, "conversations", name+".json")); err != nil {
					return err
				}
			}
			return nil
		},
		Message: func(m model.Message) error {
			msgs++
			for _, s := range sinks {
				if err := s.cs.Write(m); err != nil {
					return err
				}
			}
			return nil
		},
		Done: func(_ model.Conversation, _ int) error {
			return closeSinks()
		},
	}

	if err := qqdump.DumpStream(src, opt, h); err != nil {
		closeSinks()
		return convs, msgs, err
	}
	if err := closeSinks(); err != nil {
		return convs, msgs, err
	}
	return convs, msgs, nil
}

// ---- diagnose ----

// cmdDiagnose 对每个账号逐页校验 HMAC，统计坏页分布，判断源 db 是单页损坏
// 还是整段损坏（决定能否容错导出）。不写出任何文件，只读不写。
func cmdDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	in := flagStr(fs, "i", "input", "", "只诊断这一个 nt_msg.db")
	d := flagStr(fs, "d", "data", "", "QQ 数据目录")
	uid := flagStr(fs, "u", "uid", "", "NT UID")
	master := flagBool(fs, "", "master", false, "打印 sqlite_master 的解析详情（排查用）")
	scan := flagStr(fs, "", "scan", "", "逐 cell 扫描指定表（c2c_msg_table/group_msg_table），只报告解析失败的行")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root := ""
	if in() == "" {
		var err error
		root, err = resolveDataDir(dataDir(d()))
		if err != nil {
			return err
		}
	}

	if scan() != "" {
		if in() == "" {
			return fmt.Errorf("diagnose --scan: 需要 -i/--input <nt_msg.db>")
		}
		k, err := resolveKey(in(), "", uid())
		if err != nil {
			return err
		}
		sdb, err := db.OpenEncryptedStream(in(), k, true)
		if err != nil {
			return err
		}
		defer sdb.Close()
		for _, t := range sdb.Tables() {
			if scan() != "all" && t != scan() {
				continue
			}
			if err := sdb.ScanCells(os.Stdout, t); err != nil {
				return err
			}
		}
		return nil
	}

	if master() {
		if in() == "" {
			return fmt.Errorf("diagnose --master: 需要 -i/--input <nt_msg.db>")
		}
		k, err := resolveKey(in(), "", uid())
		if err != nil {
			return err
		}
		sdb, err := db.OpenEncryptedStream(in(), k, true)
		if err != nil {
			return err
		}
		defer sdb.Close()
		return sdb.DebugMaster(os.Stdout)
	}

	jobs, err := collectJobs(in(), root, "", uid(), "")
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return fmt.Errorf("diagnose: 没有可诊断的数据库")
	}

	for _, j := range jobs {
		bad, derr := cipher.DiagnoseNTQQ(j.db, j.key)
		if derr != nil {
			log.Printf("%s: 诊断失败: %v", j.db, derr)
			continue
		}
		if len(bad) == 0 {
			log.Printf("%s: 无坏页（%d 页全部 HMAC 校验通过）", j.db, 0)
			continue
		}
		log.Printf("%s: 共 %d 个坏页", j.db, len(bad))
		n := len(bad)
		if n > 30 {
			n = 30
		}
		log.Printf("  坏页（前 %d）: %v", n, bad[:n])
		// 给出最小/最大坏页，方便判断是否从某处起整段损坏
		log.Printf("  坏页范围: 最小 %d / 最大 %d / 总页数约 %d", bad[0], bad[len(bad)-1], bad[len(bad)-1])
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
		return nil, fmt.Errorf("export: 需要 -i/--input <nt_msg.db> 或 -d/--data <QQ数据目录>")
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
