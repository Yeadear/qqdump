// Package export 把 model.Conversation 渲染成各种可读/可交换格式。
//
// 它只依赖 model，不认识 SQL 列名，也不认识 Protobuf 细节：
// db + msgproto 负责"读懂 QQ 的数据"，export 负责"写成人能看的东西"。
package export

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Yeadear/qqdump/model"
)

// cst 是 UTC+8，QQ 的时间戳按中国时区呈现才有意义。
var cst = time.FixedZone("CST", 8*60*60)

// FmtTime 把 Unix 秒格式化为 "2006-01-02 15:04:05"。
func FmtTime(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).In(cst).Format("2006-01-02 15:04:05")
}

// FmtDate 把 Unix 秒格式化为 "2006-01-02"。
func FmtDate(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).In(cst).Format("2006-01-02")
}

// FmtClock 把 Unix 秒格式化为 "15:04"。
func FmtClock(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).In(cst).Format("15:04")
}

// FmtDuration 把秒数格式化为 "1分02秒"。
func FmtDuration(sec int32) string {
	if sec <= 0 {
		return ""
	}
	if sec < 60 {
		return fmt.Sprintf("%d秒", sec)
	}
	return fmt.Sprintf("%d分%02d秒", sec/60, sec%60)
}

// FmtSize 把字节数格式化为人类可读大小。
func FmtSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n := n / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

var unsafeChars = regexp.MustCompile(`[^\p{Han}\p{L}\p{N}_++.=]+`)

// SafeName 把任意标题转成可安全用于文件名的字符串。
// 保留中日韩文字、字母、数字和少数符号，其余替换为下划线。
func SafeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unnamed"
	}
	s = strings.ReplaceAll(s, string(filepath.Separator), "_")
	out := unsafeChars.ReplaceAllString(s, "_")
	// ".." 单独出现时也不留下：它是路径穿越的记号，即使分隔符已被替换掉
	// 也一并清理，避免拼进路径后产生歧义。
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", "_")
	}
	out = strings.Trim(out, "_.")
	if out == "" {
		return "unnamed"
	}
	// 避免文件名过长导致的文件系统问题
	if len([]rune(out)) > 60 {
		out = string([]rune(out)[:60])
	}
	return out
}

// FileName 生成会话的文件名（不含扩展名），形如 "c2c_123456_张三"。
func FileName(c model.Conversation) string {
	return fmt.Sprintf("%s_%d_%s", c.KindLabel(), c.PeerUIN, SafeName(c.Title()))
}

// SenderName 返回消息发送者的显示名，回退顺序：群名片 > 昵称 > QQ 号 > UID。
func SenderName(m model.Message) string { return model.SenderName(m) }
