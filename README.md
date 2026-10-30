# qqdump

**安卓 QQ（NT）聊天记录导出器**，纯 Go 实现，无 CGO、单文件二进制。

把一个 `nt_msg.db`（QQ NT 加密的聊天数据库）变成你自己能读、能存、能搜的东西：
明文 SQLite、结构化 JSON、Markdown、以及仿 QQ 气泡的 HTML 会话页。

它既是命令行工具，也是可以直接 `import` 的库。

---

## 为什么还要写一个

QQ NT 的聊天库是 **SQLCipher 加密**的，但它用的不是 SQLCipher 4 的默认参数，而是一套混合参数：

| 参数 | 值 |
|---|---|
| `cipher_page_size` | 4096 |
| `kdf_iter` | 4000 |
| `cipher_hmac_algorithm` | **HMAC_SHA1** |
| `cipher_kdf_algorithm` | PBKDF2_HMAC_SHA512 |

`HMAC_SHA1` 是 SQLCipher 3 风格的算法。现成的纯 Go SQLCipher 实现
（[`hanzoai/sqlcipher`](https://github.com/hanzoai/sqlcipher)）把 HMAC 写死成 SHA512，
直接拿来解 QQ 的库只会得到乱码。

所以本项目的解密依赖 **[`Yeadear/sqlcipher`](https://github.com/Yeadear/sqlcipher)**，
它是上面那个库的 fork，唯一改动就是**把页 HMAC 算法参数化**（其余保持不变，
SQLCipher 4 默认值照旧，仍是 drop-in 替换）。

除了解密，头部、密钥、表结构、消息体 Protobuf 也都按真机实测与
[QQBackup/nt_msg_db_util](https://github.com/QQBackup/nt_msg_db_util) 的字段研究还原。

## 它怎么处理一条消息

```
nt_msg.db
  ├─ 1024 字节自定义头  →  rand + 版本 + HMAC 算法（一段 Protobuf）
  └─ SQLCipher 库      →  md5(md5(uid) + rand) 解开
        └─ c2c_msg_table / group_msg_table（列名是协议字段编号 40001、40050…）
              └─ 40800 列 = Protobuf：MsgBody{repeated MsgContent}
                    └─ 文本 / 图片 / 文件 / 语音 / 引用 / 表情 / 系统提示 …
```

## 安装

```bash
go install github.com/Yeadear/qqdump/cmd/qqdump@latest
```

或从源码构建（Go 1.21+，无 CGO）：

```bash
git clone https://github.com/Yeadear/qqdump.git
cd qqdump
go build -o qqdump ./cmd/qqdump
```

## 用法

### 1. 找到密钥

在已经 root 的手机上（或 adb shell 里），QQ 的 uid 就在包名目录下的
`files/uid/{QQ号}###{uid}` 这个目录名里：

```bash
adb shell ls /data/data/com.tencent.mobileqq/files/uid/
# 10001###u_xxxxxxxxxxxx
```

把 `###` 后面的部分就是 uid。然后：

```bash
# 扫整个 QQ 数据目录，直接算出每个账号的密钥
qqdump keys -r /data/data/com.tencent.mobileqq
```

输出：

```json
[
  {
    "uin": "10001",
    "uid": "u_xxxxxxxxxxxx",
    "db": "/data/data/com.tencent.mobileqq/databases/nt_db/nt_qq_5f3c.../nt_msg.db",
    "rand": "vCsg8neC",
    "hmac": "HMAC_SHA1",
    "key": "b0cbdf4a02d1cc4995f467abe47b94d8"
  }
]
```

### 2. 导出

```bash
# 完整数据目录（root 直取 / adb pull 出来的都行）：自动扫描、算密钥、导出
qqdump export -r /data/data/com.tencent.mobileqq -o ./backup

# 只有一个库文件，手上有密钥
qqdump export -i nt_msg.db -k b0cbdf4a02d1cc4995f467abe47b94d8 -o ./out

# 只有一个库文件，只知道 uid：工具自己从库头取 rand 算密钥
qqdump export -i nt_msg.db -u u_xxxxxxxxxxxx -o ./out
```

常用选项：

| 选项 | 说明 |
|---|---|
| `-f` | 输出格式：`json,html,md`（默认全要） |
| `-o` | 输出目录（默认 `./qqdump-out`） |
| `-kind` | 只导出 `c2c` 或 `group` |
| `-since` / `-until` | 时间范围，`2006-01-02` 或 Unix 秒 |
| `-n` | 每个会话最多多少条 |
| `-keep` | 同时保留解密出的明文 SQLite 库 |
| `-a` | 按 QQ 号筛选账号（`-r` 模式） |

产物：

```
out/
├── index.html                  会话索引
├── messages.json               结构化全量数据
├── c2c_10001_小明.html         仿 QQ 气泡的会话页（单文件自包含）
├── c2c_10001_小明.md
└── group_888888_群_888888.html
```

### 3. 只要明文库

```bash
qqdump decrypt -i nt_msg.db -k <密钥> -o plain.db
```

产出的 `plain.db` 是标准 SQLite，任何 SQLite 工具都能直接打开；
再用 `qqdump export` 时也不需要密钥了（这条链路不需要解密步骤）。

### 4. 看库头信息

```bash
qqdump info -i nt_msg.db
```

## 作为库使用

```go
import (
    "github.com/Yeadear/qqdump"
    "github.com/Yeadear/qqdump/export"
)

convs, err := qqdump.Dump("nt_msg.db", qqdump.Options{
    UID: "u_xxxxxxxxxxxx",   // 或 Key: "b0cbdf4a..."
    Since: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
})
if err != nil {
    log.Fatal(err)
}

f, _ := os.Create("out.json")
defer f.Close()
export.WriteJSON(f, convs, "nt_msg.db")
```

各层也可以单独用：

| 包 | 职责 |
|---|---|
| `account` | 扫描数据目录定位 `nt_msg.db`、解析 1024 字节头、派生密钥 |
| `cipher` | 剥头 + SQLCipher 解密 |
| `db` | 读明文库（动态探测列名，兼容不同 QQ 版本） |
| `msgproto` | 40800 消息体 Protobuf → 消息段 |
| `model` | 领域模型（会话 / 消息 / 段） |
| `export` | 渲染成 JSON / Markdown / HTML |

```go
// 只要解密这一步
err := cipher.DecryptNTQQFile("nt_msg.db", "plain.db", key)

// 只要有明文库，直接读
convs, err := qqdump.Load("plain.db", qqdump.Options{})
```

## 设计取向

- **纯 Go，零 CGO**：交叉编译出单个二进制即可用，不拖 C 依赖。
- **不丢内容**：解不开的内容留原始字节，不认识的段显示为 `[未知类型]` 而不是消失。
- **不猜列**：QQ 各版本的列集合不一致，所以先探测再拼 SQL，缺的列取零值。
- **先验证再信任解密**：解密前先试着解第 1 页并校验 SQLite magic，
  密钥不对立刻报 `ErrKey`，绝不吐出看似正常的乱码明文。
- **HTML 必转义**：聊天内容是不可信输入，渲染时全部转义，打开自己的备份不会被 XSS。

## 已知边界

- 群名目前显示为群号：群名不在 `nt_msg.db` 里，需要另找来源。
- 图片 / 文件的直链依赖库里的 CDN 字段；QQ 的媒体链接有有效期，
  过期后导出里保留的是文件名、大小和 MD5。
- 合并转发（旧协议 XML）只呈现为占位，内部逐条内容暂未展开。

## 测试

```bash
go test ./...
```

端到端测试样本由 `tools/make_sample.py` 生成（需要系统里有 `sqlcipher` CLI）：
它按 NTQQ 的真实参数造一个加密库，含真实的 `c2c_msg_table` / `group_msg_table`
列和手工编码的 40800 Protobuf。

```bash
python3 tools/make_sample.py
go build -o qqdump ./cmd/qqdump
./qqdump export -i testdata/nt_msg_sample.db -u u_test1234abcd -o /tmp/out
```

## 许可与致谢

MIT。

字段与 Protobuf 的还原参考了
[QQBackup/nt_msg_db_util](https://github.com/QQBackup/nt_msg_db_util) 的公开研究，
解密格式参考了 [`hanzoai/sqlcipher`](https://github.com/hanzoai/sqlcipher)
（其上游是 SQLCipher，BSD-3，© ZETETIC LLC）。

本项目只用于导出**你自己**的聊天记录做备份。请遵守当地法律与 QQ 的用户协议。
