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
qqdump keys -d /data/data/com.tencent.mobileqq
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
# 完整数据目录（root 直取 / adb pull 出来的都行）：定位账号、算密钥、导出
qqdump export -o ./backup   # 默认就是 /data/user/0/com.tencent.mobileqq

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

### 5. 大库怎么跑

`export` 默认就是流式的：边解密边写，不落明文库，也不把整库读进内存。
一次遍历把这张表里所有会话的消息分发到各自的输出，不是每个会话各扫一遍全表。

在 6.3GB / 2350 会话 / 563.8 万条的实测库上（arm64 安卓容器内）：

| 方式 | 耗时 | 峰值内存 |
|---|---|---|
| 每个会话各扫一遍全表 | 49 分钟只出 229 个会话 | — |
| 单遍扇出，窗口 4096 | 409 秒 | 2.9 GB |
| 单遍扇出，窗口 512（默认） | **349 秒** | **628 MB** |

窗口是"每个会话缓冲多少条再排序写出"，扇出时所有会话同时保留窗口，
所以内存约等于 会话数 × 窗口 × 单条大小。会话特别多又内存紧张时，
可以用 `--limit` 限制每会话条数，或分批导出。

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
| `account` | 按固定布局定位 `nt_msg.db`、解析 1024 字节头、派生密钥 |
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
- 极少数损坏的 cell 读不出来时会跳过并计入 `Skipped()`，导出结尾会提示条数。
  在 6.6GB、566 万条的实测库上是 4098 条（0.07%）。

## 几个实现上的坑

写这块时踩到过，记下来免得重复。

**同一个群有多条"会话"是正常的，但不能多出一个 `peer=0`。**
QQ 里部分群系统消息（`40011=5`、子类型 4 的成员变动）不写 `40030`，
只把群号放在 `40021` 和 `40027`。直接读 `40030` 会得到 0，这些消息就会
流进一个不存在的"0 号会话"。所以取会话归属时按
`40030 → 40021 → 40027` 依次回退；私聊最后才允许用发送者兜底，
群表不能（发送者是群成员，不是会话）。

**b-tree 的物理顺序不是时间序。**
`40003` 在 c2c 表里是全局倒序、在群表里是群内序号，但群表的 `40003`
并不严格随时间递增。所以排序以 `40050` 时间戳为主，同秒再用 `40003`
和 rowid 稳定。流式场景下只能用固定窗口（默认 512 条）缓冲后排序，
跨窗口的时钟不一致无法消除——实测 560 万条里有几十处、最大回退几天，
这是源数据本身就有的问题。

**参数探测不能只看魔数。**
`HMAC_SHA1`（reserve 48）和 `HMAC_SHA512`（reserve 80）用同一把页密钥，
两者都能解出 page 1 的 `SQLite format 3\0`。只看魔数会选错算法，
后面所有页都跟着错位。现在额外检查 page 1 的结构自洽：页类型合法、
cell 指针数组不越界、每个 cell 指针都落在页头之后。可用长度算大了
必然截断 cell 区，指针就会越界。

**文件头第 20 字节不是 SQLCipher reserve。**
按它去选算法反而解不开 page 1。实测该库的 reserve 是 48，
依据是 page 1 尾部确实有真实的 cell 指针数据，尾部没有多出的 32 字节。

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
