#!/usr/bin/env python3
"""生成一个符合 NTQQ 参数的加密 nt_msg.db，用于端到端测试。

产出 testdata/nt_msg_sample.db，结构与真机上的一致：
  [1024 字节自定义头] + [SQLCipher 加密的 SQLite，page 4096 / kdf 4000 /
   HMAC_SHA1 / PBKDF2-HMAC-SHA512]

头里的 rand 与 uid 决定密钥：key = md5(md5(uid) + rand)，与 QQ NT 相同。
这样测试既能走 -k 直接给密钥，也能走 -u 派生，两条路径都覆盖。

用法：
    python3 tools/make_sample.py
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "testdata" / "nt_msg_sample.db"

# 与真实样本保持一致，让测试贴近真机
RAND = "vCsg8neC"
UID = "u_test1234abcd"
VERSION = "1.1.0.1"

HEADER_SIZE = 1024


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


# ---- Protobuf wire 编码（只依赖标准库，不需要 protoc）----


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def ld(field: int, data: bytes) -> bytes:
    """length-delimited 字段"""
    return tag(field, 2) + varint(len(data)) + data


def vi(field: int, n: int) -> bytes:
    """varint 字段"""
    return tag(field, 0) + varint(n)


def msg_content(seg_id: int, ctype: int, text: bytes = b"", **fields) -> bytes:
    """构造一个 MsgContent 段"""
    out = vi(45001, seg_id) + vi(45002, ctype)
    if text:
        out += ld(45101, text)
    for f, v in fields.items():
        if isinstance(v, int):
            out += vi(int(f[1:]), v)
        else:
            # 字符串与二进制一律按 length-delimited 写（协议里这些字段本就是 bytes）
            out += ld(int(f[1:]), v.encode() if isinstance(v, str) else v)
    return out


def msg_body(segments: list[bytes]) -> bytes:
    """MsgBody{repeated MsgContent content = 40800}"""
    return b"".join(ld(40800, s) for s in segments)


# ---- 测试数据 ----

C2C_COLS = (
    "40001", "40002", "40003", "40005", "40006", "40010", "40011", "40012",
    "40013", "40020", "40021", "40027", "40030", "40033", "40050", "40058",
    "40093", "40800", "40850", "40851",
)

GROUP_COLS = (
    "40001", "40002", "40003", "40005", "40006", "40010", "40011", "40012",
    "40013", "40020", "40021", "40027", "40030", "40033", "40050", "40058",
    "40090", "40093", "40800", "40850", "40851",
)


def build_rows() -> tuple[list[tuple], list[tuple]]:
    """构造 c2c / group 两表的测试行。

    行内字段顺序与 C2C_COLS / GROUP_COLS 一致，40800 是 Protobuf 的 hex 串。
    """
    seg_text = msg_content(1, 1, "你好，这是一条文本消息".encode())
    seg_img = msg_content(
        1, 2, b"",
        f45402=b"e6bc24d1a5f0e2c3_image.jpg",
        f45405=248193,
        f45411=1080,
        f45412=1920,
    )
    seg_reply = msg_content(
        1, 7, "这是引用回复".encode(),
        f47401=1001,
        f47413="被回复的那条消息",
    )
    seg_voice = msg_content(1, 4, b"", f45410=15)
    seg_face = msg_content(1, 6, b"", f47601=1, f47602="/呲牙")
    seg_mixed = msg_content(1, 1, "看看这张图".encode()) + b""
    seg_mixed2 = msg_content(2, 2, b"", f45402=b"a1b2c3d4_photo.png", f45405=51200)

    # 私聊：对方 10001，机主 10000
    c2c = [
        (1, 111, 100, 1, 1, 1, 1, 0, 0,
         "u_peer10001", "u_peer10001", 5001, 10001, 10001,
         1700000000, 1699958400, "小明",
         msg_body([seg_text]).hex().encode(), 0, 0),
        (2, 112, 99, 2, 2, 1, 1, 0, 1,
         "u_me10000", "u_peer10001", 5001, 10001, 10000,
         1700000060, 1699958400, "我",
         msg_body([seg_img]).hex().encode(), 0, 0),
        (3, 113, 98, 3, 3, 1, 7, 0, 0,
         "u_peer10001", "u_peer10001", 5001, 10001, 10001,
         1700000120, 1699958400, "小明",
         msg_body([seg_reply]).hex().encode(), 0, 0),
        (4, 114, 97, 4, 4, 1, 4, 0, 1,
         "u_me10000", "u_peer10001", 5001, 10001, 10000,
         1700000180, 1699958400, "我",
         msg_body([seg_voice]).hex().encode(), 0, 0),
        (5, 115, 96, 5, 5, 1, 6, 0, 0,
         "u_peer10001", "u_peer10001", 5001, 10001, 10001,
         1700000240, 1699958400, "小明",
         msg_body([seg_face]).hex().encode(), 0, 0),
        (6, 116, 95, 6, 6, 1, 1, 0, 1,
         "u_me10000", "u_peer10001", 5001, 10001, 10000,
         1700000300, 1699958400, "我",
         # 图文混排：一条消息两个段，必须保留段顺序
         msg_body([msg_content(1, 1, "看看这张图".encode()),
                   msg_content(2, 2, b"", f45402=b"a1b2c3d4_photo.png", f45405=51200)]).hex().encode(),
         0, 0),
        # 时间上跨到第二天，验证日期分组
        (7, 117, 94, 7, 7, 1, 1, 0, 0,
         "u_peer10001", "u_peer10001", 5001, 10001, 10001,
         1700100000, 1700044800, "小明",
         msg_body([msg_content(1, 1, "第二天了".encode())]).hex().encode(), 0, 0),
    ]

    # 群聊：群号 888888
    group = [
        (1001, 211, 10, 1, 1, 2, 1, 0, 0,
         "u_guy1", "888888", 9001, 888888, 20001,
         1700000500, 1699958400, "群里的老王", "老王",
         msg_body([msg_content(1, 1, "大家好".encode())]).hex().encode(), 0, 0),
        (1002, 212, 11, 2, 2, 2, 1, 0, 1,
         "u_me10000", "888888", 9001, 888888, 10000,
         1700000560, 1699958400, "我", "我",
         msg_body([msg_content(1, 1, "在的".encode())]).hex().encode(), 0, 0),
        (1003, 213, 12, 3, 3, 2, 1, 0, 0,
         "u_guy2", "888888", 9001, 888888, 20002,
         1700000620, 1699958400, "", "小李",
         msg_body([msg_content(1, 3, b"", f45402="报告.pdf".encode(), f45405=1048576)]).hex().encode(),
         0, 0),
        # 系统灰条（40013=3）
        (1004, 214, 13, 4, 4, 2, 8, 0, 3,
         "", "888888", 9001, 888888, 0,
         1700000680, 1699958400, "", "",
         msg_body([msg_content(1, 8, b"", f80900="小李 加入了群聊".encode())]).hex().encode(),
         0, 0),
    ]
    return c2c, group


def sql_literals(row: tuple) -> str:
    """把一行转成 SQL 字面量。bytes 就是 BLOB（40800），用 x'' 写。"""
    parts = []
    for v in row:
        if isinstance(v, bytes):
            parts.append("x'" + v.hex() + "'")
        elif isinstance(v, str):
            parts.append("'" + v.replace("'", "''") + "'")
        else:
            parts.append(str(v))
    return ", ".join(parts)


def make_header(rand: str, version: str) -> bytes:
    """构造 1024 字节自定义头：伪装页头 + QQ_NT DB 标记 + Protobuf metadata"""
    # 伪装成一个 SQLite 页头（前 100 字节），真实 QQ 就是这样
    page = bytearray(b"SQLite header 3\x00")
    page += (1024).to_bytes(2, "big")
    page += bytes(98)
    page[32:40] = b"QQ_NT DB"

    meta = ld(2, rand.encode()) + ld(3, version.encode()) + ld(4, b"HMAC_SHA1")
    page[40:44] = struct.pack("<I", len(meta))
    page[44:44 + len(meta)] = meta

    head = bytes(page)
    return head + bytes(HEADER_SIZE - len(head))


def main() -> int:
    c2c, group = build_rows()
    key = md5_hex(md5_hex(UID) + RAND)
    print(f"uid     = {UID}")
    print(f"rand    = {RAND}")
    print(f"key     = {key}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    for p in (OUT, ROOT / "testdata" / "_sample_enc_tmp.db"):
        if p.exists():
            p.unlink()

    c2c_cols = ", ".join('"%s"' % c for c in C2C_COLS)
    group_cols = ", ".join('"%s"' % c for c in GROUP_COLS)
    sql = [
        "PRAGMA cipher_page_size = 4096;",
        "PRAGMA key = '%s';" % key,
        "PRAGMA kdf_iter = 4000;",
        "PRAGMA cipher_hmac_algorithm = HMAC_SHA1;",
        "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
        "CREATE TABLE c2c_msg_table (%s);" % c2c_cols,
        "CREATE TABLE group_msg_table (%s);" % group_cols,
    ]
    for row in c2c:
        sql.append("INSERT INTO c2c_msg_table (%s) VALUES (%s);" % (c2c_cols, sql_literals(row)))
    for row in group:
        sql.append("INSERT INTO group_msg_table (%s) VALUES (%s);" % (group_cols, sql_literals(row)))
    sql.append(".quit")

    tmp = ROOT / "testdata" / "_sample_enc_tmp.db"
    proc = subprocess.run(
        ["sqlcipher", str(tmp)],
        input="\n".join(sql).encode(),
        capture_output=True,
    )
    if proc.returncode != 0:
        print(proc.stderr.decode(), file=sys.stderr)
        return 1

    body = tmp.read_bytes()
    tmp.unlink()

    with OUT.open("wb") as f:
        f.write(make_header(RAND, VERSION))
        f.write(body)

    print(f"已生成   = {OUT}  ({OUT.stat().st_size} 字节)")
    print(f"         = {HEADER_SIZE} 头 + {len(body)} 加密库 "
          f"({len(body) // 4096} 页 × 4096)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
