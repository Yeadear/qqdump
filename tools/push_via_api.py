#!/usr/bin/env python3
"""在 github.com:443 不可达时，改用 Git Data API 推送提交。

背景：某些网络环境下 api.github.com 能通、github.com 被拦，`git push`
会卡在 TLS 握手直到超时。GitHub 的 Git Data API 走 api.github.com，
可以逐个提交重建 tree 并更新 ref，等价于一次普通 push（提交信息与顺序保留）。

用法：
    python3 tools/push_via_api.py [base-commit]

    base-commit  本地已有的、远程也已有的那个提交（默认 origin/main）。
                 脚本只推送 base..HEAD 之间的提交。

依赖：gh（已登录，具备 repo 权限）、git。

注意：API 重建的提交 sha 与本地不同，但 tree 完全相同。
推送后用下面的命令核对内容一致：
    git rev-parse HEAD^{tree}
    curl -s -H "Authorization: Bearer $(gh auth token)" \\
        https://api.github.com/repos/<owner>/<repo>/git/commits/<远程sha> \\
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["tree"]["sha"])'
"""
import json
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "Yeadear/qqdump"
API = f"https://api.github.com/repos/{REPO}"
WORK = subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True
).strip()

TOKEN = subprocess.check_output(["gh", "auth", "token"], text=True).strip()


def call(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            body = r.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} {method} {url}\n{e.read().decode()[:800]}", file=sys.stderr)
        raise


def git(*args, binary=False):
    out = subprocess.check_output(["git", "-C", WORK, *args])
    return out if binary else out.decode("utf-8", "surrogateescape")


def remote_main():
    return call("GET", f"{API}/git/refs/heads/main")["object"]["sha"]


def remote_tree_of(sha):
    return call("GET", f"{API}/git/commits/{sha}")["tree"]["sha"]


def main():
    if len(sys.argv) > 1:
        base = sys.argv[1]
    else:
        base = subprocess.check_output(
            ["git", "-C", WORK, "rev-parse", "origin/main"], text=True
        ).strip()

    shas = git("rev-list", "--reverse", f"{base}..HEAD").split()
    if not shas:
        print("没有待推送的提交")
        return

    print(f"待推送 {len(shas)} 个提交")
    remote_parent = remote_main()
    print("远程 main =", remote_parent[:7])

    for s in shas:
        changed = git("diff", "--name-status", f"{s}^", s).splitlines()
        if not changed:
            print(f"  跳过（无变化）{s[:7]}")
            continue

        entries = []
        for line in changed:
            parts = line.split("\t")
            status = parts[0][0]
            if status == "D":
                entries.append({"path": parts[1], "mode": "100644", "type": "blob", "sha": None})
                continue
            if status == "R":
                # 重命名拆成「删旧 + 加新」
                entries.append({"path": parts[1], "mode": "100644", "type": "blob", "sha": None})
                path = parts[2]
            else:
                path = parts[1]
            mode = git("ls-tree", s, "--", path).split()[0]
            content = git("cat-file", "blob", f"{s}:{path}", binary=True)
            blob = call("POST", f"{API}/git/blobs", {
                "content": content.decode("utf-8", "surrogateescape"),
                "encoding": "utf-8",
            })
            entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})

        base_tree = remote_tree_of(remote_parent)
        new_tree = call("POST", f"{API}/git/trees", {"base_tree": base_tree, "tree": entries})
        msg = git("log", "-1", "--format=%B", s)
        nc = call("POST", f"{API}/git/commits", {
            "message": msg,
            "tree": new_tree["sha"],
            "parents": [remote_parent],
        })
        call("PATCH", f"{API}/git/refs/heads/main", {"sha": nc["sha"], "force": False})
        remote_parent = nc["sha"]
        print(f"  {s[:7]} -> {nc['sha'][:7]}  {msg.splitlines()[0]}")

    print("远程 main 现在 =", remote_main())


if __name__ == "__main__":
    main()
