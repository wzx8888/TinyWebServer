#!/usr/bin/env python3
"""
灌一份论坛演示数据，用于人工浏览 / 截图 / 录屏。

跑法（需先起服务）：

    python3 tests/seed_demo.py          # 默认 127.0.0.1:9006

为什么走 HTTP 而不是直接 INSERT：

  口令在库里是 bcrypt 散列（$2b$10$...），手写 INSERT 就得在脚本里塞散列或明文；
  而且直接写库绕过了注册接口的长度校验与唯一键冲突处理，灌出来的数据
  未必是接口真正允许的形状。走 HTTP 慢一点，但灌出来的每一条都是"真账号发的真帖子"。

脚本是幂等的：账号已存在就改为登录，不会重复建号。重复执行只会多出同名帖子。

演示账号口令统一为 Demo!pass123（演示用，不是任何真实口令）。
"""

import sys
import time

from forum_smoke import Client

PW = "Demo!pass123"


def login_or_register(c, name):
    """账号不存在就注册，已存在就登录；返回 user_id。"""
    c.post("/api/register", {"user": name, "password": PW})
    st, _, body = c.get("/api/whoami")
    if "user_id" not in body:
        c.post("/api/login", {"user": name, "password": PW})
        st, _, body = c.get("/api/whoami")
    import re
    m = re.search(r"user_id=(\d+)", body)
    if not m:
        print("  建号/登录失败：%s" % name)
        sys.exit(1)
    return int(m.group(1))


def main():
    stamp = time.strftime("%m%d-%H%M")

    alice, bob, carol = Client(), Client(), Client()
    aid = login_or_register(alice, "demo_alice")
    bid = login_or_register(bob, "demo_bob")
    cid = login_or_register(carol, "demo_carol")
    print("  账号：demo_alice=%d  demo_bob=%d  demo_carol=%d" % (aid, bid, cid))

    posts = [
        (bob, "从零给 TinyWebServer 加一个论坛业务：我踩过的 5 个坑",
         "地基不做完，业务接口根本写不下去。\n\n"
         "1. 这个项目没有真正的 CGI，cgi 只是个【是不是 POST】的标志位。\n"
         "2. 原来的表单解析写死了 \"user=\" 的 5 字节偏移，完全没法复用。\n"
         "3. 动态响应体超过 1024 字节会静默失败，表现为连接莫名断开。\n"
         "4. 线程池在调 process() 之前已经取好一条数据库连接了，业务里再取第二条会把池子压垮。\n"
         "5. 连接池不设 utf8mb4，中文内容会乱码，而且时好时坏。"),
        (bob, "为什么我把路由从 if-else 换成了表驱动",
         "原来靠 URL 最后一段的首字符分发，0/1/2/3/5/6/7 各占一个字符。\n"
         "论坛要加十来个接口，字符空间根本不够用。\n\n"
         "换成 map<string, Route> 之后，加接口只需要在表里加一行，"
         "顺带把\"这个方法是不是只接受 POST\"也变成了数据而不是散落的判断。"),
        (alice, "Cookie 安全：HttpOnly、SameSite 到底各挡什么",
         "HttpOnly 挡的是 XSS 偷 cookie，挡不住 CSRF；\n"
         "SameSite=Lax 挡的是跨站请求携带 cookie，也就是 CSRF。\n\n"
         "两个都要有，因为它们防的不是同一件事。"),
        (alice, "中文标题和正文的边界测试",
         "用户名 VARCHAR(64)，中文一个字占 3 字节。\n"
         "85 个中文字就超了 —— 按字符数校验的话根本拦不住，必须按字节算。"),
        (carol, "新人报道：这个论坛能发中文了吗",
         "试了一下，能。顺便看看关注流好不好用。"),
    ]

    made = []
    for owner, title, content in posts:
        st, hdrs, _ = owner.post("/api/article/create", {"title": title, "content": content})
        loc = hdrs.get("location", "")
        aid_ = loc.split("id=")[-1] if "id=" in loc else "?"
        made.append((title, aid_))
        print("  发帖 -> %s : %s" % (aid_, title))

    # 评论打在 bob 的第一篇上
    first_bob = made[0][1]
    alice.post("/api/comment/create", {"article_id": first_bob, "content": "第 3 条我也踩了，排查了半天。"})
    carol.post("/api/comment/create", {"article_id": first_bob, "content": "收藏了，正好在做类似的东西。"})
    bob.post("/api/comment/create", {"article_id": made[2][1], "content": "同感，两者防的不是一回事。"})
    print("  评论 3 条")

    alice.post("/api/follow", {"followee_id": str(bid)})
    carol.post("/api/follow", {"followee_id": str(bid)})
    print("  关注：alice -> bob，carol -> bob")

    print()
    print("灌数据完成。用浏览器看（VS Code 会自动转发 9006 端口）：")
    print("  论坛列表   http://127.0.0.1:9006/api/article/list")
    print("  文章详情   http://127.0.0.1:9006/api/article/detail?id=%s" % first_bob)
    print("  bob 主页   http://127.0.0.1:9006/api/profile?id=%d" % bid)
    print("  alice 关注流 http://127.0.0.1:9006/api/feed （需先以 demo_alice 登录）")
    print("  登录页     http://127.0.0.1:9006/log.html")
    print()
    print("  演示账号：demo_alice / demo_bob / demo_carol   口令：%s" % PW)
    print("  时间戳 %s（便于分辨重复执行灌出来的批次）" % stamp)


if __name__ == "__main__":
    main()
