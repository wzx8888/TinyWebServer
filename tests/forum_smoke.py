#!/usr/bin/env python3
"""
TinyWebServer 论坛业务冒烟测试。

跑法（需先起服务，默认 127.0.0.1:9006）：

    python3 tests/forum_smoke.py            # 默认 9006
    python3 tests/forum_smoke.py 9008       # 指定端口

设计上的两条自我约束：

1. 纯 HTTP，不连数据库。凭据写在 main.cpp 里，脚本一旦连库就得把口令抄一份
   进来；这个文件是要进版本库的，所以宁可少验一层。
2. 断言必须落在"可判定的具体值"上（状态码、Location 里解析出的 id、
   正则提取出的计数），不用"页面上出现了这个词"这种糊断言 ——
   /api/whoami 的响应体只有 user_id，打它去测用户名是永远会过的假通过。

覆盖：注册 → 登录 → 发帖 → 列表 → 详情 → 评论 → 关注 → 关注流 → 个人页 → 登出，
外加 6 类负向用例（未登录、跨站 Origin、方法错、XSS、SQL 注入、超长输入）。

退出码 0 表示全过；非 0 表示有断言失败，失败项会逐条打印。
"""

import http.client
import re
import sys
import time
import urllib.parse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9006
ORIGIN = "http://%s:%d" % (HOST, PORT)
COOKIE = "SESSIONID"

passed = []
failed = []


def check(name, cond, detail=""):
    if cond:
        passed.append(name)
    else:
        failed.append((name, detail))


class Client:
    """一次性连接 + 手工 cookie jar。

    服务端支持 keep-alive，但这里每条请求新建连接、发 Connection: close：
    冒烟的目的是验契约而不是验连接复用（那是行为回归用例的事），
    少一个变量就少一种"到底是谁的错"的扯皮。
    """

    def __init__(self):
        self.cookie = None

    def request(self, method, path, body=None, origin=ORIGIN, with_cookie=True):
        headers = {"Host": "%s:%d" % (HOST, PORT), "Connection": "close"}
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if origin is not None:
            headers["Origin"] = origin
        if with_cookie and self.cookie:
            headers["Cookie"] = "%s=%s" % (COOKIE, self.cookie)

        conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw_body = resp.read().decode("utf-8", "replace")
            status, hdrs = resp.status, resp.getheaders()
        finally:
            conn.close()

        for k, v in hdrs:
            if k.lower() == "set-cookie" and v.startswith(COOKIE + "="):
                self.cookie = v.split(";")[0].split("=", 1)[1]
        return status, dict((k.lower(), v) for k, v in hdrs), raw_body

    def post(self, path, fields, **kw):
        return self.request(
            "POST", path, urllib.parse.urlencode(fields), **kw
        )

    def get(self, path, **kw):
        return self.request("GET", path, None, **kw)


def location_id(headers, key):
    """从 302 的 Location 里解析出 ?key=<id>，解析不到返回 None。"""
    loc = headers.get("location", "")
    m = re.search(r"[?&]%s=(\d+)" % re.escape(key), loc)
    return int(m.group(1)) if m else None


def main():
    stamp = str(int(time.time()))
    alice = "smoke_a_" + stamp
    bob = "smoke_b_" + stamp
    pw = "Sm0ke!pass"

    a = Client()

    # ---------- 1. 静态页与新会话 ----------
    st, _, body = a.get("/judge.html")
    check("静态页 /judge.html 返回 200", st == 200, "got %s" % st)
    # 会话只在登录/注册成功时创建，静态页不该平白发一把钥匙出去
    check("未登录访问静态页不发会话 Cookie", a.cookie is None,
          "拿到了 %s" % a.cookie)

    st, _, body = a.get("/api/whoami")
    check("未登录时 whoami 说 not logged in", "not logged in" in body, body[:80])

    # ---------- 2. 注册 ----------
    # 注册/登录/登出成功时是 200 + 直接渲染目标页面（serve_file），不是 302。
    # 只有改数据的业务接口（发帖/评论/关注）才走 302 + Location。
    st, hdrs, body = a.post("/api/register", {"user": alice, "password": pw})
    check("注册返回 200", st == 200, "got %s" % st)
    sc = hdrs.get("set-cookie", "")
    check("注册下发 SESSIONID", sc.startswith(COOKIE + "="), sc[:60])
    check("Cookie 带 HttpOnly", "HttpOnly" in sc, sc)
    check("Cookie 带 SameSite=Lax", "SameSite=Lax" in sc, sc)
    check("Cookie 带 Path=/", "Path=/" in sc, sc)
    check("Cookie 带 Max-Age", "Max-Age=" in sc, sc)

    st, _, body = a.get("/api/whoami")
    m = re.search(r"user_id=(\d+)", body)
    check("注册后 whoami 能拿到 user_id", m is not None, body[:120])
    alice_id = int(m.group(1)) if m else -1

    # ---------- 3. 发帖 ----------
    title = "冒烟帖 " + stamp
    st, hdrs, body = a.post("/api/article/create", {"title": title, "content": "第一行\n第二行"})
    check("发帖返回 302", st == 302, "got %s" % st)
    aid = location_id(hdrs, "id")
    check("发帖的 Location 里能解析出 article_id", aid is not None, hdrs.get("location", ""))

    # ---------- 4. 列表与详情 ----------
    st, _, body = a.get("/api/article/list?page=1")
    check("列表页返回 200", st == 200, "got %s" % st)
    check("列表页出现刚发的帖子", title in body, "标题未出现在列表中")
    check("列表页的文章链接指向详情", "/api/article/detail?id=%d" % aid in body, "")

    st, _, body = a.get("/api/article/detail?id=%d" % aid)
    check("详情页返回 200", st == 200, "got %s" % st)
    check("详情页有标题", title in body, "")
    check("详情页有正文", "第一行" in body, "")

    # ---------- 5. 评论 ----------
    ctext = "冒烟评论 " + stamp
    st, hdrs, body = a.post(
        "/api/comment/create", {"article_id": str(aid), "content": ctext}
    )
    check("评论返回 302", st == 302, "got %s" % st)
    check("评论后跳回文章详情", hdrs.get("location", "").endswith("id=%d" % aid),
          hdrs.get("location", ""))
    st, _, body = a.get("/api/article/detail?id=%d" % aid)
    check("详情页出现评论内容", ctext in body, "")

    # ---------- 6. 第二个用户 + 关注 + 关注流 ----------
    b = Client()
    st, _, _ = b.post("/api/register", {"user": bob, "password": pw})
    check("B 注册返回 200", st == 200, "got %s" % st)
    st, _, body = b.get("/api/whoami")
    m = re.search(r"user_id=(\d+)", body)
    bob_id = int(m.group(1)) if m else -1

    btitle = "B 的帖子 " + stamp
    st, hdrs, _ = b.post("/api/article/create", {"title": btitle, "content": "B 的正文"})
    check("B 发帖成功", st == 302, "got %s" % st)

    st, hdrs, body = a.post("/api/follow", {"followee_id": str(bob_id)})
    check("A 关注 B 返回 302", st == 302, "got %s" % st)
    check("关注后跳到 B 的个人页",
          hdrs.get("location", "").endswith("id=%d" % bob_id), hdrs.get("location", ""))

    st, _, body = a.get("/api/feed")
    check("A 的关注流里有 B 的帖子", btitle in body, "feed 里没有 B 的帖子")

    st, _, body = b.get("/api/feed")
    check("B 的关注流里没有 A 的帖子（关注是单向的）", title not in body, "")

    # ---------- 7. 个人页计数 ----------
    st, _, body = a.get("/api/profile?id=%d" % bob_id)
    check("B 的个人页返回 200", st == 200, "got %s" % st)
    fans = re.search(r'class="stat">粉丝\s*<b>(\d+)</b>', body)
    check("B 的粉丝数为 1", fans is not None and fans.group(1) == "1",
          "粉丝计数未匹配到或不为 1")

    st, _, body = a.get("/api/profile?id=%d" % alice_id)
    arts = re.search(r'class="stat">文章\s*<b>(\d+)</b>', body)
    check("A 的文章数为 1", arts is not None and arts.group(1) == "1",
          "文章计数未匹配到或不为 1")

    # ---------- 8. 负向：鉴权与协议 ----------
    anon = Client()
    st, _, _ = anon.post("/api/article/create", {"title": "x", "content": "y"})
    check("未登录发帖返回 401", st == 401, "got %s" % st)

    st, _, _ = a.post("/api/article/create", {"title": "x", "content": "y"},
                      origin="http://evil.example")
    check("跨站 Origin 发帖返回 403", st == 403, "got %s" % st)

    st, _, _ = a.get("/api/article/create")
    check("GET 打写接口返回 405", st == 405, "got %s" % st)

    st, _, _ = anon.get("/api/article/detail?id=999999")
    check("不存在的文章返回 404", st == 404, "got %s" % st)

    # 无 Origin 的非浏览器客户端（curl/脚本）按设计放行
    raw = Client()
    raw.cookie = a.cookie
    st, _, _ = raw.post("/api/article/create", {"title": "无 Origin " + stamp, "content": "z"},
                        origin=None)
    check("无 Origin 的脚本客户端可发帖（设计如此）", st == 302, "got %s" % st)

    # ---------- 9. 负向：注入与转义 ----------
    xss = "<script>alert(1)</script>"
    st, hdrs, _ = a.post("/api/article/create", {"title": xss, "content": "xss " + stamp})
    check("带 <> 的标题能发出去（不是静默丢弃）", st == 302, "got %s" % st)
    xid = location_id(hdrs, "id")
    if xid:
        st, _, body = a.get("/api/article/detail?id=%d" % xid)
        check("详情页没有未转义的 <script>alert(1)", xss not in body, "原始载荷出现在响应里")
        check("详情页出现了转义后的实体", "&lt;script&gt;" in body, "没看到 &lt;script&gt;")

    inj = "1' OR '1'='1"
    st, hdrs, _ = a.post("/api/article/create", {"title": inj, "content": "inj " + stamp})
    check("注入载荷被当作普通文本写入（302 而不是 500）", st == 302, "got %s" % st)
    iid = location_id(hdrs, "id")
    if iid:
        st, _, body = a.get("/api/article/detail?id=%d" % iid)
        # 单引号会被转义成 &#39;（见 html_util.cpp），所以"原样出现"必然失败；
        # 要找的是它的实体形态 —— 这同时也是"输入确实落库了、没被静默丢弃"的证据。
        escaped = inj.replace("'", "&#39;")
        check("注入载荷以转义后的实体形态完整落库并显示", escaped in body,
              "没找到 %s" % escaped)
        check("注入载荷没有把后面的 article 表带走（详情接口仍返回 200）", st == 200,
              "got %s" % st)

    # ---------- 10. 负向：超长输入 ----------
    st, _, _ = a.post("/api/article/create",
                      {"title": "A" * 300, "content": "boundary " + stamp})
    check("标题超长返回 400 而不是崩溃", st == 400, "got %s" % st)

    # ---------- 11. 登出 ----------
    st, _, _ = a.post("/api/logout", {})
    check("登出返回 200", st == 200, "got %s" % st)
    st, _, body = a.get("/api/whoami")
    check("登出后旧 cookie 不再有效（服务端会话已销毁，不是只清了浏览器）",
          "not logged in" in body, body[:80])

    # ---------- 12. 重新登录（走口令校验这条路，注册时的自动会话不算） ----------
    c = Client()
    st, hdrs, body = c.post("/api/login", {"user": alice, "password": pw})
    check("口令正确时登录返回 200", st == 200, "got %s" % st)
    check("登录下发新会话", c.cookie is not None, "没有 Set-Cookie")
    st, _, body = c.get("/api/whoami")
    m = re.search(r"user_id=(\d+)", body)
    check("重新登录拿到的还是同一个 user_id",
          m is not None and int(m.group(1)) == alice_id,
          "期望 %d，得到 %s" % (alice_id, body[:60]))

    # 错误口令要用一个干净客户端测：c 身上已经挂着 alice 的有效会话，
    # 拿它去试相当于"已登录的人又输错一次密码"，验不出"未登录者登不进去"。
    bad = Client()
    before = bad.cookie
    st, _, _ = bad.post("/api/login", {"user": alice, "password": pw + "wrong"})
    check("口令错误时登录被拒（不返回 302/不建会话）", st in (200, 401),
          "got %s" % st)
    check("口令错误不发新会话", bad.cookie == before,
          "拿到了 %s" % bad.cookie)
    st, _, body = bad.get("/api/whoami")
    check("口令错误后仍是未登录状态", "not logged in" in body, body[:80])

    # 不存在的用户名不能与"口令错"区分出不同的时序（避免用户名枚举）
    st2, _, _ = Client().post("/api/login", {"user": "no_such_" + stamp, "password": pw})
    check("不存在的用户名同样登录失败", st2 in (200, 401), "got %s" % st2)

    # ---------- 13. 服务仍存活 ----------
    st, _, _ = Client().get("/judge.html")
    check("全部用例跑完服务仍存活", st == 200, "got %s" % st)

    # ---------- 汇总 ----------
    total = len(passed) + len(failed)
    print("=" * 62)
    print("冒烟用例：%d 项，通过 %d，失败 %d" % (total, len(passed), len(failed)))
    if failed:
        print("-" * 62)
        for name, detail in failed:
            print("  FAIL  %s   (%s)" % (name, detail))
    print("=" * 62)
    print("本轮创建的测试账号：%s / %s" % (alice, bob))
    # 五条外键的 ON DELETE 都是 NO ACTION（不是 CASCADE），所以必须按依赖顺序删，
    # 直接删 user 会被外键挡下来。顺序：comment → article → follow → user。
    print("清理（按外键依赖顺序）：")
    sel = "SELECT user_id FROM user WHERE username LIKE 'smoke\\_%'"
    print("  DELETE FROM comment WHERE user_id IN (%s);" % sel)
    print("  DELETE FROM article WHERE user_id IN (%s);" % sel)
    print("  DELETE FROM follow  WHERE follower_id IN (%s) OR followee_id IN (%s);"
          % (sel, sel))
    print("  DELETE FROM user    WHERE username LIKE 'smoke\\_%';")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
