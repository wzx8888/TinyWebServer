# 部署：nginx 反向代理终止 TLS

服务本身只说 HTTP，TLS 在前面的 nginx 上终止。这份目录里的东西都是自包含的，
**不需要 sudo，也不碰 `/etc/nginx`**，用普通用户在仓库里就能跑起来验证。

## 为什么是代理而不是把 TLS 做进 C++ 服务

1. 服务里每一个字节的收发只经过四个 socket 调用点（LT/ET 两处 `recv`、
   `close_conn` 里排空输入的 `recv`、`write` 里的 `writev`）。
   要支持 TLS 就得把这四个都换成 `SSL_read`/`SSL_write`，再加上非阻塞握手状态机、
   `SSL_ERROR_WANT_READ/WANT_WRITE` 的重试语义，以及 「`writev` 在 TLS 里没有对应物」
   这个必须手写分段发送的问题。这些改动全部落在**每个请求都要走的热路径**上，
   而它能带来的收益代理已经全给了。
2. 证书轮换、TLS 版本与密码套件策略、HSTS、OCSP stapling、HTTP/2 —— 这些都会随
   时间变化。放在代理里改一行配置，放在 C++ 里就是一次重新编译加发布。
3. 代理顺手还能给限速、访问日志、真实客户端 IP 还原（`X-Forwarded-For`）。

## 怎么跑

```bash
cd /home/wuzhaoxin/TinyWebServer

# 1) 生成自签证书（只需一次，私钥落在 deploy/tls/，已在 .gitignore 里）
./deploy/gen-cert.sh

# 2) 起后端（默认就只监听 127.0.0.1，不用加参数）
./server &

# 3) 起代理
mkdir -p deploy/logs deploy/temp
nginx -c "$PWD/deploy/nginx.conf" -p "$PWD/deploy/"

# 4) 验证
curl -k https://127.0.0.1:8443/judge.html
openssl s_client -connect 127.0.0.1:8443 -brief </dev/null | head -3
#   Protocol version: TLSv1.3
#   Ciphersuite: TLS_AES_256_GCM_SHA384

# 5) 关掉代理
nginx -c "$PWD/deploy/nginx.conf" -p "$PWD/deploy/" -s quit
```

## 最关键的一条：`Host` 必须用 `$http_host`

配置里有一行是这样写的：

```nginx
proxy_set_header Host $http_host;   # 不能改成 $host
```

这不是风格问题。后端的 CSRF 防护（`http_conn::origin_ok`）拿 `Origin` 和 `Host`
比对，比对时**忽略 scheme、但保留端口**：

| | 浏览器发出的 | 后端解析出的 authority |
|---|---|---|
| `Origin` | `https://127.0.0.1:8443` | `127.0.0.1:8443` |
| `Host`（用 `$http_host`） | `127.0.0.1:8443` | `127.0.0.1:8443` → **相等，放行** |
| `Host`（用 `$host`） | `127.0.0.1` | `127.0.0.1` → **不等，403** |

`$host` 会丢掉端口，于是每一个写请求都会被自己人拒掉。
这个失效方式**只在写请求上出现，读请求完全正常**，看上去非常像"CSRF 防护太严了"，
排查方向很容易被带偏。

这条已经实测过，不是推演：把同一份配置的 `$http_host` 换成 `$host`，
`POST /api/article/create`（带匹配的 `Origin`）从 302 变成 **403**，
而同一端口上的 `GET /judge.html` 仍然是 200。

## 为什么后端必须只监听 127.0.0.1

`config.cpp` 里默认 `LISTEN_ADDR = "127.0.0.1"`（可用 `-b` 改）。
这是整套部署方式成立的前提，不是保守：

- 如果绑到 `0.0.0.0`，同一网络里任何人都可以 `http://内网IP:9006` 直连后端，
  绕过 TLS、绕过代理上的所有策略；
- 更糟的是这条路**不需要攻击者做任何事就能拿到已登录用户的响应**——
  Cookie 是 `SameSite=Lax; HttpOnly`，但不带 `Secure`，
  浏览器在明文 `http://` 请求上照样会把它带上。

所以 `-b 0.0.0.0` 应当只在做本地压测、且明确知道当前网段可信时才用。

## 上生产要改的三处

1. `listen 443 ssl;` + `user www-data;`，日志改到 `/var/log/nginx/`。
2. 换成 CA 签发的证书（Let's Encrypt 等），并加 HSTS —— 但要先确认全站都能走 HTTPS，
   HSTS 加错会让用户在一段时间内完全打不开站点。
3. 保持后端只监听回环。

这些的完整写法写在 `nginx.conf` 文末的注释里。
