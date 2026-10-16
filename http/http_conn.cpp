#include "http_conn.h"

#include <mysql/mysql.h>
#include <fstream>

#include "../db/sql_util.h"
#include "../session/session_manager.h"
#include "form_parser.h"
#include "html_util.h"
#include "../auth/password.h"

//定义http响应的一些状态信息
const char *ok_200_title = "OK";
const char *error_400_title = "Bad Request";
const char *error_400_form = "Your request has bad syntax or is inherently impossible to staisfy.\n";
const char *error_403_title = "Forbidden";
// 403 现在有两个来源：路径穿越，和"写请求的 Origin 不是本站"。
// 原文案只提"取文件"，对着一个被拒的 POST 说这句话会把人带到错误的方向。
const char *error_403_form = "You do not have permission to access this resource.\n";
const char *error_404_title = "Not Found";
const char *error_404_form = "The requested file was not found on this server.\n";
const char *error_500_title = "Internal Error";
const char *error_500_form = "There was an unusual problem serving the request file.\n";
const char *error_405_title = "Method Not Allowed";
const char *error_405_form = "This endpoint does not accept that HTTP method. Use POST.\n";
const char *error_413_title = "Content Too Large";
const char *error_413_form = "The request body is larger than this server accepts (48 KB).\n";
const char *error_501_title = "Not Implemented";
const char *error_501_form = "This server only implements GET and POST.\n";

const char *SESSION_COOKIE_NAME = "SESSIONID";

namespace
{
// 从结果集里安全取一个字段：SQL NULL 当成空串，避免解引用空指针。
// 放在文件靠前的位置，登录/注册和后面的论坛 handler 都要用。
string col(MYSQL_ROW row, unsigned int i)
{
    return (row[i] != NULL) ? string(row[i]) : string();
}

// 把 SQL 里所有单引号字面量抹成 '?'，只留下语句结构（表名、列名、条件形状）。
// 为什么必须这么做：db_exec 出错时原本记的是整条语句，而本项目所有语句都是
// 拼出来的，字面量里既有用户正文，也有 passwd_hash（bcrypt 散列里就含 salt）。
// 一旦某条带凭据的语句执行失败，散列就会被抄进日志文件 ——
// 日志是长期留存、通常权限更宽的文件，拿到散列就等于拿到一份离线爆破的原料。
string redact_sql(const string &sql)
{
    string out;
    out.reserve(64);

    bool in_quote = false;
    for (size_t i = 0; i < sql.size(); ++i)
    {
        char c = sql[i];
        if (in_quote)
        {
            // 单引号内的 \' 不是结束符。mysql_real_escape_string 产生的正是这种形式，
            // 不跳过反斜杠后面的字符，就会把 '\'' 错当成"字面量结束 + 新字面量开始"。
            if (c == '\\' && i + 1 < sql.size())
            {
                ++i;
                continue;
            }
            if (c == '\'')
            {
                in_quote = false;
                out += "'?'";
            }
            continue;
        }
        if (c == '\'')
        {
            in_quote = true;
            continue;
        }
        out.push_back(c);
    }

    // 引号没闭合就走到末尾：调用方拼出了坏语句（例如漏了结尾的引号）。
    // 内容已经全部丢弃，但要在日志里留下"这里本来有个字面量"的痕迹，
    // 否则打出来的是一条看着像被截断的语句，读日志的人会往错的方向查。
    if (in_quote)
        out += "'?'";

    // 截断放在最后统一做，保证输出长度上限是硬的：
    // 循环里遇到上限就 break 的话，上面那句补的标记会突破上限。
    // 注意 out 里【不含】任何字面量内容，所以它的长度取决于语句结构，
    // 不会被用户正文撑大，这里不需要担心多走几步的代价。
    if (out.size() > 200)
    {
        out.resize(200);
        out += "...";
    }

    return out;
}

// 按扩展名给静态文件定 Content-Type。
// 原项目只在动态响应里写死了 text/html，静态文件一个 Content-Type 都不发：
// 浏览器靠内容嗅探多数时候还能正常显示，但代理缓存、下载行为、
// X-Content-Type-Options: nosniff 这些场景都依赖服务端给对类型。
//
// 不认识的扩展名给 application/octet-stream，而不是让浏览器去猜：
// 猜错方向的代价是把一个数据文件当成 HTML 渲染（嗅探型 XSS 的经典形状），
// 顶多多一次下载提示，这个方向的错误便宜得多。
const char *content_type_for(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (dot == NULL)
        return "application/octet-stream";

    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0)
        return "text/html; charset=utf-8";
    if (strcasecmp(dot, ".css") == 0)
        return "text/css; charset=utf-8";
    if (strcasecmp(dot, ".js") == 0)
        return "application/javascript; charset=utf-8";
    if (strcasecmp(dot, ".json") == 0)
        return "application/json; charset=utf-8";
    if (strcasecmp(dot, ".txt") == 0 || strcasecmp(dot, ".md") == 0)
        return "text/plain; charset=utf-8";
    if (strcasecmp(dot, ".png") == 0)
        return "image/png";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0)
        return "image/jpeg";
    if (strcasecmp(dot, ".gif") == 0)
        return "image/gif";
    if (strcasecmp(dot, ".svg") == 0)
        return "image/svg+xml";
    if (strcasecmp(dot, ".ico") == 0)
        return "image/x-icon";
    if (strcasecmp(dot, ".mp4") == 0)
        return "video/mp4";
    if (strcasecmp(dot, ".webm") == 0)
        return "video/webm";
    if (strcasecmp(dot, ".woff2") == 0)
        return "font/woff2";

    return "application/octet-stream";
}

// 请求行按"留结构不留值"处理，和 redact_sql 是同一个思路：
//   GET /api/login?user=alice&password=hunter2 HTTP/1.1
//   -> GET /api/login?user=?&password=? HTTP/1.1
//
// 为什么必须做：请求行是原样进日志的，而带凭据的请求完全可以走查询串
// （GET /2CGISQL.cgi?user=a&password=x）。这类请求会被 post_only 拦成 405，
// 但日志是在方法检查【之前】写的 —— 请求被拒了，口令已经躺在日志文件里。
//
// 为什么不用"敏感参数名单"（password/token/sessionid…）：榜单永远列不全，
// 而且新加的参数会默认落入"不在名单里 = 记下来"，默认方向就是错的。
// 值一律记成 ?，需要具体值时由对应的 handler 自己记（它才知道哪个值无害）。
string redact_request_line(const string &line)
{
    // 先把版本号摘出来：路径里不会出现 " HTTP/"。
    // 用它兜住末尾，避免把 "HTTP/1.1" 当成查询串的一部分。
    size_t ver = line.find(" HTTP/");
    string target = (ver == string::npos) ? line : line.substr(0, ver);
    string tail = (ver == string::npos) ? string() : line.substr(ver);

    string out;
    size_t q = target.find('?');
    if (q == string::npos)
    {
        // 没有查询串：路径本身不含凭据，原样保留（这是排查 405/404 的主要线索）
        out = target;
    }
    else
    {
        out = target.substr(0, q + 1);
        size_t i = q + 1;
        while (i < target.size())
        {
            size_t amp = target.find('&', i);
            if (amp == string::npos)
                amp = target.size();

            string seg = target.substr(i, amp - i);
            size_t eq = seg.find('=');
            if (eq == string::npos)
                out += seg;                          // 只有 key 的段，本来就没有值
            else
                out += seg.substr(0, eq + 1) + "?";  // key=? ，值丢掉

            if (amp < target.size())
                out += "&";
            i = amp + 1;
        }
    }

    out += tail;

    // 上限兜底：参数个数不受限，不能让一条日志被查询串撑长
    if (out.size() > 300)
    {
        out.resize(300);
        out += "...";
    }
    return out;
}

// "host[:port]" 归一化成可比对的形式：去首尾空白、转小写、去掉 scheme 的默认端口。
// 浏览器在 Origin 里会省略 http:80 / https:443，而 Host 头不一定省，
// 两边都归一化再比，才能让 "http://a.com" 和 "a.com:80" 判为同一个站。
//
// 首尾空白都要去：解析层已经用 strspn 吃掉了前导空白，尾随空白则可能残留
// （"Host: a.com \r\n" 的取值是 "a.com "，parse_line 切掉的是 \r\n）。
// 这里的调用方只有 origin_ok()，而它是个拒绝逻辑 —— 少去一处空白，
// 结果就是把合法请求判成跨站写请求，误伤方向比漏放方向更疼。
// 去掉空白不会让两个不同的 authority 变得相等，所以不会放松判断。
string normalize_authority(string a)
{
    size_t b = 0;
    while (b < a.size() && (a[b] == ' ' || a[b] == '\t'))
        ++b;
    if (b > 0)
        a.erase(0, b);

    while (!a.empty() && (a[a.size() - 1] == ' ' || a[a.size() - 1] == '\t'))
        a.erase(a.size() - 1);

    // 主机名大小写不敏感
    for (size_t i = 0; i < a.size(); ++i)
    {
        if (a[i] >= 'A' && a[i] <= 'Z')
            a[i] = (char)(a[i] - 'A' + 'a');
    }

    // 长度判断保证去掉端口后不会剩下空串
    if (a.size() > 4 && a.compare(a.size() - 3, 3, ":80") == 0)
        a.erase(a.size() - 3);
    else if (a.size() > 5 && a.compare(a.size() - 4, 4, ":443") == 0)
        a.erase(a.size() - 4);

    return a;
}
} // namespace

//对文件描述符设置非阻塞
int setnonblocking(int fd)
{
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

//将内核事件表注册读事件，ET模式，选择开启EPOLLONESHOT
void addfd(int epollfd, int fd, bool one_shot, int TRIGMode)
{
    epoll_event event;
    event.data.fd = fd;

    if (1 == TRIGMode)
        event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    else
        event.events = EPOLLIN | EPOLLRDHUP;

    if (one_shot)
        event.events |= EPOLLONESHOT;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
    setnonblocking(fd);
}

//从内核时间表删除描述符
void removefd(int epollfd, int fd)
{
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, 0);
    close(fd);
}

//将事件重置为EPOLLONESHOT
void modfd(int epollfd, int fd, int ev, int TRIGMode)
{
    epoll_event event;
    event.data.fd = fd;

    if (1 == TRIGMode)
        event.events = ev | EPOLLET | EPOLLONESHOT | EPOLLRDHUP;
    else
        event.events = ev | EPOLLONESHOT | EPOLLRDHUP;

    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

int http_conn::m_user_count = 0;
int http_conn::m_epollfd = -1;

//关闭连接，关闭一个连接，客户总量减一
void http_conn::close_conn(bool real_close)
{
    if (real_close && (m_sockfd != -1))
    {
        // 关闭前先把对端已经发到、但我们还没读走的数据读干净。
        //
        // 为什么必须做：带着未读数据的 socket 调 close()，内核会发 RST，
        // 而 RST 到对端时会把对端【还没读走】的接收缓冲一起丢掉 ——
        // 也就是我们刚发出去的那个响应。典型场景是 "Transfer-Encoding: chunked"
        // 和超限正文：正文还在内核缓冲里，我们直接回 400/413 然后关连接，
        // 客户端只看到 "Connection reset by peer"，根本看不到 413。
        // 实测：本地强制 shutdown(SHUT_WR) 的客户端会 100% 收不到响应，
        // 不 shutdown 的客户端则看运气（取决于 RST 和它 read 谁先到）。
        // 表现成"服务好像崩了"，而真正的原因是这条连接关得不够体面。
        //
        // 只排空【已经到达】的数据：非阻塞读，读到 EAGAIN/EOF 就停。
        // 上限 64KB 是必须的：不加限制的话，对端只要持续灌数据就能让这个循环
        // 一直转下去（每轮都能读到一点），关闭被无限推迟 = 一个廉价的连接占用。
        // 64KB 足够覆盖"错误响应 + 未读正文"的常见情形，超出的部分宁可让它 RST。
        // 正常请求这条路径上接收缓冲本来就是空的，多一次 recv 而已。
        char drain[4096];
        int drained = 0;
        while (drained < 65536)
        {
            int n = recv(m_sockfd, drain, sizeof(drain), MSG_DONTWAIT);
            if (n <= 0)
                break;
            drained += n;
        }

        printf("close %d\n", m_sockfd);
        removefd(m_epollfd, m_sockfd);
        m_sockfd = -1;
        m_user_count--;
    }
}

//初始化连接,外部调用初始化套接字地址
void http_conn::init(int sockfd, const sockaddr_in &addr, char *root, int TRIGMode,
                     int close_log, string user, string passwd, string sqlname)
{
    m_sockfd = sockfd;
    m_address = addr;

    addfd(m_epollfd, sockfd, true, m_TRIGMode);
    m_user_count++;

    //当浏览器出现连接重置时，可能是网站根目录出错或http响应格式出错或者访问的文件中内容完全为空
    doc_root = root;
    m_TRIGMode = TRIGMode;
    m_close_log = close_log;

    strcpy(sql_user, user.c_str());
    strcpy(sql_passwd, passwd.c_str());
    strcpy(sql_name, sqlname.c_str());

    init();
}

//初始化新接受的连接
//check_state默认为分析请求行状态
void http_conn::init()
{
    mysql = NULL;
    bytes_to_send = 0;
    bytes_have_send = 0;
    m_check_state = CHECK_STATE_REQUESTLINE;
    m_linger = false;
    m_method = GET;
    m_url.clear();
    m_version.clear();
    m_content_length = 0;
    m_host.clear();
    m_start_line = 0;
    m_checked_idx = 0;
    m_read_idx = 0;
    m_write_idx = 0;
    cgi = 0;
    m_state = 0;
    timer_flag = 0;
    improv = 0;

    // 上次响应如果没发完就断了连接，mmap 会留在成员里，这里一并清掉。
    // 正常路径上 write() 已经调用过 unmap()，所以不会重复解映射。
    m_file_address = 0;
    m_body_ptr = 0;
    m_iv_count = 0;

    m_session_id.clear();
    m_user_id = -1;
    m_origin.clear();
    m_extra_headers.clear();
    m_dyn_body.clear();
    m_post.clear();
    m_path.clear();
    // 状态行必须复位：keep-alive 下同一个 http_conn 会服务多个请求，
    // 上一次若是 302/401，不复位就会串到下一个请求上
    m_resp_status = 200;
    m_resp_status_title = ok_200_title;

    // 上一次请求可能把读缓冲撑大了，这里只复位长度、保留容量，
    // 避免 keep-alive 下反复申请释放内存。
    if (m_read_buf.size() != (size_t)READ_BUFFER_SIZE)
        m_read_buf.assign(READ_BUFFER_SIZE, '\0');
    else
        memset(m_read_buf.data(), '\0', READ_BUFFER_SIZE);

    memset(m_write_buf, '\0', WRITE_BUFFER_SIZE);
    memset(m_real_file, '\0', FILENAME_LEN);
}

//从状态机，用于分析出一行内容
//返回值为行的读取状态，有LINE_OK,LINE_BAD,LINE_OPEN
http_conn::LINE_STATUS http_conn::parse_line()
{
    char temp;
    for (; m_checked_idx < m_read_idx; ++m_checked_idx)
    {
        temp = m_read_buf[m_checked_idx];
        if (temp == '\r')
        {
            if ((m_checked_idx + 1) == m_read_idx)
                return LINE_OPEN;
            else if (m_read_buf[m_checked_idx + 1] == '\n')
            {
                m_read_buf[m_checked_idx++] = '\0';
                m_read_buf[m_checked_idx++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }
        else if (temp == '\n')
        {
            if (m_checked_idx > 1 && m_read_buf[m_checked_idx - 1] == '\r')
            {
                m_read_buf[m_checked_idx - 1] = '\0';
                m_read_buf[m_checked_idx++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }
    }
    return LINE_OPEN;
}

//读缓冲不够时翻倍扩容；已经到上限说明请求过大，放弃这个连接
//注意：扩容【可能重新分配内存】。因此 http_conn 里不允许保存任何指向
//m_read_buf 的裸指针成员（解析结果一律拷贝成 std::string），
//否则扩容之后就是 use-after-free。缓冲内部的临时指针（get_line()/text）
//只在同一次 process_read 内使用，期间不会扩容，是安全的。
bool http_conn::grow_read_buf()
{
    if (m_read_buf.size() >= (size_t)MAX_READ_BUFFER)
    {
        LOG_ERROR("request too large, close conn(fd=%d)", m_sockfd);
        return false;
    }

    size_t new_size = m_read_buf.size() * 2;
    if (new_size > (size_t)MAX_READ_BUFFER)
        new_size = MAX_READ_BUFFER;

    m_read_buf.resize(new_size, '\0');
    return true;
}

//循环读取客户数据，直到无数据可读或对方关闭连接
//非阻塞ET工作模式下，需要一次性将数据读完
bool http_conn::read_once()
{
    //缓冲满了先尝试扩容，扩不动就说明请求超过 MAX_READ_BUFFER
    if (m_read_idx >= (long)m_read_buf.size() && !grow_read_buf())
        return false;

    int bytes_read = 0;

    //LT读取数据
    if (0 == m_TRIGMode)
    {
        bytes_read = recv(m_sockfd, m_read_buf.data() + m_read_idx,
                          m_read_buf.size() - m_read_idx, 0);
        if (bytes_read <= 0)
        {
            return false;
        }
        m_read_idx += bytes_read;
        return true;
    }
    //ET读数据
    else
    {
        while (true)
        {
            if (m_read_idx >= (long)m_read_buf.size() && !grow_read_buf())
                return false;

            bytes_read = recv(m_sockfd, m_read_buf.data() + m_read_idx,
                              m_read_buf.size() - m_read_idx, 0);
            if (bytes_read == -1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                return false;
            }
            else if (bytes_read == 0)
            {
                return false;
            }
            m_read_idx += bytes_read;
        }
        return true;
    }
}

//解析http请求行，获得请求方法，目标url及http版本号
//
// 【为什么解析结果要拷贝，而不是像原来那样直接存指针】
// 原来 m_url / m_version / m_host 都直接指向 m_read_buf 里的位置。
// 而 m_read_buf 在 0.7-B 之后是会按需扩容的 std::vector：
// grow_read_buf() 里的 resize() 一旦触发重新分配，这些指针立刻全部悬空。
// 要命的是使用顺序 —— do_request() 是在"请求正文收全"之后才拿 m_url
// 去查路由的，而正文恰恰就是逼着缓冲扩容的那个东西：
//   正文稍大 → 需要第二次 recv → 扩容 → m_url 悬空 → 路由查不到 →
//   请求落到静态文件逻辑 → strrchr(垃圾指针, '/') 返回 NULL → 静默 400。
// 实测：正文 1900 / 5000 字节的 POST 稳定返回 400（正文在 2KB 上下的那几档），
// 而日志里没有任何异常，只有一行看不见问题的 "POST /api/login HTTP/1.1"。
// 这不是"状态码不对"这么轻的问题：读的是已经 free 掉的内存（use-after-free），
// 换个堆布局就可能是崩溃或更离谱的行为。
// 现在整行解析完就拷贝进 std::string，之后再怎么扩容都与它无关。
http_conn::HTTP_CODE http_conn::parse_request_line(char *text)
{
    // text 形如 "POST /api/login HTTP/1.1"，parse_line() 已把两处空白改成 '\0'
    char *method = text;

    char *url = strpbrk(method, " \t");
    if (!url)
        return BAD_REQUEST;
    *url++ = '\0';
    url += strspn(url, " \t");

    char *version = strpbrk(url, " \t");
    if (!version)
        return BAD_REQUEST;
    *version++ = '\0';
    version += strspn(version, " \t");

    // 方法名要区分两种"不认识"：
    //   1. 合法的 HTTP 方法但我们没实现（PUT/DELETE/OPTIONS/...）
    //      -> 501 Not Implemented，并在 Allow 里说明该用什么。
    //      RFC 7231 4.3：服务端收到自己不支持的方法时就应该回 501。
    //   2. 根本不是方法名的东西（乱码、空、含非法字符）-> 400 Bad Request。
    // 以前一律 400，结果是 "HEAD /welcome.html HTTP/1.1" 这种完全合法的请求
    // 被回了一句 "Your request has bad syntax" —— 状态码在撒谎，
    // 排查的人会去查客户端拼错了什么，而真正的原因是服务端没实现 HEAD。
    if (strcasecmp(method, "GET") == 0)
        m_method = GET;
    else if (strcasecmp(method, "POST") == 0)
    {
        m_method = POST;
        cgi = 1;
    }
    else if (strcasecmp(method, "HEAD") == 0)
        m_method = HEAD;
    else if (strcasecmp(method, "PUT") == 0)
        m_method = PUT;
    else if (strcasecmp(method, "DELETE") == 0)
        m_method = DELETE;
    else if (strcasecmp(method, "OPTIONS") == 0)
        m_method = OPTIONS;
    else if (strcasecmp(method, "TRACE") == 0)
        m_method = TRACE;
    else if (strcasecmp(method, "CONNECT") == 0)
        m_method = CONNECT;
    else
        return BAD_REQUEST;

    m_version = version;
    if (m_version != "HTTP/1.1")
        return BAD_REQUEST;

    // 绝对 URI 形式：http://host/path 只保留 path 部分
    string u;
    if (strncasecmp(url, "http://", 7) == 0)
    {
        char *slash = strchr(url + 7, '/');
        if (slash == NULL)
            return BAD_REQUEST;
        u = slash;
    }
    else if (strncasecmp(url, "https://", 8) == 0)
    {
        char *slash = strchr(url + 8, '/');
        if (slash == NULL)
            return BAD_REQUEST;
        u = slash;
    }
    else
    {
        u = url;
    }

    if (u.empty() || u[0] != '/')
        return BAD_REQUEST;
    //当url为/时，显示判断界面
    if (u.size() == 1)
        u += "judge.html";

    m_url = u;
    m_check_state = CHECK_STATE_HEADER;
    return NO_REQUEST;
}

//解析http请求的一个头部信息
http_conn::HTTP_CODE http_conn::parse_headers(char *text)
{
    if (text[0] == '\0')
    {
        if (m_content_length != 0)
        {
            m_check_state = CHECK_STATE_CONTENT;
            return NO_REQUEST;
        }
        return GET_REQUEST;
    }
    else if (strncasecmp(text, "Connection:", 11) == 0)
    {
        text += 11;
        text += strspn(text, " \t");
        if (strcasecmp(text, "keep-alive") == 0)
        {
            m_linger = true;
        }
    }
    else if (strncasecmp(text, "Content-length:", 15) == 0)
    {
        text += 15;
        text += strspn(text, " \t");

        // 严格按纯数字解析，两端允许空白。
        // 不能直接用 atol/strtoll，它们会把这些全收下：
        //   "abc"    -> 0    把非法头当成"没有正文"
        //   "3 3"    -> 3    中间的垃圾被忽略
        //   "+5"     -> 5    带符号，RFC 不允许
        //   超长数字  -> 溢出
        //   "-1"     -> -1   最严重：负数流到 parse_content，
        //                     (size_t)(-1) 变成 SIZE_MAX，parse_form 拿着这个长度
        //                     一路越界读。实测一个 "Content-Length: -1" 的请求
        //                     就能让整个 server 进程段错误退出（单进程，全体用户一起断）。
        string cl_text(text);
        size_t cb = cl_text.find_first_not_of(" \t");
        size_t ce = cl_text.find_last_not_of(" \t");
        string digits;
        if (cb != string::npos && ce != string::npos)
            digits = cl_text.substr(cb, ce - cb + 1);

        if (digits.empty())
            return BAD_REQUEST;

        for (size_t i = 0; i < digits.size(); ++i)
        {
            if (digits[i] < '0' || digits[i] > '9')
            {
                LOG_WARN("bad Content-Length header, rejected");
                return BAD_REQUEST;
            }
        }

        // 位数过多时 strtoll 会置 errno=ERANGE，to_ll 因此返回 def(-1)
        long long cl = to_ll(digits, -1);
        if (cl < 0)
            return BAD_REQUEST;

        if (cl > MAX_CONTENT_LENGTH)
        {
            // 超过上限要给明确的 413，而不是"连接被悄悄断开"。
            // 设置 m_linger = false：我们不会去读这个正文，
            // 连接上还残留着未读的数据，不能拿它当下一个请求解析。
            LOG_WARN("Content-Length %lld exceeds limit %d", cl, MAX_CONTENT_LENGTH);
            m_linger = false;
            return PAYLOAD_TOO_LARGE;
        }

        m_content_length = (long)cl;
    }
    else if (strncasecmp(text, "Host:", 5) == 0)
    {
        text += 5;
        text += strspn(text, " \t");
        // 拷贝而不是记指针，理由同 parse_request_line
        m_host = text;
    }
    else if (strncasecmp(text, "Cookie:", 7) == 0)
    {
        text += 7;
        text += strspn(text, " \t");
        m_session_id = cookie_value(text, SESSION_COOKIE_NAME);
    }
    else if (strncasecmp(text, "Origin:", 7) == 0)
    {
        text += 7;
        text += strspn(text, " \t");
        m_origin = text;
    }
    else if (strncasecmp(text, "Transfer-Encoding:", 18) == 0)
    {
        // 本服务器不解析 chunked 正文，而"看见却不管"比"明确拒绝"危险得多：
        // 忽略这个头会让 m_content_length 保持 0，请求被当成"已经读完"，
        // 留在读缓冲里的块数据会被当成同一个连接上的下一个请求 —— 这正是
        // 请求走私的经典形状（攻击者让一个请求的尾巴变成另一个请求的头）。
        // 这里没有前端代理，危害只限于搞乱自己的解析，但没有理由留着。
        LOG_WARN("Transfer-Encoding not supported, rejected");
        // 连接上还有没读完的数据，不能复用
        m_linger = false;
        return BAD_REQUEST;
    }
    else
    {
        LOG_INFO("oop!unknow header: %s", text);
    }
    return NO_REQUEST;
}

//判断http请求是否被完整读入
http_conn::HTTP_CODE http_conn::parse_content(char *text)
{
    // 兜底：正常路径上 parse_headers 已经把负数挡在外面了，
    // 但这里是越界读取的最后一道门，必须自己再确认一次。
    // 少了这个判断，"m_content_length 为负"会变成 (size_t) 巨值传给 parse_form。
    if (m_content_length < 0 || m_content_length > MAX_CONTENT_LENGTH)
    {
        LOG_ERROR("parse_content: content_length out of range: %ld", m_content_length);
        return BAD_REQUEST;
    }

    if (m_read_idx >= (m_content_length + m_checked_idx))
    {
        // 不在这里写 text[m_content_length] = '\0' 了。
        // parse_form 收的是 (指针, 长度)，本来就不需要结尾符；
        // 而那个写入是把 NUL 放在"已收到数据"的后一个字节上，
        // 一旦边界算错就是缓冲越界写。删掉它，这类风险直接消失。
        m_post = parse_form(text, (size_t)m_content_length);
        return GET_REQUEST;
    }
    return NO_REQUEST;
}

http_conn::HTTP_CODE http_conn::process_read()
{
    HTTP_CODE ret = NO_REQUEST;

    while (true)
    {
        // ============================================================
        // 正文必须和"按行解析"彻底分开，不能共用同一个循环。
        // ============================================================
        // 原来的写法是：正文没读全时把 line_status 置成 LINE_OPEN 继续
        // 让循环条件再调一次 parse_line()。但 parse_line() 扫描到
        // "已收到数据的末尾"才返回 LINE_OPEN —— 这一扫会把 m_checked_idx
        // 一路推到 m_read_idx。而正文收齐的判断正是
        //     m_read_idx >= m_content_length + m_checked_idx
        // 基准 m_checked_idx 被自己推到了末尾，这个条件就再也无法成立：
        // 请求会一直"没读全"，直到客户端或定时器把连接掐掉。
        // 实测：正文 3000 字节（超过初始 2048 缓冲，需要分两次 recv）时
        // 请求永远挂住不响应 —— 也就是说 0.7-B 把缓冲改成按需增长之后，
        // 大于约 1.9KB 的 POST 正文其实一直是坏的，只是没人试过。
        // 现在这个分支直接返回，正文状态下 m_checked_idx 不再被挪动：
        // 它始终指向"正文起点"，随时可以拿它算"还差多少字节"。
        if (m_check_state == CHECK_STATE_CONTENT)
        {
            // 正文不落盘（里面有明文密码），只记长度
            LOG_INFO("<request body: %ld bytes, not logged>", m_content_length);

            ret = parse_content(m_read_buf.data() + m_checked_idx);
            if (ret == GET_REQUEST)
                return do_request();

            // 没收全：已收到的字节留在缓冲里，等下一个读事件接着收
            return NO_REQUEST;
        }

        LINE_STATUS line_status = parse_line();
        if (line_status == LINE_OPEN)
            return NO_REQUEST;
        if (line_status == LINE_BAD)
            return BAD_REQUEST;

        char *text = get_line();
        m_start_line = m_checked_idx;

        // 日志不能落盘任何凭证：
        //   - Cookie 头里带 session_id，拿到就能冒充登录
        //   - 请求正文里带明文密码（上面那个分支已经处理）
        //   - 请求行的查询串里可能直接带口令，见 redact_request_line
        // 花括号不能省：LOG_* 宏展开后是 if (0 == m_close_log) {...}，
        // 不加大括号的话，下面的 else 会被宏内部那个 if 抢走（编译期报错）。
        if (m_check_state == CHECK_STATE_REQUESTLINE)
        {
            LOG_INFO("%s", redact_request_line(text).c_str());
        }
        else if (strncasecmp(text, "Cookie:", 7) == 0)
        {
            LOG_INFO("Cookie: <redacted>");
        }
        else
        {
            LOG_INFO("%s", text);
        }

        switch (m_check_state)
        {
        case CHECK_STATE_REQUESTLINE:
        {
            ret = parse_request_line(text);
            if (ret == BAD_REQUEST)
                return BAD_REQUEST;
            break;
        }
        case CHECK_STATE_HEADER:
        {
            ret = parse_headers(text);
            // 头解析阶段的两个终态错误要原样上报：
            //   BAD_REQUEST（正文长度非法）和 PAYLOAD_TOO_LARGE（正文超限）。
            // 漏掉任何一个，请求都会继续往下走，最后变成"连接莫名被关闭"。
            if (ret == BAD_REQUEST || ret == PAYLOAD_TOO_LARGE)
                return ret;
            else if (ret == GET_REQUEST)
            {
                return do_request();
            }
            break;
        }
        default:
            return INTERNAL_ERROR;
        }
    }
    return NO_REQUEST;
}

// 取一个表单参数。POST 正文和 URL 查询串都会并进 m_post，这里不用区分方法。
string http_conn::get_param(const char *name) const
{
    map<string, string>::const_iterator it = m_post.find(name);
    if (it == m_post.end())
        return string();
    return it->second;
}

// CSRF 第二道防线：写请求的 Origin 必须指向本站。
// 和 Cookie 上的 SameSite=Lax 是互补关系，两道都留着：
//   - SameSite 是新属性，老浏览器直接忽略；
//   - 登录/注册接口不需要 Cookie 就能生效（登录 CSRF 会把自己的账号
//     塞进受害者的浏览器），Cookie 策略对它们完全无效；
//   - 反过来，SameSite 能挡住浏览器静默发出的跨站请求，
//     而 Origin 判不了"同一站点不同端口"之外的场景。
bool http_conn::origin_ok() const
{
    // 非浏览器客户端不发 Origin，也就不存在"被第三方页面借用手脚"这回事
    if (m_origin.empty())
        return true;

    // 沙箱 iframe / data: 页面发出的是字面量 "null"，那正是最典型的攻击来源
    if (m_origin == "null")
        return false;

    size_t scheme_end = m_origin.find("://");
    if (scheme_end == string::npos)
        return false;

    string authority = m_origin.substr(scheme_end + 3);
    // 去掉可能存在的路径/查询串，只留 host[:port]
    size_t cut = authority.find_first_of("/?#");
    if (cut != string::npos)
        authority.resize(cut);

    // HTTP/1.1 里 Host 是必需头；连它都没有的请求无从比对，
    // 写请求宁可失败也不能放行。
    if (m_host.empty())
        return false;

    return normalize_authority(authority) == normalize_authority(m_host);
}

// 执行一条语句，失败时把 errno/mysql_error 记进日志。
// 用的是成员 mysql —— 线程池在调 process() 之前已经 connectionRAII 取好连接了。
// 这里绝不自己去连接池再取一条：池只有 8 条，一个请求占两条会直接把并发打崩。
bool http_conn::db_exec(const string &sql)
{
    if (mysql == NULL)
    {
        LOG_ERROR("db_exec: no mysql connection");
        return false;
    }
    if (mysql_query(mysql, sql.c_str()))
    {
        // 记 redact_sql() 处理过的版本，不记原文：字面量里可能是凭据材料
        // （见 redact_sql 上的说明）。语句结构足够定位问题。
        LOG_ERROR("query error(%u):%s | sql: %s", mysql_errno(mysql),
                  mysql_error(mysql), redact_sql(sql).c_str());
        return false;
    }
    return true;
}

// 动态响应：body 挂在 m_iv[1] 上，状态行由参数决定。
// 注意 body 里塞进来的用户内容必须已经过 html_escape，本函数不做转义
// （它拿到的是完整的 HTML 文档，再转义一次会把标签也转掉）。
http_conn::HTTP_CODE http_conn::dynamic_html(const string &html, int status, const char *title)
{
    m_dyn_body = html;
    m_resp_status = status;
    m_resp_status_title = (title != NULL) ? title : ok_200_title;
    return DYNAMIC_REQUEST;
}

// 302 跳转。Location 必须加在空行之前，所以走 m_extra_headers。
http_conn::HTTP_CODE http_conn::redirect_to(const string &location)
{
    m_extra_headers += "Location: " + location + "\r\n";

    // 浏览器会自动跟随 Location，这段 body 只是给不用浏览器的场景
    // （curl 不加 -L、脚本、无障碍工具）一个能点/能读的去处。
    string body = "<p>已提交，正在跳转…</p><p><a href=\"" + html_escape(location) +
                  "\">如果没有自动跳转，点这里</a></p>";
    return dynamic_html(html_page("跳转中", html_nav(m_user_id >= 0), body), 302, "Found");
}

// 写接口的未登录门禁。返回 401 而不是静默成功，让客户端能区分
// "没登录"和"登录了但参数不对"。
http_conn::HTTP_CODE http_conn::require_login()
{
    string body = "<div class=\"err\"><p>这个操作需要先登录。</p>"
                  "<p><a href=\"/log.html\">去登录</a> 或 "
                  "<a href=\"/register.html\">注册新账号</a></p></div>";
    return dynamic_html(html_page("需要登录", html_nav(false), body), 401, "Unauthorized");
}

// URL 路径 -> 处理函数 + 方法要求。函数内静态量，C++11 保证初始化是线程安全的。
//
// post_only = true 的是所有会改数据的接口：发帖、评论、关注、登出、登录、注册。
// 它们只接受 POST，别的写法一律 405。
// 读接口（列表/详情/feed/主页/whoami）在这里不限制方法。
// 注意实际能到这张表的只有 GET 和 POST 两种：parse_request_line() 对
// HEAD/PUT/DELETE/OPTIONS 直接返回 400，m_method 枚举里其余几个值都不可达。
const map<string, http_conn::Route> &http_conn::route_table()
{
    static const map<string, Route> routes = {
        //账号
        {"/api/register", {&http_conn::handle_register, true}},
        {"/api/login", {&http_conn::handle_login, true}},
        {"/api/logout", {&http_conn::handle_logout, true}},
        {"/api/whoami", {&http_conn::handle_whoami, false}},
        //论坛业务
        {"/api/article/create", {&http_conn::handle_article_create, true}},
        {"/api/article/list", {&http_conn::handle_article_list, false}},
        {"/api/article/detail", {&http_conn::handle_article_detail, false}},
        {"/api/comment/create", {&http_conn::handle_comment_create, true}},
        {"/api/follow", {&http_conn::handle_follow, true}},
        {"/api/unfollow", {&http_conn::handle_unfollow, true}},
        {"/api/feed", {&http_conn::handle_feed, false}},
        {"/api/profile", {&http_conn::handle_profile, false}},
        //兼容旧表单 action：html 里写的是相对路径，浏览器会 POST 到 /3CGISQL.cgi
        {"/3CGISQL.cgi", {&http_conn::handle_register, true}},
        {"/2CGISQL.cgi", {&http_conn::handle_login, true}},
    };
    return routes;
}

// 从 Cookie 解析出当前登录用户；没有会话就是 -1
void http_conn::load_session()
{
    m_user_id = -1;
    if (m_session_id.empty())
        return;

    m_user_id = session_manager::get_instance()->get_user_id(m_session_id);
}

// 登录/注册成功后建会话，并通过响应头把 session_id 交给浏览器
void http_conn::start_session(int user_id)
{
    // 先销毁请求里带的旧会话，再发新的。
    // 同一个浏览器先登 A 再登 B 时，如果不销毁 A 的那条记录，
    // 服务端会同时留着两把有效的钥匙；而"让旧钥匙立即失效"是登录应有的语义。
    if (!m_session_id.empty())
        session_manager::get_instance()->destroy_session(m_session_id);

    string sid = session_manager::get_instance()->create_session(user_id);
    if (sid.empty())
    {
        LOG_ERROR("create session failed, user_id=%d", user_id);
        return;
    }

    m_session_id = sid;
    m_user_id = user_id;

    // SameSite=Lax 是这里唯一挡得住 CSRF 的东西，不能省：
    // 写接口虽然锁了 POST（GET 一律 405），但跨站表单一样可以 POST。
    // Lax 让浏览器在跨站请求里不带这个 Cookie，攻击者的页面就发不出
    // "带着你身份的请求"。不用 Strict 是因为它会让"从外部链接点进论坛"
    // 的第一次请求看起来像未登录，体验代价没必要付。
    char cookie[320];
    snprintf(cookie, sizeof(cookie),
             "Set-Cookie: %s=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Lax\r\n",
             SESSION_COOKIE_NAME, sid.c_str(), session_manager::DEFAULT_TTL);
    m_extra_headers += cookie;
}

// 登录校验：/2CGISQL.cgi、/api/login
http_conn::HTTP_CODE http_conn::handle_login()
{
    // 和注册侧（handle_register）用同一组上限：user.username 是 VARCHAR(64)，
    // 超过列宽的用户名在库里必然不存在，而下面校验散列要跑一次完整的 bcrypt
    // （cost 10，约 60ms），先用长度挡掉能省下这份纯粹的无用功。
    const size_t USERNAME_MAX = 64;
    // 64 < bcrypt 的 72 字节上限，这个关系不能破：bcrypt 会【静默忽略】
    // 第 72 字节之后的内容，只要 HTTP 层允许超过 72 字节的口令进到 verify，
    // 就会出现"前 72 字节对得上就登录成功"，等于把口令空间截短。
    const size_t PASSWORD_MAX = 64;

    string name = get_param("user");
    string password = get_param("password");

    if (name.empty() || name.size() > USERNAME_MAX ||
        password.empty() || password.size() > PASSWORD_MAX)
        return serve_file("/logError.html");

    // 连接由线程池在调 process() 之前从池子里取好，放在 mysql 成员里
    if (mysql == NULL)
    {
        LOG_ERROR("handle_login: no mysql connection");
        return INTERNAL_ERROR;
    }

    // 只取散列列。bcrypt 的散列串自带 salt，不再有单独的 salt 列；
    // 明文列也已经删掉了（见 db/schema.sql 的迁移留档）。
    string sql = "SELECT user_id, passwd_hash FROM user WHERE username='" +
                 sql_escape(mysql, name) + "' LIMIT 1";

    if (mysql_query(mysql, sql.c_str()))
    {
        LOG_ERROR("SELECT error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }

    bool ok = false;
    long long uid = -1;
    string stored_hash;

    MYSQL_ROW row = mysql_fetch_row(res);
    if (row != NULL)
    {
        uid = (row[0] != NULL) ? atoll(row[0]) : -1;
        stored_hash = col(row, 1);
        ok = password::verify(password, stored_hash);
    }
    else
    {
        // 用户不存在时也跑一遍同样代价的散列再丢掉结果。
        // 否则"账号不存在"是一条只查一次表就返回的快速路径，
        // 而"账号存在"要付一次完整的 bcrypt —— 攻击者不需要看返回码，
        // 光看响应快慢就能把'哪些用户名是有效的'列出来。
        // 这里的结果没有任何用途，只要耗时对得上，所以用哪个口令无所谓。
        password::hash(password);
    }
    mysql_free_result(res);

    if (!ok || uid < 0)
        return serve_file("/logError.html");

    start_session((int)uid);
    return serve_file("/welcome.html");
}

// 注册：/3CGISQL.cgi、/api/register
http_conn::HTTP_CODE http_conn::handle_register()
{
    // 长度上限：user.username 是 VARCHAR(64)，passwd_hash 是 VARCHAR(100)。
    // 这里用 std::string::size()（字节数）来判断，比列宽的字符数更严格
    // （一个中文字符占 3 字节，所以中文用户名最多 21 个字符）。
    // 故意取严：宁可少收几个字符，也不能让多字节输入撑爆列宽。
    const size_t USERNAME_MAX = 64;
    // 见 handle_login 里的说明：必须 < bcrypt 的 72 字节上限。
    const size_t PASSWORD_MAX = 64;

    string name = get_param("user");
    string password = get_param("password");

    // 服务端自己校验，前端的 required/maxlength 只是体验
    if (name.empty() || name.size() > USERNAME_MAX ||
        password.empty() || password.size() > PASSWORD_MAX)
        return serve_file("/registerError.html");

    if (mysql == NULL)
    {
        LOG_ERROR("handle_register: no mysql connection");
        return INTERNAL_ERROR;
    }

    // 注册只写散列。库里根本没有明文列可写（见 db/schema.sql 的迁移留档）。
    string new_hash = password::hash(password);
    if (new_hash.empty())
    {
        // 拿不到散列就不能建账号。随机源不可用 / 口令超长都会走到这里，
        // 继续下去只会写出一个谁也匹配不上的账号，或者更糟 —— 一个空串散列。
        LOG_ERROR("register: password::hash failed, refuse to create account");
        return INTERNAL_ERROR;
    }

    string sql = "INSERT INTO user(username, passwd_hash) VALUES('" +
                 sql_escape(mysql, name) + "', '" +
                 sql_escape(mysql, new_hash) + "')";

    if (mysql_query(mysql, sql.c_str()))
    {
        unsigned int err = mysql_errno(mysql);
        // 1062 = ER_DUP_ENTRY。重名判断交给数据库唯一键，
        // 比自己先查一遍再插入可靠：并发同名注册不会双写。
        // 注意 LOG_* 宏展开后自带 if，所以这里必须加花括号。
        if (err == 1062)
        {
            LOG_INFO("register: username already exists: %s", name.c_str());
        }
        else
        {
            LOG_ERROR("INSERT error(%u):%s", err, mysql_error(mysql));
        }
        return serve_file("/registerError.html");
    }

    long long uid = (long long)mysql_insert_id(mysql);
    if (uid <= 0)
    {
        LOG_ERROR("register: invalid user_id after insert");
        return serve_file("/registerError.html");
    }

    start_session((int)uid);
    return serve_file("/log.html");
}

// 登出：销毁会话，并让浏览器立刻丢掉 cookie
http_conn::HTTP_CODE http_conn::handle_logout()
{
    if (!m_session_id.empty())
        session_manager::get_instance()->destroy_session(m_session_id);

    // 清 Cookie 时属性要和下发时完全一致（HttpOnly/Path/SameSite）。
    // 属性不一致时浏览器会把它当成"另一个 Cookie"，原有那条就删不掉。
    char cookie[192];
    snprintf(cookie, sizeof(cookie),
             "Set-Cookie: %s=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax\r\n",
             SESSION_COOKIE_NAME);
    m_extra_headers += cookie;

    m_session_id.clear();
    m_user_id = -1;

    return serve_file("/judge.html");
}

// 返回当前登录状态。既用来验证会话，也用来压测大响应体
// （pad=N 时在响应体后补 N 个 'x'，让 writev 一次发不完，覆盖 iov 重算分支）
http_conn::HTTP_CODE http_conn::handle_whoami()
{
    string body;
    if (m_user_id >= 0)
    {
        char buf[128];
        snprintf(buf, sizeof(buf), "<h1>logged in</h1><p>user_id=%d</p>", m_user_id);
        body = string("<html><body>") + buf + "</body></html>";
    }
    else
    {
        body = "<html><body><h1>not logged in</h1></body></html>";
    }

    long long pad = to_ll(get_param("pad"), 0);
    if (pad > 0)
    {
        if (pad > MAX_READ_BUFFER)
            pad = MAX_READ_BUFFER;
        body.append((size_t)pad, 'x');
    }

    m_dyn_body = body;
    return DYNAMIC_REQUEST;
}

// ============================================================
// 论坛业务
//
// 三条铁律，每个 handler 都要遵守：
//   1. user_id 一律取自 session（m_user_id），绝不从请求参数里读。
//      否则任何人改一个表单字段就能以别人的身份发帖。
//   2. 字符串参数一律 sql_escape 后再拼进 SQL；数字参数一律 to_ll 转整数。
//   3. 渲染进 HTML 的用户内容一律 html_escape，否则是存储型 XSS。
// ============================================================

// 分页大小。列表和关注流共用。
static const long long FORUM_PAGE_SIZE = 20;
// 页码上限。用来挡住 ?page=99999999999 这种让 OFFSET 巨大、
// 数据库被迫扫全表再丢弃的请求（这是一种廉价的拒绝服务）。
static const long long FORUM_MAX_PAGE = 100000;

// 长度上限，按列宽定，同样用字节数判断（比列宽的字符数更严格，见 handle_register 的说明）。
// title 是 VARCHAR(255)，comment.content 是 VARCHAR(1000)，
// article.content 是 TEXT(65535 字节)。
//
// CONTENT_MAX 为什么是 16000 而不是列宽允许的更大值：
// 这两个上限必须能对得上。正文在 HTTP 层是 application/x-www-form-urlencoded，
// 每个字节最坏会膨胀成 "%XX" 三个字节（中文、emoji、引号都会）。
// 正文 16000 字节 + 标题 255 字节，编码后最坏是
//   3*16000 + 3*255 + 约20字节的分隔符 ≈ 48785 字节
// 刚好落在 MAX_CONTENT_LENGTH(49152) 之内。
// 若把 CONTENT_MAX 设成 20000，一篇 2 万字节的中文长文编码后会超过 48KB，
// 用户看到的是 HTTP 层的 413 而不是这条"正文太长"的业务提示 —— 两个限制打架了。
static const size_t TITLE_MAX = 255;
static const size_t CONTENT_MAX = 16000;
static const size_t COMMENT_MAX = 1000;

namespace
{
// 统一的参数错误页，省得每个 handler 各拼一遍
string bad_request_page(const char *msg)
{
    string b = "<div class=\"err\"><p>";
    b += html_escape(msg);
    b += "</p><p><a href=\"/api/article/list\">回论坛列表</a></p></div>";
    return b;
}

// 资源不存在的 404 页。
// 不用 process_write 里那个 NO_RESOURCE 的静态文案：那句是
// "The requested file was not found on this server."，是给"静态文件找不到"写的，
// 对一个不存在的文章 id 这么说，用户只会以为是页面坏了。
string not_found_page(const char *msg)
{
    string b = "<div class=\"err\"><p>";
    b += html_escape(msg);
    b += "</p><p><a href=\"/api/article/list\">回论坛列表</a></p></div>";
    return b;
}
} // namespace

// 发文章：POST /api/article/create  参数 title, content
http_conn::HTTP_CODE http_conn::handle_article_create()
{
    // 写接口必须先登录。这里返回 401，而不是静默当成匿名发帖。
    if (m_user_id < 0)
        return require_login();

    string title = get_param("title");
    string content = get_param("content");

    if (title.empty() || content.empty())
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("标题和正文都不能为空。")),
                            400, "Bad Request");

    if (title.size() > TITLE_MAX)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("标题太长（上限 255 字节）。")),
                            400, "Bad Request");

    if (content.size() > CONTENT_MAX)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("正文太长（上限 16000 字节）。")),
                            400, "Bad Request");

    // user_id 来自 session，不接受客户端传值
    char uid[32];
    snprintf(uid, sizeof(uid), "%d", m_user_id);

    string sql = "INSERT INTO article(user_id, title, content) VALUES(" +
                 string(uid) + ", '" + sql_escape(mysql, title) + "', '" +
                 sql_escape(mysql, content) + "')";

    if (!db_exec(sql))
        return INTERNAL_ERROR;

    long long aid = (long long)mysql_insert_id(mysql);
    if (aid <= 0)
    {
        LOG_ERROR("article_create: invalid article_id after insert");
        return INTERNAL_ERROR;
    }

    // 跳转到详情页。用 302 而不是直接渲染，避免用户刷新时重复提交表单。
    return redirect_to("/api/article/detail?id=" + to_string(aid));
}

// 文章列表：GET /api/article/list?page=N
http_conn::HTTP_CODE http_conn::handle_article_list()
{
    // 没给 page 时默认第 1 页；但"给了 page 而值非法"必须拒绝，
    // 不能静默当成第 1 页 —— 那会让 ?page=abc 和 ?page=1 返回同样的内容，
    // 把客户端的拼参数 bug 藏起来。
    string page_s = get_param("page");
    long long page = page_s.empty() ? 1 : to_ll(page_s, -1);

    if (page < 1 || page > FORUM_MAX_PAGE)
        return dynamic_html(html_page("参数错误", html_nav(m_user_id >= 0),
                                      bad_request_page("页码超出允许范围（1 ~ 100000）。")),
                            400, "Bad Request");

    // LIMIT/OFFSET 只接整数，不存在注入问题。
    // 边界已经卡住，page 最大 100000，乘 20 不会溢出 long long。
    long long offset = (page - 1) * FORUM_PAGE_SIZE;

    char off[32];
    snprintf(off, sizeof(off), "%lld", offset);

    // JOIN user 取作者名。列表要显示"谁发的"，否则一排标题看不出归属。
    //
    // ORDER BY 里的 article_id DESC 不是装饰，是分页正确性的必要条件：
    // create_time 是 DATETIME，只有秒级精度。连续发帖（或在压测下）很容易
    // 一批帖子的 create_time 完全相同，此时"仅按 create_time 排序"在并列组内
    // 没有定义顺序。第 1 页和第 2 页是两个独立查询，并列组内部顺序一旦不一致，
    // 就会有帖子在两页各出现一次、另一条永远看不到。
    // 补上唯一的 article_id 之后就构成全序，分页才是稳定的。
    //
    // 代价为零：InnoDB 的二级索引会隐式带上主键，idx_create_time 物理上就是
    // (create_time, article_id)，反向扫描恰好满足 (DESC, DESC)，不会多出 filesort。
    string sql = "SELECT a.article_id, a.title, a.user_id, a.view_count, a.create_time, u.username "
                 "FROM article a JOIN user u ON a.user_id = u.user_id "
                 "ORDER BY a.create_time DESC, a.article_id DESC LIMIT 20 OFFSET " + string(off);

    if (!db_exec(sql))
        return INTERNAL_ERROR;

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("article_list: store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }

    string body;
    body += "<h1>论坛</h1>";

    // 登录后可以直接在这里发帖，不用再跳到别的页面
    if (m_user_id >= 0)
    {
        body += "<form action=\"/api/article/create\" method=\"post\">"
                "<input type=\"text\" name=\"title\" maxlength=\"100\" "
                "placeholder=\"标题\" required><br>"
                "<textarea name=\"content\" rows=\"5\" placeholder=\"正文\" required></textarea><br>"
                "<button type=\"submit\">发布</button></form>";
    }
    else
    {
        body += "<p><a href=\"/log.html\">登录</a> 后可以发帖和评论。</p>";
    }

    long long n = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) != NULL)
    {
        ++n;
        long long aid = atoll(col(row, 0).c_str());

        char link[64];
        snprintf(link, sizeof(link), "/api/article/detail?id=%lld", aid);

        body += "<div class=\"item\">";
        // title 是用户内容，必须转义
        body += "<a class=\"title\" href=\"" + string(link) + "\">" +
                html_escape(col(row, 1)) + "</a>";
        body += "<div class=\"meta\">" + html_escape(col(row, 5)) +
                " 发布于 " + html_time(col(row, 4)) +
                " · 阅读 " + col(row, 3) + "</div>";
        body += "</div>";
    }
    mysql_free_result(res);

    if (n == 0)
    {
        body += (page == 1)
                    ? "<p>还没有人发帖。</p>"
                    : "<p>这一页没有内容。</p>";
    }

    // 不做 COUNT(*) 来算总页数：那是一次没有任何索引支撑的全表计数，
    // 而"当前页是否满 20 条"已经足够决定要不要给出下一页链接。
    body += "<div class=\"nav\">";
    if (page > 1)
    {
        char prev[64];
        snprintf(prev, sizeof(prev), "/api/article/list?page=%lld", page - 1);
        body += "<a href=\"" + string(prev) + "\">上一页</a>";
    }
    if (n == FORUM_PAGE_SIZE)
    {
        char next[64];
        snprintf(next, sizeof(next), "/api/article/list?page=%lld", page + 1);
        body += " <a href=\"" + string(next) + "\">下一页</a>";
    }
    body += "</div>";

    return dynamic_html(html_page("论坛", html_nav(m_user_id >= 0), body));
}

// 文章详情 + 评论列表：GET /api/article/detail?id=N
http_conn::HTTP_CODE http_conn::handle_article_detail()
{
    long long aid = to_ll(get_param("id"), -1);
    if (aid <= 0)
        return dynamic_html(html_page("文章不存在", html_nav(m_user_id >= 0),
                                      not_found_page("文章 id 不合法。")),
                            404, "Not Found");

    char idbuf[32];
    snprintf(idbuf, sizeof(idbuf), "%lld", aid);

    string sql = "SELECT a.article_id, a.user_id, a.title, a.content, a.view_count, "
                 "a.create_time, u.username "
                 "FROM article a JOIN user u ON a.user_id = u.user_id "
                 "WHERE a.article_id = " + string(idbuf);

    if (!db_exec(sql))
        return INTERNAL_ERROR;

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("article_detail: store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }

    MYSQL_ROW row = mysql_fetch_row(res);

    // 文章不存在要给 404 页面，不能返回一个空白页 —— 空白页会让用户
    // 以为是前端渲染坏了，而实际是 id 错了。
    if (row == NULL)
    {
        mysql_free_result(res);
        return dynamic_html(html_page("文章不存在", html_nav(m_user_id >= 0),
                                      not_found_page("这篇文章不存在或已被删除。")),
                            404, "Not Found");
    }

    string title = col(row, 2);
    string content = col(row, 3);
    string author = col(row, 6);
    string ctime = col(row, 5);
    long long views = atoll(col(row, 4).c_str());
    mysql_free_result(res);

    // view_count 自增。故意【不】和上面的查询放在同一个事务里：
    // 详情查询是读、计数是写，包成一个事务只会拉长持锁时间，
    // 把一个人人都会访问的热点页面变成一个写热点。
    // 少记几次浏览量无所谓，锁冲突才是真问题。
    if (!db_exec("UPDATE article SET view_count = view_count + 1 WHERE article_id = " +
                 string(idbuf)))
    {
        // 计数失败不该让整个页面挂掉：记了日志继续渲染。
        LOG_WARN("article_detail: view_count update failed, id=%lld", aid);
    }
    else
    {
        ++views;
    }

    string body;
    body += "<h1>" + html_escape(title) + "</h1>";
    body += "<div class=\"meta\">" + html_escape(author) + " 发布于 " +
            html_time(ctime) + " · 阅读 " + to_string(views) + "</div>";
    body += "<div class=\"content\">" + html_escape(content) + "</div>";

    // 评论列表：JOIN user 取评论者名字
    string csql = "SELECT c.content, c.create_time, u.username "
                  "FROM comment c JOIN user u ON c.user_id = u.user_id "
                  "WHERE c.article_id = " + string(idbuf) +
                  // 同样补 comment_id 做 tiebreaker，否则同一秒的多条评论顺序不稳定
                  " ORDER BY c.create_time ASC, c.comment_id ASC";

    if (db_exec(csql))
    {
        MYSQL_RES *cres = mysql_store_result(mysql);
        if (cres != NULL)
        {
            long long cn = 0;
            MYSQL_ROW crow;
            string clist;
            while ((crow = mysql_fetch_row(cres)) != NULL)
            {
                ++cn;
                clist += "<div class=\"cbox\"><div class=\"who\">" +
                         html_escape(col(crow, 2)) + " · " + html_time(col(crow, 1)) +
                         "</div><div class=\"txt\">" + html_escape(col(crow, 0)) +
                         "</div></div>";
            }
            mysql_free_result(cres);

            body += "<h2>评论（" + to_string(cn) + "）</h2>";
            body += (cn == 0) ? "<p>还没有评论，来说两句。</p>" : clist;
        }
    }

    // 评论表单。登录了才能发，未登录给登录入口。
    if (m_user_id >= 0)
    {
        body += "<h2>发表评论</h2>"
                "<form action=\"/api/comment/create\" method=\"post\">"
                "<input type=\"hidden\" name=\"article_id\" value=\"" +
                to_string(aid) + "\">"
                "<textarea name=\"content\" rows=\"3\" maxlength=\"330\" "
                "placeholder=\"写点什么…\" required></textarea><br>"
                "<button type=\"submit\">提交评论</button></form>";
    }
    else
    {
        body += "<p><a href=\"/log.html\">登录</a> 后可以评论。</p>";
    }

    body += "<p><a href=\"/api/article/list\">← 回论坛列表</a></p>";

    return dynamic_html(html_page(title, html_nav(m_user_id >= 0), body));
}

// 发评论：POST /api/comment/create  参数 article_id, content
http_conn::HTTP_CODE http_conn::handle_comment_create()
{
    if (m_user_id < 0)
        return require_login();

    long long aid = to_ll(get_param("article_id"), -1);
    string content = get_param("content");

    if (aid <= 0)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("article_id 不合法。")),
                            400, "Bad Request");

    if (content.empty())
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("评论内容不能为空。")),
                            400, "Bad Request");

    if (content.size() > COMMENT_MAX)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("评论太长（上限 1000 字节）。")),
                            400, "Bad Request");

    char idbuf[32];
    snprintf(idbuf, sizeof(idbuf), "%lld", aid);

    // 先查文章是否存在。外键约束也会拦（1452），但那个报错对用户毫无意义，
    // 而且会把一次正常的用户输入错误变成一行错误日志。这里主动查一次。
    if (!db_exec("SELECT 1 FROM article WHERE article_id = " + string(idbuf) + " LIMIT 1"))
        return INTERNAL_ERROR;

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("comment_create: store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }
    bool exists = (mysql_fetch_row(res) != NULL);
    mysql_free_result(res);

    if (!exists)
        return dynamic_html(html_page("文章不存在", html_nav(true),
                                      bad_request_page("要评论的文章不存在或已被删除。")),
                            404, "Not Found");

    char uid[32];
    snprintf(uid, sizeof(uid), "%d", m_user_id);

    string sql = "INSERT INTO comment(article_id, user_id, content) VALUES(" +
                 string(idbuf) + ", " + string(uid) + ", '" +
                 sql_escape(mysql, content) + "')";

    if (!db_exec(sql))
        return INTERNAL_ERROR;

    // 302 回详情页，避免刷新重复提交
    return redirect_to("/api/article/detail?id=" + to_string(aid));
}

// 关注：POST /api/follow  参数 followee_id
http_conn::HTTP_CODE http_conn::handle_follow()
{
    if (m_user_id < 0)
        return require_login();

    long long target = to_ll(get_param("followee_id"), -1);
    if (target <= 0)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("followee_id 不合法。")),
                            400, "Bad Request");

    // 禁止自己关注自己。
    // 这一点必须在这里拦：follow 表的联合主键只保证"同一对不重复"，
    // 对 follower_id == followee_id 完全放行（阶段 1 实测确认过）。
    if (target == m_user_id)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("不能关注自己。")),
                            400, "Bad Request");

    char tid[32], uid[32];
    snprintf(tid, sizeof(tid), "%lld", target);
    snprintf(uid, sizeof(uid), "%d", m_user_id);

    // 先确认目标用户存在。外键会拦，但应用层先查能给出友好提示。
    if (!db_exec("SELECT 1 FROM user WHERE user_id = " + string(tid) + " LIMIT 1"))
        return INTERNAL_ERROR;

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("follow: store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }
    bool exists = (mysql_fetch_row(res) != NULL);
    mysql_free_result(res);

    if (!exists)
        return dynamic_html(html_page("用户不存在", html_nav(true),
                                      bad_request_page("要关注的用户不存在。")),
                            404, "Not Found");

    // INSERT IGNORE：重复关注不报 1062，直接当成功。
    // 幂等是必须的 —— 用户连点两下"关注"不能看到报错。
    if (!db_exec("INSERT IGNORE INTO follow(follower_id, followee_id) VALUES(" +
                 string(uid) + ", " + string(tid) + ")"))
        return INTERNAL_ERROR;

    return redirect_to("/api/profile?id=" + to_string(target));
}

// 取关：POST /api/unfollow  参数 followee_id
http_conn::HTTP_CODE http_conn::handle_unfollow()
{
    if (m_user_id < 0)
        return require_login();

    long long target = to_ll(get_param("followee_id"), -1);
    if (target <= 0)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("followee_id 不合法。")),
                            400, "Bad Request");

    // 取关自己本来就不可能有记录（关注时已拦），DELETE 影响 0 行即可，不算错误。
    if (target == m_user_id)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("不能取关自己。")),
                            400, "Bad Request");

    char tid[32], uid[32];
    snprintf(tid, sizeof(tid), "%lld", target);
    snprintf(uid, sizeof(uid), "%d", m_user_id);

    // 幂等：没关注过时影响 0 行，同样返回成功
    if (!db_exec("DELETE FROM follow WHERE follower_id = " + string(uid) +
                 " AND followee_id = " + string(tid)))
        return INTERNAL_ERROR;

    return redirect_to("/api/profile?id=" + to_string(target));
}

// 关注流：GET /api/feed?page=N
http_conn::HTTP_CODE http_conn::handle_feed()
{
    if (m_user_id < 0)
        return require_login();

    string page_s = get_param("page");
    long long page = page_s.empty() ? 1 : to_ll(page_s, -1);
    if (page < 1 || page > FORUM_MAX_PAGE)
        return dynamic_html(html_page("参数错误", html_nav(true),
                                      bad_request_page("页码超出允许范围（1 ~ 100000）。")),
                            400, "Bad Request");

    long long offset = (page - 1) * FORUM_PAGE_SIZE;
    char off[32], uid[32];
    snprintf(off, sizeof(off), "%lld", offset);
    snprintf(uid, sizeof(uid), "%d", m_user_id);

    string body;
    body += "<h1>关注流</h1>";

    // 2.7 的接口 B：粉丝数 / 关注数 / 文章数。
    // 三个 COUNT(*) 都有索引支撑（idx_followee、follow 主键前缀、idx_user_time），
    // 当前数据量下够用。真上量了再考虑冗余计数列 + 事务维护 —— 现在别过早优化。
    long long fans = 0, follows = 0, arts = 0;
    if (db_exec("SELECT (SELECT COUNT(*) FROM follow WHERE followee_id = " + string(uid) +
                "), (SELECT COUNT(*) FROM follow WHERE follower_id = " + string(uid) +
                "), (SELECT COUNT(*) FROM article WHERE user_id = " + string(uid) + ")"))
    {
        MYSQL_RES *res = mysql_store_result(mysql);
        if (res != NULL)
        {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row != NULL)
            {
                fans = atoll(col(row, 0).c_str());
                follows = atoll(col(row, 1).c_str());
                arts = atoll(col(row, 2).c_str());
            }
            mysql_free_result(res);
        }
    }

    body += "<p><span class=\"stat\">关注 <b>" + to_string(follows) +
            "</b> 人</span><span class=\"stat\">粉丝 <b>" + to_string(fans) +
            "</b></span><span class=\"stat\">我的文章 <b>" + to_string(arts) +
            "</b></span></p>";

    // 关注流：JOIN follow + article。
    // f 走主键最左前缀(follower_id)，a 走 idx_user_time，见阶段 1 的 EXPLAIN 验证。
    string sql = "SELECT a.article_id, a.title, a.create_time, u.username "
                 "FROM follow f "
                 "JOIN article a ON a.user_id = f.followee_id "
                 "JOIN user u ON u.user_id = a.user_id "
                 "WHERE f.follower_id = " + string(uid) +
                 // article_id 做 tiebreaker，理由同列表页：create_time 只有秒级精度
                 " ORDER BY a.create_time DESC, a.article_id DESC LIMIT 20 OFFSET " + string(off);

    if (!db_exec(sql))
        return INTERNAL_ERROR;

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("feed: store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }

    long long n = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) != NULL)
    {
        ++n;
        long long aid = atoll(col(row, 0).c_str());
        char link[64];
        snprintf(link, sizeof(link), "/api/article/detail?id=%lld", aid);

        body += "<div class=\"item\"><a class=\"title\" href=\"" + string(link) + "\">" +
                html_escape(col(row, 1)) + "</a>" +
                "<div class=\"meta\">" + html_escape(col(row, 3)) + " 发布于 " +
                html_time(col(row, 2)) + "</div></div>";
    }
    mysql_free_result(res);

    if (n == 0)
    {
        body += (page == 1)
                    ? "<p>关注流是空的。去 <a href=\"/api/article/list\">论坛</a> "
                      "找人，进 TA 的主页点关注。</p>"
                    : "<p>这一页没有内容。</p>";
    }

    body += "<div class=\"nav\">";
    if (page > 1)
    {
        char prev[64];
        snprintf(prev, sizeof(prev), "/api/feed?page=%lld", page - 1);
        body += "<a href=\"" + string(prev) + "\">上一页</a>";
    }
    if (n == FORUM_PAGE_SIZE)
    {
        char next[64];
        snprintf(next, sizeof(next), "/api/feed?page=%lld", page + 1);
        body += " <a href=\"" + string(next) + "\">下一页</a>";
    }
    body += "</div>";

    return dynamic_html(html_page("关注流", html_nav(true), body));
}

// 个人主页：GET /api/profile?id=N（省略 id 时是当前登录用户）
// 承载 2.7 的计数，也是关注/取关按钮的落点。
http_conn::HTTP_CODE http_conn::handle_profile()
{
    long long target = to_ll(get_param("id"), -1);
    if (target <= 0)
        target = m_user_id;  // 不传 id 就看自己

    if (target <= 0)
        return require_login();  // 未登录又没有 id，没有可展示的主页

    char tid[32];
    snprintf(tid, sizeof(tid), "%lld", target);

    if (!db_exec("SELECT username, create_time FROM user WHERE user_id = " + string(tid) +
                 " LIMIT 1"))
        return INTERNAL_ERROR;

    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
    {
        LOG_ERROR("profile: store result error:%s", mysql_error(mysql));
        return INTERNAL_ERROR;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row == NULL)
    {
        mysql_free_result(res);
        return dynamic_html(html_page("用户不存在", html_nav(m_user_id >= 0),
                                      not_found_page("这个用户不存在。")),
                            404, "Not Found");
    }
    string uname = col(row, 0);
    string ujoined = col(row, 1);
    mysql_free_result(res);

    // 计数（同 2.7 接口 B）
    long long fans = 0, follows = 0, arts = 0;
    bool i_follow = false;
    if (db_exec("SELECT (SELECT COUNT(*) FROM follow WHERE followee_id = " + string(tid) +
                "), (SELECT COUNT(*) FROM follow WHERE follower_id = " + string(tid) +
                "), (SELECT COUNT(*) FROM article WHERE user_id = " + string(tid) + ")"))
    {
        MYSQL_RES *r2 = mysql_store_result(mysql);
        if (r2 != NULL)
        {
            MYSQL_ROW r = mysql_fetch_row(r2);
            if (r != NULL)
            {
                fans = atoll(col(r, 0).c_str());
                follows = atoll(col(r, 1).c_str());
                arts = atoll(col(r, 2).c_str());
            }
            mysql_free_result(r2);
        }
    }

    // 我是否已关注 TA（决定按钮显示"关注"还是"取关"）
    if (m_user_id >= 0 && m_user_id != target)
    {
        char uid[32];
        snprintf(uid, sizeof(uid), "%d", m_user_id);
        if (db_exec("SELECT 1 FROM follow WHERE follower_id = " + string(uid) +
                    " AND followee_id = " + string(tid) + " LIMIT 1"))
        {
            MYSQL_RES *r3 = mysql_store_result(mysql);
            if (r3 != NULL)
            {
                i_follow = (mysql_fetch_row(r3) != NULL);
                mysql_free_result(r3);
            }
        }
    }

    string body;
    body += "<h1>" + html_escape(uname) + "</h1>";
    body += "<p><span class=\"stat\">文章 <b>" + to_string(arts) +
            "</b></span><span class=\"stat\">粉丝 <b>" + to_string(fans) +
            "</b></span><span class=\"stat\">关注 <b>" + to_string(follows) +
            "</b></span></p>";
    body += "<div class=\"meta\">加入于 " + html_time(ujoined) + "</div>";

    if (m_user_id < 0)
    {
        body += "<p><a href=\"/log.html\">登录</a> 后可以关注 TA。</p>";
    }
    else if (m_user_id == target)
    {
        body += "<p>这是你自己的主页。</p>";
    }
    else
    {
        const char *action = i_follow ? "/api/unfollow" : "/api/follow";
        const char *label = i_follow ? "取消关注" : "关注 TA";
        body += "<form action=\"" + string(action) + "\" method=\"post\">"
                "<input type=\"hidden\" name=\"followee_id\" value=\"" + string(tid) + "\">"
                "<button type=\"submit\">" + label + "</button></form>";
    }

    // TA 的最近文章
    if (db_exec("SELECT article_id, title, create_time, view_count FROM article "
                "WHERE user_id = " + string(tid) +
                " ORDER BY create_time DESC, article_id DESC LIMIT 20"))
    {
        MYSQL_RES *r4 = mysql_store_result(mysql);
        if (r4 != NULL)
        {
            string list;
            long long n = 0;
            MYSQL_ROW r;
            while ((r = mysql_fetch_row(r4)) != NULL)
            {
                ++n;
                long long aid = atoll(col(r, 0).c_str());
                char link[64];
                snprintf(link, sizeof(link), "/api/article/detail?id=%lld", aid);
                list += "<div class=\"item\"><a class=\"title\" href=\"" + string(link) +
                        "\">" + html_escape(col(r, 1)) + "</a>"
                        "<div class=\"meta\">" + html_time(col(r, 2)) +
                        " · 阅读 " + col(r, 3) + "</div></div>";
            }
            mysql_free_result(r4);

            body += "<h2>TA 的文章（" + to_string(n) + "）</h2>";
            body += (n == 0) ? "<p>还没有发过文章。</p>" : list;
        }
    }

    return dynamic_html(html_page(uname + " 的主页", html_nav(m_user_id >= 0), body));
}

http_conn::HTTP_CODE http_conn::do_request()
{
    load_session();

    // 本服务器只实现 GET / POST / HEAD。
    // HEAD 按 GET 的路由走，只是不发正文（见 process_write 末尾）。
    // 其余方法（PUT/DELETE/OPTIONS/TRACE/CONNECT）到这里就已经解析成了具体方法，
    // 直接 501，不进入路由和静态文件逻辑。
    if (m_method != GET && m_method != POST && m_method != HEAD)
        return NOT_IMPLEMENTED;

    //拆出查询串：GET /api/article/list?page=1
    string url(m_url);
    string query;
    size_t q = url.find('?');
    if (q != string::npos)
    {
        query = url.substr(q + 1);
        url = url.substr(0, q);
    }
    m_path = url;

    //查询串也并进 m_post，handler 不用区分参数来自 GET 还是 POST。
    //请求体里的同名参数优先，不被查询串覆盖。
    if (!query.empty())
    {
        map<string, string> qs = parse_form(query.c_str(), query.size());
        for (map<string, string>::const_iterator qit = qs.begin(); qit != qs.end(); ++qit)
        {
            if (m_post.find(qit->first) == m_post.end())
                m_post[qit->first] = qit->second;
        }
    }

    const map<string, Route> &routes = route_table();
    map<string, Route>::const_iterator it = routes.find(url);
    if (it != routes.end())
    {
        // 写接口只收 POST。用 405 而不是 404 或静默执行：
        // 明确告诉调用方"路径对、方法错"，同时带 Allow 头说明该用什么方法。
        if (it->second.post_only && m_method != POST)
            return METHOD_NOT_ALLOWED;

        // 写接口还要确认请求来自本站页面，见 origin_ok()。
        // 读接口不查：它们不改数据，被别人跨站读到也不产生副作用。
        if (it->second.post_only && !origin_ok())
        {
            LOG_WARN("cross-site write request blocked: Origin=%s", m_origin.c_str());
            return FORBIDDEN_REQUEST;
        }

        return (this->*(it->second.handler))();
    }

    //未注册的 /api/* 直接 404，不能落到静态文件逻辑里去
    if (url.compare(0, 5, "/api/") == 0)
        return NO_RESOURCE;

    return serve_static();
}

// 静态资源：保留原有的 0/1/5/6/7 跳转约定，其余按路径直接找 root 下的文件
http_conn::HTTP_CODE http_conn::serve_static()
{
    const char *url = m_path.c_str();
    const char *p = strrchr(url, '/');
    if (p == NULL)
        return BAD_REQUEST;

    const char *target = NULL;
    switch (*(p + 1))
    {
    case '0':
        target = "/register.html";
        break;
    case '1':
        target = "/log.html";
        break;
    case '5':
        target = "/picture.html";
        break;
    case '6':
        target = "/video.html";
        break;
    case '7':
        target = "/fans.html";
        break;
    default:
        break;
    }

    if (target != NULL)
        return serve_file(target);

    return serve_file(url);
}

// 把 root 下的相对路径映射成响应
http_conn::HTTP_CODE http_conn::serve_file(const char *relative_path)
{
    // 拒绝路径穿越：URL 里带 ".." 一律不当文件处理。
    // 原实现直接把 m_url 拼到 doc_root 后面，/../ 可以读到 root 之外的文件。
    if (strstr(relative_path, "..") != NULL)
    {
        LOG_WARN("path traversal blocked: %s", relative_path);
        return FORBIDDEN_REQUEST;
    }

    int len = strlen(doc_root);
    if (len + (int)strlen(relative_path) + 1 > FILENAME_LEN)
        return BAD_REQUEST;

    strcpy(m_real_file, doc_root);
    strncpy(m_real_file + len, relative_path, FILENAME_LEN - len - 1);
    m_real_file[FILENAME_LEN - 1] = '\0';

    return map_file_to_response();
}

// 文件检查 + mmap。返回 FILE_REQUEST 时响应体是 mmap 出来的文件。
http_conn::HTTP_CODE http_conn::map_file_to_response()
{
    if (stat(m_real_file, &m_file_stat) < 0)
        return NO_RESOURCE;

    if (!(m_file_stat.st_mode & S_IROTH))
        return FORBIDDEN_REQUEST;

    if (S_ISDIR(m_file_stat.st_mode))
        return BAD_REQUEST;

    int fd = open(m_real_file, O_RDONLY);
    if (fd < 0)
        return NO_RESOURCE;

    if (m_file_stat.st_size == 0)
    {
        // 空文件不 mmap（mmap 长度为 0 会失败），process_write 会返回空 body
        close(fd);
        m_file_address = 0;
        return FILE_REQUEST;
    }

    m_file_address = (char *)mmap(0, m_file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (m_file_address == MAP_FAILED)
    {
        // 原实现没检查这个返回值，失败时会把 MAP_FAILED 当响应体发出去
        LOG_ERROR("mmap error:%s", strerror(errno));
        m_file_address = 0;
        return INTERNAL_ERROR;
    }

    return FILE_REQUEST;
}
void http_conn::unmap()
{
    if (m_file_address)
    {
        munmap(m_file_address, m_file_stat.st_size);
        m_file_address = 0;
    }
}
bool http_conn::write()
{
    int temp = 0;

    if (bytes_to_send == 0)
    {
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        init();
        return true;
    }

    // HEAD：响应头必须和等价的 GET 一模一样（Content-Length 也要照写，
    // 客户端靠它知道 GET 会返回多大），但正文一个字节都不发 —— 这是 HEAD 的定义。
    // process_write 已经把完整的头块拼好了，这里只要丢掉第二个 iov。
    // 判断 m_iv_count == 2 是为了幂等：EAGAIN 之后 write() 会被再次调用，
    // 那时 m_iv_count 已经是 1，不能再按"头块还没发"来重算。
    if (m_method == HEAD && m_iv_count == 2)
    {
        m_iv_count = 1;
        m_iv[1].iov_base = NULL;
        m_iv[1].iov_len = 0;
        bytes_to_send = (int)(m_write_idx - bytes_have_send);
    }

    while (1)
    {
        temp = writev(m_sockfd, m_iv, m_iv_count);

        if (temp < 0)
        {
            if (errno == EAGAIN)
            {
                modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
                return true;
            }
            unmap();
            return false;
        }

        bytes_have_send += temp;
        bytes_to_send -= temp;
        if (bytes_have_send >= m_iv[0].iov_len)
        {
            m_iv[0].iov_len = 0;
            // m_body_ptr 指向 mmap 出来的文件或 m_dyn_body，两种响应共用这一段
            if (m_iv_count == 2 && m_body_ptr != NULL)
            {
                m_iv[1].iov_base = m_body_ptr + (bytes_have_send - m_write_idx);
                m_iv[1].iov_len = bytes_to_send;
            }
        }
        else
        {
            m_iv[0].iov_base = m_write_buf + bytes_have_send;
            m_iv[0].iov_len = m_iv[0].iov_len - bytes_have_send;
        }

        if (bytes_to_send <= 0)
        {
            unmap();
            modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);

            if (m_linger)
            {
                init();
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
bool http_conn::add_response(const char *format, ...)
{
    if (m_write_idx >= WRITE_BUFFER_SIZE)
        return false;
    va_list arg_list;
    va_start(arg_list, format);
    int len = vsnprintf(m_write_buf + m_write_idx, WRITE_BUFFER_SIZE - 1 - m_write_idx, format, arg_list);
    if (len >= (WRITE_BUFFER_SIZE - 1 - m_write_idx))
    {
        va_end(arg_list);
        return false;
    }
    m_write_idx += len;
    va_end(arg_list);

    return true;
}
bool http_conn::add_status_line(int status, const char *title)
{
    return add_response("%s %d %s\r\n", "HTTP/1.1", status, title);
}
bool http_conn::add_headers(int content_len)
{
    return add_content_length(content_len) && add_linger() &&
           add_extra_headers() && add_blank_line();
}
bool http_conn::add_content_length(int content_len)
{
    return add_response("Content-Length:%d\r\n", content_len);
}
bool http_conn::add_content_type()
{
    return add_response("Content-Type:%s\r\n", "text/html; charset=utf-8");
}
// 静态文件按扩展名定类型（见 content_type_for 的说明）
bool http_conn::add_content_type_for(const char *path)
{
    return add_response("Content-Type:%s\r\n", content_type_for(path));
}
bool http_conn::add_linger()
{
    return add_response("Connection:%s\r\n", (m_linger == true) ? "keep-alive" : "close");
}
// 额外响应头（目前只有 Set-Cookie），必须加在空行之前
bool http_conn::add_extra_headers()
{
    if (m_extra_headers.empty())
        return true;
    return add_content(m_extra_headers.c_str());
}
bool http_conn::add_blank_line()
{
    return add_response("%s", "\r\n");
}
bool http_conn::add_content(const char *content)
{
    return add_response("%s", content);
}
bool http_conn::process_write(HTTP_CODE ret)
{
    switch (ret)
    {
    case INTERNAL_ERROR:
    {
        add_status_line(500, error_500_title);
        add_content_type();
        add_headers(strlen(error_500_form));
        if (!add_content(error_500_form))
            return false;
        break;
    }
    case BAD_REQUEST:
    {
        // 原实现这里写的是 404。BAD_REQUEST 的含义是"请求本身不合法"
        // （请求行语法错、Content-Length 非法、文件名过长），那是 400 的语义。
        // 返回 404 会让调用方以为"路径不存在"，照着去改 URL，查错方向就偏了。
        add_status_line(400, error_400_title);
        add_content_type();
        add_headers(strlen(error_400_form));
        if (!add_content(error_400_form))
            return false;
        break;
    }
    case NO_RESOURCE:
    {
        // 原实现漏了这个 case，NO_RESOURCE 会落到 default 返回 false，
        // 表现成"访问不存在的文件时连接被直接关闭、浏览器没有任何响应"，
        // 而不是返回 404 页面。
        add_status_line(404, error_404_title);
        add_content_type();
        add_headers(strlen(error_404_form));
        if (!add_content(error_404_form))
            return false;
        break;
    }
    case FORBIDDEN_REQUEST:
    {
        add_status_line(403, error_403_title);
        add_content_type();
        add_headers(strlen(error_403_form));
        if (!add_content(error_403_form))
            return false;
        break;
    }
    case METHOD_NOT_ALLOWED:
    {
        add_status_line(405, error_405_title);
        // Allow 头说明该用哪个方法。m_extra_headers 由 add_headers()
        // 内部的 add_extra_headers() 写到空行之前。
        m_extra_headers += "Allow: POST\r\n";
        add_content_type();
        add_headers(strlen(error_405_form));
        if (!add_content(error_405_form))
            return false;
        break;
    }
    case NOT_IMPLEMENTED:
    {
        // 方法名本身合法，只是本服务器没实现。回 400（"语法错误"）会让调用方
        // 去查自己拼错了什么，而真正的原因是服务端能力缺失。
        add_status_line(501, error_501_title);
        m_extra_headers += "Allow: GET, POST\r\n";
        add_content_type();
        add_headers(strlen(error_501_form));
        if (!add_content(error_501_form))
            return false;
        break;
    }
    case PAYLOAD_TOO_LARGE:
    {
        // m_linger 在 parse_headers 里已经置 false，所以 add_linger()
        // 会写上 Connection: close，发完之后 write() 会关掉连接。
        // 这是必须的：正文还留在 socket 里没读，不能拿它当下一个请求解析。
        add_status_line(413, error_413_title);
        add_content_type();
        add_headers(strlen(error_413_form));
        if (!add_content(error_413_form))
            return false;
        break;
    }
    case FILE_REQUEST:
    {
        add_status_line(200, ok_200_title);
        // Content-Type 必须在 add_headers() 之前加：add_headers 的最后一步是空行
        if (m_file_stat.st_size != 0)
        {
            add_content_type_for(m_real_file);
            add_headers(m_file_stat.st_size);
            m_iv[0].iov_base = m_write_buf;
            m_iv[0].iov_len = m_write_idx;
            m_iv[1].iov_base = m_file_address;
            m_iv[1].iov_len = m_file_stat.st_size;
            m_iv_count = 2;
            bytes_to_send = m_write_idx + m_file_stat.st_size;
            m_body_ptr = m_file_address;
            return true;
        }
        else
        {
            const char *ok_string = "<html><body></body></html>";
            add_content_type_for(m_real_file);
            add_headers(strlen(ok_string));
            if (!add_content(ok_string))
                return false;
            // 空文件走 switch 结尾的统一收尾（只有一个 iov）。
            // 这里必须 break：原实现少了它，会落到 default 直接返回 false，
            // 表现成"访问空文件时连接被关闭"。
            break;
        }
    }
    case DYNAMIC_REQUEST:
    {
        // 动态内容走内存缓冲，不经过 mmap。
        // 注意不能像错误页那样用 add_content()：它写进 1024 字节的 m_write_buf，
        // 超长会静默失败并直接断开连接。这里把 body 挂在 m_iv[1] 上。
        // 状态码由 handler 决定（默认 200，可能是 302/400/401/404）。
        add_status_line(m_resp_status, m_resp_status_title);
        add_content_type();
        add_headers((int)m_dyn_body.size());

        m_iv[0].iov_base = m_write_buf;
        m_iv[0].iov_len = m_write_idx;
        m_iv[1].iov_base = (void *)m_dyn_body.data();
        m_iv[1].iov_len = m_dyn_body.size();
        m_iv_count = 2;
        bytes_to_send = m_write_idx + (int)m_dyn_body.size();
        m_body_ptr = (char *)m_dyn_body.data();
        return true;
    }
    default:
        return false;
    }
    m_iv[0].iov_base = m_write_buf;
    m_iv[0].iov_len = m_write_idx;
    m_iv_count = 1;
    bytes_to_send = m_write_idx;
    return true;
}
void http_conn::process()
{
    HTTP_CODE read_ret = process_read();
    if (read_ret == NO_REQUEST)
    {
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        return;
    }
    bool write_ret = process_write(read_ret);
    if (!write_ret)
    {
        close_conn();
    }
    modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
}
