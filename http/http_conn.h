#ifndef HTTPCONNECTION_H
#define HTTPCONNECTION_H
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <map>
#include <string>
#include <vector>

#include "../lock/locker.h"
#include "../CGImysql/sql_connection_pool.h"
#include "../timer/lst_timer.h"
#include "../log/log.h"

class http_conn
{
public:
    static const int FILENAME_LEN = 200;
    static const int READ_BUFFER_SIZE = 2048;  // 读缓冲初始大小，不够会按需翻倍
    static const int MAX_READ_BUFFER = 65536;  // 读缓冲上限，超过则放弃该连接
    // 单次请求正文的硬上限。必须明显小于 MAX_READ_BUFFER：
    // 读缓冲里除了正文还有请求行和请求头，两者共用同一块内存。
    // 留出约 16KB 给请求头，正文最多收 48KB。
    // 超过它是 413（明确的客户端错误），而不是"连接被悄悄断掉"。
    static const int MAX_CONTENT_LENGTH = 49152;
    static const int WRITE_BUFFER_SIZE = 1024;
    enum METHOD
    {
        GET = 0,
        POST,
        HEAD,
        PUT,
        DELETE,
        TRACE,
        OPTIONS,
        CONNECT,
        PATH
    };
    enum CHECK_STATE
    {
        CHECK_STATE_REQUESTLINE = 0,
        CHECK_STATE_HEADER,
        CHECK_STATE_CONTENT
    };
    enum HTTP_CODE
    {
        NO_REQUEST,
        GET_REQUEST,
        BAD_REQUEST,
        NO_RESOURCE,
        FORBIDDEN_REQUEST,
        FILE_REQUEST,
        INTERNAL_ERROR,
        CLOSED_CONNECTION,
        DYNAMIC_REQUEST,     // 响应体在内存里（m_dyn_body），不走 mmap
        PAYLOAD_TOO_LARGE,   // 请求体超过上限，413
        METHOD_NOT_ALLOWED,  // 写接口收到 GET/HEAD，405
        NOT_IMPLEMENTED      // 方法合法但本服务器没实现（PUT/DELETE/...），501
    };
    enum LINE_STATUS
    {
        LINE_OK = 0,
        LINE_BAD,
        LINE_OPEN
    };

public:
    http_conn() {}
    ~http_conn() {}

public:
    void init(int sockfd, const sockaddr_in &addr, char *, int, int, string user, string passwd, string sqlname);
    void close_conn(bool real_close = true);
    void process();
    bool read_once();
    bool write();
    sockaddr_in *get_address()
    {
        return &m_address;
    }
    int timer_flag;
    int improv;


private:
    // 每个 handler 返回的 HTTP_CODE 决定 process_write 怎么生成响应
    typedef HTTP_CODE (http_conn::*Handler)();

    // 路由条目。post_only 用来把写接口锁成只收 POST。
    // 不区分方法的后果：GET /api/logout 也能登出，一个 <img src="/api/logout">
    // 就能把访客踢下线；写接口用 GET 也能提交，为 CSRF 打开方便之门。
    struct Route
    {
        Handler handler;
        bool post_only;
    };

    void init();
    HTTP_CODE process_read();
    bool process_write(HTTP_CODE ret);
    HTTP_CODE parse_request_line(char *text);
    HTTP_CODE parse_headers(char *text);
    HTTP_CODE parse_content(char *text);
    HTTP_CODE do_request();
    char *get_line() { return m_read_buf.data() + m_start_line; };
    LINE_STATUS parse_line();
    void unmap();
    bool add_response(const char *format, ...);
    bool add_content(const char *content);
    bool add_status_line(int status, const char *title);
    bool add_headers(int content_length);
    bool add_content_type();
    // 静态文件按扩展名定 Content-Type（见 http_conn.cpp 里的 content_type_for）
    bool add_content_type_for(const char *path);
    bool add_content_length(int content_length);
    bool add_linger();
    bool add_extra_headers();
    bool add_blank_line();

    // 读缓冲按需翻倍，到达 MAX_READ_BUFFER 后返回 false
    bool grow_read_buf();

    // 路由：URL 路径 -> 处理函数 + 方法要求
    static const std::map<std::string, Route> &route_table();
    // 从 Cookie 里取出 session，解析成 m_user_id（未登录为 -1）
    void load_session();
    // 建会话并把 Set-Cookie 放进响应头
    void start_session(int user_id);
    // 取一个表单参数（POST 体和 URL 查询串共用，缺省返回空串）
    std::string get_param(const char *name) const;

    // 写接口的 CSRF 第二道防线：Origin 头必须指向本站。
    // 没有 Origin 头（curl/压测工具/老客户端）视为无浏览器上下文，放行。
    bool origin_ok() const;

    // 执行一条写/查语句，失败记日志返回 false。
    // 只做"C 风格 API 的错误检查"这一件事，避免每个 handler 重复 6 行样板。
    bool db_exec(const std::string &sql);

    // 动态响应。status/title 可省略，默认 200 OK。
    // 动态内容一律走 m_iv[1]，不能走 add_content()（那会写爆 1024 字节的 m_write_buf）。
    HTTP_CODE dynamic_html(const std::string &html, int status = 200, const char *title = NULL);
    // 302 跳转：Location 放进额外响应头，body 留一个给 curl/无 JS 环境的链接
    HTTP_CODE redirect_to(const std::string &location);
    // 未登录访问写接口时的统一拒绝（401）
    HTTP_CODE require_login();

    // 账号
    HTTP_CODE handle_login();
    HTTP_CODE handle_register();
    HTTP_CODE handle_logout();
    HTTP_CODE handle_whoami();

    // 论坛业务
    HTTP_CODE handle_article_create();
    HTTP_CODE handle_article_list();
    HTTP_CODE handle_article_detail();
    HTTP_CODE handle_comment_create();
    HTTP_CODE handle_follow();
    HTTP_CODE handle_unfollow();
    HTTP_CODE handle_feed();
    HTTP_CODE handle_profile();

    // 静态文件
    HTTP_CODE serve_static();
    HTTP_CODE serve_file(const char *relative_path);
    HTTP_CODE map_file_to_response();

public:
    static int m_epollfd;
    static int m_user_count;
    MYSQL *mysql;
    int m_state;  //读为0, 写为1

private:
    int m_sockfd;
    sockaddr_in m_address;
    // 读缓冲：改成按需增长的堆缓冲。
    // 一是为了让 POST 正文不再受 2048 字节限制，二是 http_conn 数组是按
    // MAX_FD(65536) 一次性 new 出来的，固定数组会白白常驻几百 MB。
    std::vector<char> m_read_buf;
    long m_read_idx;
    long m_checked_idx;
    int m_start_line;
    char m_write_buf[WRITE_BUFFER_SIZE];
    int m_write_idx;
    CHECK_STATE m_check_state;
    METHOD m_method;
    char m_real_file[FILENAME_LEN];
    // 请求行/请求头的解析结果：一律【拷贝】成 std::string，不保存指向
    // m_read_buf 的裸指针。m_read_buf 会按需扩容，resize() 一旦重新分配内存，
    // 指向旧缓冲的指针立刻悬空，而 do_request() 恰恰是在扩容之后才用 m_url
    // 查路由的（详见 parse_request_line 上的说明）。
    std::string m_url;
    std::string m_version;
    std::string m_host;
    long m_content_length;
    bool m_linger;
    char *m_file_address;
    struct stat m_file_stat;
    struct iovec m_iv[2];
    int m_iv_count;
    int cgi; //是否启用的POST
    int bytes_to_send;
    int bytes_have_send;
    char *doc_root;

    // 本次请求的响应体。静态文件指向 mmap 的地址，动态内容指向 m_dyn_body，
    // write() 靠它重算 iov[1]，所以两种响应可以共用一套发送逻辑。
    char *m_body_ptr;

    // 请求解析结果
    std::string m_path;  // 去掉查询串后的 URL 路径
    std::map<std::string, std::string> m_post; // POST 表单 + URL 查询参数

    // 会话
    std::string m_session_id;
    int m_user_id; // 未登录为 -1

    // Origin 请求头，用来判断写请求是不是从本站页面发出的（防 CSRF）。
    // 非浏览器客户端（curl）不发这个头，此时按放行处理。
    std::string m_origin;

    // 响应
    std::string m_extra_headers; // 额外响应头（Set-Cookie、Location）
    std::string m_dyn_body;      // 动态响应体
    // 动态响应的状态行。默认 200，业务 handler 可以改成 302/400/401/404。
    // title 指向全局常量，生命周期比 http_conn 长，不需要拷贝。
    int m_resp_status;
    const char *m_resp_status_title;

    int m_TRIGMode;
    int m_close_log;

    char sql_user[100];
    char sql_passwd[100];
    char sql_name[100];
};

#endif
