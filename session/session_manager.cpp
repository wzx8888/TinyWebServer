#include "session_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../log/log.h"

// log.h 里的 LOG_* 宏依赖成员变量 m_close_log，这里不在任何类里，
// 所以直接调 write_log。
static void sess_log_error(const char *format, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    Log::get_instance()->write_log(3, "%s", buf);
    Log::get_instance()->flush();
}

session_manager *session_manager::get_instance()
{
    // C++11 保证函数内静态变量的初始化是线程安全的
    static session_manager instance;
    return &instance;
}

session_manager::session_manager()
{
    m_ttl = DEFAULT_TTL;
    m_last_purge = 0;
    m_seq = 0;
    m_sessions.reserve(1024);
}

session_manager::~session_manager()
{
}

// 从内核随机源取 32 字节并编码成 64 个十六进制字符。
// 不能用 rand()/time() 拼，那样可以被预测，等于没有会话保护。
std::string session_manager::gen_session_id()
{
    unsigned char buf[32];

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        sess_log_error("open /dev/urandom error: %s", strerror(errno));
        return std::string();
    }

    size_t got = 0;
    while (got < sizeof(buf))
    {
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            sess_log_error("read /dev/urandom error: %s", strerror(errno));
            close(fd);
            return std::string();
        }
        if (n == 0)
        {
            sess_log_error("read /dev/urandom got EOF");
            close(fd);
            return std::string();
        }
        got += (size_t)n;
    }
    close(fd);

    static const char *hex = "0123456789abcdef";
    std::string id;
    id.reserve(sizeof(buf) * 2);
    for (size_t i = 0; i < sizeof(buf); ++i)
    {
        id.push_back(hex[buf[i] >> 4]);
        id.push_back(hex[buf[i] & 0x0f]);
    }
    return id;
}

// 调用方必须已经持有 m_lock
void session_manager::purge_expired_locked()
{
    if (m_ttl <= 0)
        return;

    time_t now = time(NULL);
    std::unordered_map<std::string, entry>::iterator it = m_sessions.begin();
    while (it != m_sessions.end())
    {
        if (now - it->second.last_active > m_ttl)
            it = m_sessions.erase(it);
        else
            ++it;
    }
    m_last_purge = now;
}

// 调用方必须已经持有 m_lock，并且已经尝试过 purge_expired_locked()
void session_manager::evict_oldest_locked()
{
    if (m_sessions.empty())
        return;

    // 只有"表已经撑到上限"这一条路径会走到这里，
    // 为了它把 last_active 维护成有序结构（堆/链表）不值得，线性扫一次即可。
    // 比较用 (last_active, seq)：秒级时间戳打平手时，seq 小的是更早被访问过的，
    // 这样"淘汰最久未活动的一条"才有确定含义，而不是按哈希表遍历顺序随机挑。
    std::unordered_map<std::string, entry>::iterator oldest = m_sessions.begin();
    for (std::unordered_map<std::string, entry>::iterator it = m_sessions.begin();
         it != m_sessions.end(); ++it)
    {
        if (it->second.last_active < oldest->second.last_active ||
            (it->second.last_active == oldest->second.last_active &&
             it->second.seq < oldest->second.seq))
            oldest = it;
    }

    sess_log_error("session table full (%zu), evicting the oldest entry",
                   MAX_SESSIONS);
    m_sessions.erase(oldest);
}

std::string session_manager::create_session(int user_id)
{
    std::string id = gen_session_id();
    if (id.empty())
        return id;

    m_lock.lock();

    // 两种情况必须立刻清理，不受节流限制：
    //   1. 距离上次清理已经超过 PURGE_INTERVAL；
    //   2. 表已经达到硬上限（继续塞会把内存吃光）。
    time_t now = time(NULL);
    if (now - m_last_purge >= PURGE_INTERVAL || m_sessions.size() >= MAX_SESSIONS)
        purge_expired_locked();

    // 清完过期会话还是满的，说明活跃会话确实达到了上限，
    // 这时候淘汰最久未活动的一条，而不是把新登录的用户挡在门外 ——
    // 拒绝登录等于用"可用性"换"内存"，淘汰一条旧会话的影响面小得多。
    if (m_sessions.size() >= MAX_SESSIONS)
        evict_oldest_locked();

    entry e;
    e.user_id = user_id;
    e.last_active = now;
    e.seq = ++m_seq;
    m_sessions[id] = e;

    m_lock.unlock();
    return id;
}

int session_manager::get_user_id(const std::string &session_id)
{
    if (session_id.empty())
        return -1;

    m_lock.lock();

    std::unordered_map<std::string, entry>::iterator it = m_sessions.find(session_id);
    if (it == m_sessions.end())
    {
        m_lock.unlock();
        return -1;
    }

    if (m_ttl > 0 && (time(NULL) - it->second.last_active) > m_ttl)
    {
        m_sessions.erase(it);
        m_lock.unlock();
        return -1;
    }

    it->second.last_active = time(NULL);
    it->second.seq = ++m_seq;   // 续期同样要更新序号，否则 LRU 会看错
    int uid = it->second.user_id;

    m_lock.unlock();
    return uid;
}

void session_manager::destroy_session(const std::string &session_id)
{
    if (session_id.empty())
        return;

    m_lock.lock();
    m_sessions.erase(session_id);
    m_lock.unlock();
}

size_t session_manager::size()
{
    m_lock.lock();
    size_t n = m_sessions.size();
    m_lock.unlock();
    return n;
}
