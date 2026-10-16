#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <ctime>
#include <string>
#include <unordered_map>

#include "../lock/locker.h"

// 会话表：session_id -> user_id，进程内单例，所有 IO 线程共享，内部加锁。
//
// 注意两点：
//   1. 会话只存在内存里，服务重启后全部失效，用户需要重新登录；
//   2. 会话表不落盘，也不做跨进程共享，所以服务只能单实例部署。
class session_manager
{
public:
    // 会话空闲超过该秒数视为失效；浏览器端 Cookie 的 Max-Age 用同一个值
    static const int DEFAULT_TTL = 24 * 3600;

    // 两次全表清理之间的最小间隔（秒）。
    // 每次登录都扫一遍全表是 O(n)：n 到十万级时，每次登录都要在持锁状态下
    // 遍历十万个节点，登录会被自己拖慢，而这个锁是所有 IO 线程共用的。
    // 清过期会话本来就不要求实时，节流到一分钟一次，代价可以忽略。
    static const int PURGE_INTERVAL = 60;

    // 会话数硬上限。达到它就强制清理；清完还满就淘汰最久未活动的那条。
    // 有上限是必须的：TTL 清理只在"还有新登录"时才被触发，
    // 全是过期会话的表如果不设上限，就会一直占着内存不放。
    static const size_t MAX_SESSIONS = 100000;

    static session_manager *get_instance();

    // 登录/注册成功后调用，返回新的 session_id；生成失败返回空串
    std::string create_session(int user_id);
    // 会话不存在或已过期返回 -1
    int get_user_id(const std::string &session_id);
    void destroy_session(const std::string &session_id);

    void set_ttl(int ttl) { m_ttl = ttl; }
    size_t size();

private:
    session_manager();
    ~session_manager();
    // 单例不允许拷贝
    session_manager(const session_manager &);
    session_manager &operator=(const session_manager &);

    std::string gen_session_id();
    void purge_expired_locked();
    // 超过 MAX_SESSIONS 时淘汰最久未活动的一条（调用方必须已持锁）
    void evict_oldest_locked();

    struct entry
    {
        int user_id;
        time_t last_active;
        // 单调递增的访问序号，用来给 last_active 打平手的情况定序。
        // time() 只有秒级精度，同一秒内建起来的一批会话 last_active 完全相同，
        // 光比时间的话"淘汰最久未活动的那条"会退化成按 unordered_map 的遍历顺序挑，
        // 等于随机淘汰。而表被撑满恰恰最容易发生在登录突发（全在同一秒）的时候，
        // 所以这个 tiebreaker 不是理论问题。
        unsigned long long seq;
    };

    std::unordered_map<std::string, entry> m_sessions;
    locker m_lock;
    int m_ttl;
    // 上次全表清理的时间。初值给 0，保证第一次登录一定会清一次。
    time_t m_last_purge;
    // 访问序号发号器，只增不减；unsigned long long 不会绕回
    unsigned long long m_seq;
};

#endif
