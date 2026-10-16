#ifndef DB_TRANSACTION_H
#define DB_TRANSACTION_H

#include <mysql/mysql.h>

// 事务的 RAII 守卫（阶段 3.3）。
//
// 用法：
//     db_transaction tx(mysql);          // mysql 就是 http_conn::mysql
//     if (!tx.started()) return INTERNAL_ERROR;
//     ... 若干条写语句 ...
//     if (失败) return INTERNAL_ERROR;   // 直接 return，析构自动 ROLLBACK
//     if (!tx.commit()) return INTERNAL_ERROR;
//
// ============================================================
// 用之前必须知道的两件事
// ============================================================
// 1. 【必须用线程池已经取好的那条连接】
//    http_conn::mysql 是 threadpool 在调 process() 之前用 connectionRAII
//    取好并交给本次请求的连接。事务必须整段跑在这【一条】连接上。
//    如果中途自己去连接池再取一条（connectionRAII 局部变量），
//    START TRANSACTION 开在 A 上、后续语句写在 B 上，
//    结果是"事务静默失效"：不报错、不生效，最难查的一类 bug。
//
// 2. 【构造前不能有未消费的结果集】
//    本类只发 START TRANSACTION / COMMIT / ROLLBACK，不碰结果集。
//    如果调用方之前用 mysql_query 发过 SELECT 却没 mysql_store_result，
//    连接的状态是"命令不同步"，这里的 START TRANSACTION 会直接失败
//    （2014 Commands out of sync）。失败时 started() 返回 false，
//    调用方应据此放弃并返回 500，而不是假装事务已经开着继续写。
//
// 为什么要有它：靠"记得在每条 return 前写 ROLLBACK"是不可靠的，
// 漏一个分支就等于把半截数据留在库里。让析构去兜底才不会有漏网之鱼。
class db_transaction
{
public:
    explicit db_transaction(MYSQL *conn)
        : m_conn(conn), m_open(false), m_done(false)
    {
        if (m_conn != NULL && mysql_query(m_conn, "START TRANSACTION") == 0)
            m_open = true;
    }

    // 没有显式 commit 就析构 = 中途 return 或抛异常，一律回滚
    ~db_transaction()
    {
        if (m_open && !m_done)
            mysql_query(m_conn, "ROLLBACK");
    }

    // 事务是否真的开起来了。开了才有"回滚"这回事，
    // 没开就必须让上层报错，不能当没事发生。
    bool started() const { return m_open; }

    bool commit()
    {
        if (!m_open || m_done)
            return false;
        if (mysql_query(m_conn, "COMMIT") != 0)
            return false; // 保持 m_done=false，析构会再补一次 ROLLBACK
        m_done = true;
        return true;
    }

    void rollback()
    {
        if (m_open && !m_done)
        {
            mysql_query(m_conn, "ROLLBACK");
            m_done = true;
        }
    }

private:
    // 事务句柄不该被拷贝/赋值：拷贝出来的副本析构时会多做一次 ROLLBACK
    db_transaction(const db_transaction &);
    db_transaction &operator=(const db_transaction &);

    MYSQL *m_conn;
    bool m_open;
    bool m_done;
};

#endif
