#ifndef SQL_UTIL_H
#define SQL_UTIL_H

#include <mysql/mysql.h>
#include <cerrno>
#include <cstdlib>
#include <string>

// 把字符串转义成可以安全放进单引号之间的形式，防 SQL 注入。
// 前提：连接必须已经设置好字符集（见 connection_pool::init 里的 mysql_options），
// 否则多字节字符的转义结果可能不正确。调用前确认 conn != NULL。
inline std::string sql_escape(MYSQL *conn, const std::string &s)
{
    if (conn == NULL || s.empty())
        return std::string();

    // 最坏情况下每个字节膨胀成两个字符（\" 等），再留一个结束位
    std::string out(s.size() * 2 + 1, '\0');
    unsigned long n = mysql_real_escape_string(conn, &out[0], s.c_str(), s.size());
    out.resize(n);
    return out;
}

// 数字型参数一律先转成整数再拼进 SQL，而不是直接拼字符串。
// 转换失败返回 def，调用方据此拒绝请求。
inline long long to_ll(const std::string &s, long long def = -1)
{
    if (s.empty())
        return def;

    errno = 0;
    char *end = NULL;
    long long v = strtoll(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0')
        return def;
    return v;
}

#endif
