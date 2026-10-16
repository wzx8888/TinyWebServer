#ifndef HTML_UTIL_H
#define HTML_UTIL_H

#include <string>

// HTML 输出转义。
// 凡是把【用户产生的内容】（标题、正文、评论、用户名）渲染进页面的地方，
// 都必须先过这个函数，否则就是存储型 XSS：
// 用户在标题里写 <script>...</script>，别人的浏览器就会执行它。
//
// 转义 5 个字符：& < > " '
// 注意 & 必须第一个替换，否则会把后面替换出来的实体二次转义
// （"<" -> "&lt;" 若在 & 之后处理，就会变成 "&amp;lt;"）。
std::string html_escape(const std::string &in);

// 统一的页面外壳，避免每个 handler 各写一套 <html><head>...
// title 会转义；content 是【已经拼好的 HTML】，由调用方负责转义其中的用户内容。
std::string html_page(const std::string &title, const std::string &nav, const std::string &content);

// 顶部导航。按登录状态给出不同的链接组。
std::string html_nav(bool logged_in);

// 把 DATETIME 字符串（"2026-10-16 20:29:04"）原样安全嵌入。
// 值来自 MySQL 的 DATETIME 列，格式固定，但仍然过一遍转义以防万一。
std::string html_time(const std::string &db_time);

#endif
