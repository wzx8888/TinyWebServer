#ifndef FORM_PARSER_H
#define FORM_PARSER_H

#include <map>
#include <string>

// URL 解码：'%XX' 还原成字节，'+' 还原成空格。
// 解码结果中若出现 '\0'，或 '%' 后面不是合法的两位十六进制，返回 false。
bool url_decode(const std::string &in, std::string &out);

// 解析 application/x-www-form-urlencoded 请求体（Content-Length 可能大于 strlen，
// 所以必须显式传长度）。
// 规则：按 '&' 分隔字段；每对按【第一个】'=' 切成 key/value（value 里允许出现 '='）；
//       key 和 value 都做 URL 解码；空字段、解码失败的字段、空 key 一律丢弃。
std::map<std::string, std::string> parse_form(const char *body, size_t len);

// 从 Cookie 请求头里取出指定 cookie 的值。按 ';' 分段后精确匹配 cookie 名，
// 不会把 "XSID" 误配成 "SID"。找不到返回空串。
std::string cookie_value(const std::string &cookie_header, const std::string &name);

#endif
