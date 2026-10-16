#include "form_parser.h"

static int hex_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool url_decode(const std::string &in, std::string &out)
{
    out.clear();
    out.reserve(in.size());

    for (size_t i = 0; i < in.size(); ++i)
    {
        char c = in[i];
        if (c == '+')
        {
            out.push_back(' ');
        }
        else if (c == '%')
        {
            // %XX 必须凑够两个十六进制字符
            if (i + 2 >= in.size())
                return false;
            int hi = hex_val(in[i + 1]);
            int lo = hex_val(in[i + 2]);
            if (hi < 0 || lo < 0)
                return false;

            char decoded = (char)((hi << 4) | lo);
            // %00 会让后续的 C 字符串处理被截断，直接拒绝
            if (decoded == '\0')
                return false;
            out.push_back(decoded);
            i += 2;
        }
        else if (c == '\0')
        {
            // 请求体里夹了裸的 NUL 字节，按构造请求处理
            return false;
        }
        else
        {
            out.push_back(c);
        }
    }
    return true;
}

std::map<std::string, std::string> parse_form(const char *body, size_t len)
{
    std::map<std::string, std::string> form;
    if (body == NULL || len == 0)
        return form;

    size_t pos = 0;
    while (pos < len)
    {
        // 找到本字段的结尾 '&'
        size_t amp = pos;
        while (amp < len && body[amp] != '&')
            ++amp;

        // 只在【第一个】'=' 处切分，value 里的 '=' 原样保留
        size_t eq = pos;
        while (eq < amp && body[eq] != '=')
            ++eq;

        std::string raw_key(body + pos, eq - pos);
        std::string raw_val;
        if (eq < amp)
            raw_val.assign(body + eq + 1, amp - eq - 1);

        std::string key, val;
        if (!raw_key.empty() && url_decode(raw_key, key) &&
            url_decode(raw_val, val) && !key.empty())
        {
            form[key] = val;
        }

        if (amp >= len)
            break;
        pos = amp + 1;
    }
    return form;
}

std::string cookie_value(const std::string &cookie_header, const std::string &name)
{
    size_t pos = 0;
    while (pos < cookie_header.size())
    {
        size_t semi = cookie_header.find(';', pos);
        if (semi == std::string::npos)
            semi = cookie_header.size();

        size_t start = cookie_header.find_first_not_of(" \t", pos);
        if (start != std::string::npos && start < semi)
        {
            size_t eq = cookie_header.find('=', start);
            if (eq != std::string::npos && eq < semi)
            {
                // 精确比较 cookie 名
                if (cookie_header.compare(start, eq - start, name) == 0)
                {
                    size_t vstart = eq + 1;
                    size_t vend = semi;
                    while (vend > vstart &&
                           (cookie_header[vend - 1] == ' ' || cookie_header[vend - 1] == '\t'))
                        --vend;
                    return cookie_header.substr(vstart, vend - vstart);
                }
            }
        }

        if (semi >= cookie_header.size())
            break;
        pos = semi + 1;
    }
    return std::string();
}
