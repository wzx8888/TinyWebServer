#include "html_util.h"

namespace
{
// 一次遍历完成转义，比连续 5 次 replace 快，也不会踩"二次转义"的坑。
// 扩容按输入大小预估：绝大多数内容里需要转义的字符很少，
// 直接 reserve(size + size/8) 通常一次就够，超了 string 自己会再扩。
const char *entity_for(char c)
{
    switch (c)
    {
    case '&':
        return "&amp;";
    case '<':
        return "&lt;";
    case '>':
        return "&gt;";
    case '"':
        return "&quot;";
    case '\'':
        // 单引号用 &#39; 而不是 &apos;，后者在 HTML4 里未定义
        return "&#39;";
    default:
        return NULL;
    }
}
} // namespace

std::string html_escape(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + in.size() / 8);

    for (size_t i = 0; i < in.size(); ++i)
    {
        const char *ent = entity_for(in[i]);
        if (ent != NULL)
            out += ent;
        else
            out.push_back(in[i]);
    }
    return out;
}

std::string html_nav(bool logged_in)
{
    std::string n;
    n += "<div class=\"nav\">";
    n += "<a href=\"/api/article/list\">论坛</a>";
    n += " | <a href=\"/api/feed\">关注流</a>";
    n += " | <a href=\"/api/profile\">我的主页</a>";
    if (logged_in)
        // 登出是要改状态的操作，必须是 POST，不能是一个 <a> 链接。
        // 用 GET 链接的话，别人在你页面里放个 <img src="/api/logout">
        // 就能把你踢下线。表单做成行内的，看起来还是个文字链接。
        n += " | <form action=\"/api/logout\" method=\"post\" class=\"inline\">"
             "<button type=\"submit\" class=\"linkish\">退出登录</button></form>";
    else
        n += " | <a href=\"/log.html\">登录</a>"
             " | <a href=\"/register.html\">注册</a>";
    n += "</div>";
    return n;
}

std::string html_time(const std::string &db_time)
{
    return html_escape(db_time);
}

std::string html_page(const std::string &title, const std::string &nav, const std::string &content)
{
    std::string p;
    p.reserve(content.size() + 700);

    p += "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n";
    p += "<meta charset=\"UTF-8\">\n";
    p += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    // title 来自调用方，可能是用户内容（如文章标题），必须转义
    p += "<title>" + html_escape(title) + "</title>\n";
    p += "<style>\n"
         "body{font-family:system-ui,-apple-system,\"Segoe UI\",\"Noto Sans CJK SC\",sans-serif;"
         "max-width:860px;margin:0 auto;padding:1em 1.2em;line-height:1.7;color:#222}\n"
         ".nav{background:#f4f4f5;padding:.6em .8em;border-radius:6px;margin-bottom:1.2em;"
         "font-size:.95em}\n"
         ".nav a{text-decoration:none;color:#1a5fb4}\n"
         "h1{font-size:1.5em;border-bottom:2px solid #eee;padding-bottom:.3em}\n"
         "h2{font-size:1.15em;margin-top:1.6em}\n"
         ".item{border-bottom:1px solid #eee;padding:.7em 0}\n"
         ".item .title{font-size:1.05em;font-weight:600;text-decoration:none;color:#1a5fb4}\n"
         ".meta{color:#666;font-size:.85em;margin-top:.2em}\n"
         ".content{white-space:pre-wrap;word-wrap:break-word;background:#fafafa;"
         "padding:.9em;border-radius:6px;margin:.8em 0}\n"
         ".cbox{background:#fafafa;border-left:3px solid #ccc;padding:.5em .8em;margin:.6em 0;"
         "border-radius:0 6px 6px 0}\n"
         ".cbox .who{font-weight:600;font-size:.9em}\n"
         ".cbox .txt{white-space:pre-wrap;word-wrap:break-word}\n"
         "textarea,input[type=text]{width:100%;box-sizing:border-box;padding:.5em;"
         "border:1px solid #ccc;border-radius:4px;font-family:inherit;font-size:1em}\n"
         "button{padding:.45em 1.1em;border:0;border-radius:4px;background:#1a5fb4;color:#fff;"
         "font-size:.95em;cursor:pointer;margin-top:.4em}\n"
         ".stat{display:inline-block;margin-right:1.5em;color:#444}\n"
         ".stat b{font-size:1.2em}\n"
         ".err{background:#fdecec;border:1px solid #f5c2c2;color:#a33;padding:.8em;border-radius:6px}\n"
         // 让"退出登录"这个 form 按钮看起来仍是一个文字链接
         "form.inline{display:inline;margin:0}\n"
         "button.linkish{background:none;border:0;color:#1a5fb4;cursor:pointer;"
         "font:inherit;padding:0;margin:0;text-decoration:none}\n"
         "</style>\n</head>\n<body>\n";
    p += nav;
    p += content;
    p += "\n</body>\n</html>\n";
    return p;
}
