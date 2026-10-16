// _GNU_SOURCE 必须出现在任何 #include 之前。
// crypt_gensalt_rn() 是 glibc/libxcrypt 的 GNU 扩展，在 -std=c++11 这种
// 严格模式下不会自动声明 —— 不定义它，编译期会报"未声明标识符"，
// 而不是给出一个能用的默认实现。
#define _GNU_SOURCE

#include "password.h"

#include <crypt.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

namespace password
{

namespace
{

// 从 /dev/urandom 读一批随机字节。失败返回 false。
// 不走 rand()/time()：那些是可预测的，salt 可预测等于没有 salt。
bool random_bytes(unsigned char *buf, size_t len)
{
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp == NULL)
        return false;

    size_t got = 0;
    while (got < len)
    {
        size_t n = fread(buf + got, 1, len - got, fp);
        if (n == 0)
        {
            // 区分"被信号打断"和"真的读不到"：前者重试，后者失败。
            if (ferror(fp) && errno == EINTR)
            {
                clearerr(fp);
                continue;
            }
            fclose(fp);
            return false;
        }
        got += n;
    }

    fclose(fp);
    return true;
}

// crypt_r 需要一个 struct crypt_data 工作区，它约 32KB。
// 放在栈上会在每个 handler 帧里压 32KB，而线程池的栈大小不是我们能假定的；
// 用 thread_local 则每个工作线程一份，既避免了每次分配，也天然线程安全。
//
// 为什么必须用 crypt_r 而不是 crypt：
//   crypt() 把结果放在一个【静态缓冲】里。本服务是 8 线程的线程池，
//   两个线程同时登录会互相覆盖返回值 —— 表现是"偶发登录失败/成功"，
//   而且是并发压力下才出现，极难复现。
struct CryptWorkspace
{
    struct crypt_data data;

    CryptWorkspace() { memset(&data, 0, sizeof(data)); }
};

CryptWorkspace &workspace()
{
    static thread_local CryptWorkspace ws;
    return ws;
}

} // namespace

std::string hash(const std::string &plain)
{
    // 空口令在这里拒绝，而不是"照常算出一个合法散列，由上层决定收不收"。
    // 理由：允许它算出来，就等于允许库里存在一条"空口令可登录"的记录，
    // 而这条记录从散列串本身完全看不出来 —— 校验方拿到的是一串标准的 60 字符。
    // verify() 也是拒绝空口令的，两边必须一致，否则会出现
    // "写得进库但验不过"这种只能靠线上现象才发现的不对称。
    if (plain.empty())
    {
        fprintf(stderr, "password::hash: empty plaintext refused\n");
        return std::string();
    }

    if (plain.size() > MAX_PLAINTEXT)
    {
        // 宁可失败也不静默截断：bcrypt 只会取前 72 字节，
        // 静默截断意味着两个不同口令可能得到同一个散列。
        fprintf(stderr, "password::hash: plaintext too long (%zu > %zu)\n",
                plain.size(), MAX_PLAINTEXT);
        return std::string();
    }

    unsigned char rnd[16];
    if (!random_bytes(rnd, sizeof(rnd)))
    {
        fprintf(stderr, "password::hash: cannot read /dev/urandom: %s\n",
                strerror(errno));
        return std::string();
    }

    // 产出 "$2b$10$" + 22 字符 salt。cost 直接交给它，
    // 不要自己拼字符串 —— salt 的字母表是 bcrypt 自己的 base64，
    // 不是标准 base64，拼错了 crypt_r 会返回 "*0" 而不会报错。
    char salt[CRYPT_GENSALT_OUTPUT_SIZE];
    if (crypt_gensalt_rn("$2b$", BCRYPT_COST, (const char *)rnd, sizeof(rnd),
                         salt, sizeof(salt)) == NULL)
    {
        fprintf(stderr, "password::hash: crypt_gensalt_rn failed: %s\n",
                strerror(errno));
        return std::string();
    }

    // 工作区每次清空：libxcrypt 复用工作区时依赖内部状态，
    // 从头开始是唯一不需要研究其实现细节就正确的做法。
    // 32KB 的 memset 相对 50ms 的 bcrypt 可以忽略。
    CryptWorkspace &ws = workspace();
    memset(&ws.data, 0, sizeof(ws.data));

    char *out = crypt_r(plain.c_str(), salt, &ws.data);
    // crypt_r 出错时返回 NULL，或者返回以 '*' 开头的串（"*0"/"*1"）。
    // 只判 NULL 会漏掉后一种，把 "*0" 当成合法散列写进库，
    // 而任何口令都无法匹配 "*0"，那个账号会永久登录不上。
    if (out == NULL || out[0] == '*')
    {
        fprintf(stderr, "password::hash: crypt_r failed: %s\n", strerror(errno));
        return std::string();
    }

    return std::string(out);
}

bool verify(const std::string &plain, const std::string &stored)
{
    if (plain.empty() || stored.empty())
        return false;

    // 这条检查是防"截断绕过"：如果库里存的散列是 72 字节口令算出来的，
    // 而攻击者提交一个前 72 字节相同、后面随便加东西的口令，
    // bcrypt 会截断成一样的内容从而通过校验。
    if (plain.size() > MAX_PLAINTEXT)
        return false;

    // 先把格式挡掉再算。格式不对时 crypt_r 的行为是"返回一个看起来
    // 正常的串"，白花 50ms 才失败；而格式不对本身就说明这条记录不可用。
    if (stored.size() < 4 || stored[0] != '$')
        return false;

    CryptWorkspace &ws = workspace();
    memset(&ws.data, 0, sizeof(ws.data));

    char *out = crypt_r(plain.c_str(), stored.c_str(), &ws.data);
    if (out == NULL || out[0] == '*')
        return false;

    return ct_equal(std::string(out), stored);
}

bool ct_equal(const std::string &a, const std::string &b)
{
    // 长度不同直接返回。长度本身不是秘密（这里比的是定长散列串，
    // 长度恒为 60），所以这个提前返回不构成泄漏。
    if (a.size() != b.size())
        return false;

    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (unsigned char)(a[i] ^ b[i]);

    return diff == 0;
}

} // namespace password
