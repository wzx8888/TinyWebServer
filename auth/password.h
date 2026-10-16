#ifndef PASSWORD_H
#define PASSWORD_H

#include <string>

// 口令散列。用 libcrypt 提供的 bcrypt（$2b$），不自己实现密码学原语。
//
// 为什么从"迭代式 SHA256"换成 bcrypt（这是 2026-10-16 的改动）：
//   迭代式 SHA256 只把单次尝试的成本抬高若干个数量级，但它的每一步都是
//   纯整数运算、几十字节的状态，正好是 GPU/ASIC 最擅长的形状 ——
//   一块显卡每秒仍能试上十亿次量级。bcrypt 走的是另一条路：它的核心
//   Blowfish key schedule 有 4KB 状态、要反复读写，并且 cost 每加 1
//   就把工作量翻倍。这挡住了"用并行硬件换时间"的路线。
//   业界更强的是 argon2id（内存硬，能进一步挡住 ASIC），但本机只有
//   libargon2 的运行库、没有头文件，装 libargon2-dev 需要联网装包；
//   而 libcrypt 的 crypt() 已经原生支持 $2b$，零新依赖。
//
// 存储形态变了：bcrypt 的散列串自带算法标识、cost 和 salt，是自描述的 ——
//   $2b$10$AhAC8I.IpxpscPoyurl.X.ZzwYajh5tHIjelfxb30rIJ5FO1PI7gO
//   └┬─┘└┬┘└─────────┬──────────┘└──────────────┬───────────────┘
//  算法 cost     22 字符 salt               31 字符散列
// 所以不再需要单独一列存 salt，"明文列 + salt 列 + hash 列"收敛成了一列。
namespace password
{

// bcrypt 的 cost 因子：工作量 = 2^cost 轮。
// 10 是 OWASP 给 bcrypt 的下限，单次约 50~80ms。
// 这个数字是"抗暴力破解"和"登录延迟"之间的取舍点：
//   调大到 12 会让每次登录多 4 倍等待，调小到 8 则加速 4 倍破解。
const int BCRYPT_COST = 10;

// bcrypt 只取口令的前 72 字节，超出部分被【静默忽略】。
// 这一点必须由调用方守住，否则 "前 72 字节对上了就能登录"。
// 本项目的上限是 64 字节（见 http_conn.cpp 的 PASSWORD_MAX），留有余量。
const size_t MAX_PLAINTEXT = 72;

// 生成散列，返回形如 "$2b$10$...." 的 60 字符自描述串。
// 空口令、超过 MAX_PLAINTEXT、拿不到随机源、libcrypt 报错时均返回空串。
// 调用方必须把空串当成错误处理，绝不能写进库 —— 那会留下一条
// "谁也登录不上"（或者更糟，被当成合法散列）的记录。
// 注意与旧实现的行为差异：旧的 SHA256 版本不可能失败，调用方原本
// 只需要防 gen_salt() 失败；现在 hash() 本身也会失败。
std::string hash(const std::string &plain);

// 用库里那串散列重算一遍再比对。
// stored 为空、格式非法、口令为空或超过 MAX_PLAINTEXT 时一律返回 false。
bool verify(const std::string &plain, const std::string &stored);

// 定长比较两个字符串，不因"第几个字节开始不同"而提前返回。
// 普通 == 会在第一个不同的字节处短路。这里比的是两个散列串而不是口令本身，
// 时序泄漏的实际危害小得多，但既然代价只是一个不复用 ==，就没必要省。
bool ct_equal(const std::string &a, const std::string &b);

} // namespace password

#endif
