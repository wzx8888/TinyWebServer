#include "config.h"
#include <cstdio>
#include <cstdlib>

// 数据库凭据从环境变量读取，源码里不留任何真实凭据。
//
// 上游原版把 user/passwd 直接硬编码在 main.cpp 里（root/root）。这个文件一旦
// 进了公开仓库，等于把库口令、库名、以及"哪台机器在用"一并交出去；而
// "提交前记得改回来"这种约定，靠人是守不住的。
//
//   MYSQL_USER  库账号（必填）
//   MYSQL_PWD   库口令（必填，沿用 mysql 客户端自己的变量名）
//   MYSQL_DB    库名（选填，默认 yourdb）
//
// 本地起服务用仓库根的 ./run-local.sh，它装着真实凭据且已在 .gitignore 里。
static const char *env_or_exit(const char *name)
{
    const char *v = getenv(name);
    if (v == NULL || *v == '\0')
    {
        fprintf(stderr,
                "启动失败：环境变量 %s 未设置。\n"
                "库凭据不再硬编码在源码里，请用仓库根的 ./run-local.sh 启动，\n"
                "或自行导出：export MYSQL_USER=... MYSQL_PWD=... MYSQL_DB=...\n",
                name);
        exit(1);
    }
    return v;
}

int main(int argc, char *argv[])
{
    //需要修改的数据库信息,登录名,密码,库名
    string user = env_or_exit("MYSQL_USER");
    string passwd = env_or_exit("MYSQL_PWD");
    const char *db_from_env = getenv("MYSQL_DB");
    string databasename = (db_from_env != NULL && *db_from_env != '\0')
                              ? db_from_env
                              : "yourdb";

    //命令行解析
    Config config;
    config.parse_arg(argc, argv);

    WebServer server;

    //初始化。注意这是【位置参数】—— 顺序必须与 webserver.h 的声明逐字对应，
    // 加参数时 config.h / config.cpp / main.cpp / webserver.h / webserver.cpp 五处一起改。
    server.init(config.PORT, user, passwd, databasename, config.LOGWrite,
                config.OPT_LINGER, config.TRIGMode,  config.sql_num,  config.thread_num,
                config.close_log, config.actor_model, config.LISTEN_ADDR);
    

    //日志
    server.log_write();

    //数据库
    server.sql_pool();

    //线程池
    server.thread_pool();

    //触发模式
    server.trig_mode();

    //监听
    server.eventListen();

    //运行
    server.eventLoop();

    return 0;
}
