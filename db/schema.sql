-- TinyWebServer 论坛业务表结构
-- 目标库：yourdb   MySQL 8.0（依赖 utf8mb4_0900_ai_ci 排序规则与 DATETIME DEFAULT CURRENT_TIMESTAMP）
--
-- 本文件分两部分：
--   1. 全新部署时的建表语句（4 张表）
--   2. user 表从旧结构迁移过来的历史 ALTER 语句（已执行，仅作留档，不要重复执行）
--
-- 关系：
--   user 1 --- n article   一个用户发多篇文章
--   user 1 --- n comment   一个用户发多条评论
--   article 1 - n comment  一篇文章有多条评论
--   user n --- n user      用户互相关注（多对多自关联，落在 follow 表）

SET NAMES utf8mb4;

-- ============================================================
-- 一、全新部署建表
-- ============================================================

-- ① user 用户表
--
-- 口令只存一列，内容是 bcrypt 的自描述散列串（60 字符）：
--   $2b$10$AhAC8I.IpxpscPoyurl.X.ZzwYajh5tHIjelfxb30rIJ5FO1PI7gO
--    └┬─┘└┬┘└─────────┬──────────┘└──────────────┬───────────────┘
--   算法 cost    22 字符 salt              31 字符散列
-- 算法标识、cost、salt 都在串里，所以不需要单独的 salt 列，也就不可能
-- 出现"散列写了、salt 忘了写"这种只能靠人工检查发现的错配。
--
-- 列宽 100 而不是精确的 60：留出换算法的余地（argon2id 的串约 96 字符），
-- 到时候不必再 ALTER 一次表。
--
-- 历史沿革（见文件末尾的迁移留档）：
--   最早是 passwd 一列明文 → 加 passwd_salt + passwd_hash 走"首次登录顺手迁移"
--   → 现在明文列与 salt 列都已删除，库里没有任何明文存储的可能。
CREATE TABLE IF NOT EXISTS `user` (
  `user_id`     BIGINT       NOT NULL AUTO_INCREMENT,
  `username`    VARCHAR(64)  NOT NULL,
  `passwd_hash` VARCHAR(100) NOT NULL COMMENT 'bcrypt 自描述散列串（$2b$cost$salt+hash）',
  `email`       VARCHAR(128) DEFAULT NULL,
  `status`      TINYINT      NOT NULL DEFAULT 1,
  `create_time` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `uk_username` (`username`),
  -- email 允许 NULL；MySQL 唯一索引允许多个 NULL，正好符合"邮箱可不填"的需求
  UNIQUE KEY `uk_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ② article 文章表
CREATE TABLE IF NOT EXISTS `article` (
  `article_id`  BIGINT       NOT NULL AUTO_INCREMENT,
  `user_id`     BIGINT       NOT NULL,
  `title`       VARCHAR(255) NOT NULL,
  `content`     TEXT         NOT NULL,
  `view_count`  INT          NOT NULL DEFAULT 0,
  `create_time` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`article_id`),
  -- 服务"查某人的文章"与"关注流"（都要 WHERE user_id=? ORDER BY create_time DESC）
  KEY `idx_user_time` (`user_id`, `create_time`),
  -- 服务首页列表"ORDER BY create_time DESC LIMIT 20 OFFSET n"。
  -- 没有这个索引时 MySQL 要全表扫 + filesort 才能取前 20 行，这是论坛最热的查询。
  KEY `idx_create_time` (`create_time`),
  CONSTRAINT `fk_article_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ③ comment 评论表
CREATE TABLE IF NOT EXISTS `comment` (
  `comment_id`  BIGINT        NOT NULL AUTO_INCREMENT,
  `article_id`  BIGINT        NOT NULL,
  `user_id`     BIGINT        NOT NULL,
  `content`     VARCHAR(1000) NOT NULL,
  `create_time` DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`comment_id`),
  -- 服务文章详情页的评论列表：WHERE article_id=? ORDER BY create_time
  KEY `idx_article_time` (`article_id`, `create_time`),
  -- 服务"我发过的评论"以及按用户统计
  KEY `idx_user_time` (`user_id`, `create_time`),
  CONSTRAINT `fk_comment_article` FOREIGN KEY (`article_id`) REFERENCES `article` (`article_id`),
  CONSTRAINT `fk_comment_user`    FOREIGN KEY (`user_id`)    REFERENCES `user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ④ follow 关注表（多对多自关联）
CREATE TABLE IF NOT EXISTS `follow` (
  `follower_id` BIGINT   NOT NULL,
  `followee_id` BIGINT   NOT NULL,
  `create_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- 联合主键天然防止重复关注：重复 INSERT 直接报 1062，配合 INSERT IGNORE 做成幂等
  PRIMARY KEY (`follower_id`, `followee_id`),
  -- 主键的最左前缀是 follower_id，"查我的粉丝"（WHERE followee_id=?）
  -- 用不上主键，必须单独建这个索引，否则全表扫
  KEY `idx_followee` (`followee_id`),
  -- 自关联：两列都指向 user(user_id)，所以约束名必须不同
  CONSTRAINT `fk_follow_follower` FOREIGN KEY (`follower_id`) REFERENCES `user` (`user_id`),
  CONSTRAINT `fk_follow_followee` FOREIGN KEY (`followee_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 外键一律使用默认的 RESTRICT：删除还有文章/评论/关注关系的用户会被数据库拒绝，
-- 避免误删导致内容静默丢失。需要注销用户时应在应用层走软删除（user.status）。


-- ============================================================
-- 二、历史迁移记录（已执行，勿重复执行）
-- ============================================================
-- 迁移前的 user 表只有两列，无主键无唯一键、密码明文：
--   username char(50) DEFAULT NULL, passwd char(50) DEFAULT NULL
--
-- ALTER TABLE user ADD COLUMN user_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;
-- ALTER TABLE user MODIFY username VARCHAR(64) NOT NULL;
-- ALTER TABLE user ADD UNIQUE KEY uk_username (username);
-- ALTER TABLE user ADD COLUMN email VARCHAR(128) NULL;
-- ALTER TABLE user ADD UNIQUE KEY uk_email (email);
-- ALTER TABLE user ADD COLUMN status TINYINT NOT NULL DEFAULT 1;
-- ALTER TABLE user ADD COLUMN create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
-- ALTER TABLE user MODIFY passwd VARCHAR(64) NOT NULL;
--
-- 第二阶段（口令从明文改为散列存储）的三条 ALTER，已执行：
-- ALTER TABLE user ADD COLUMN passwd_salt CHAR(32) NULL COMMENT '16 字节随机 salt 的十六进制';
-- ALTER TABLE user ADD COLUMN passwd_hash CHAR(64) NULL COMMENT 'SHA-256 迭代 10000 轮的十六进制';
-- ALTER TABLE user MODIFY passwd VARCHAR(64) NULL COMMENT '旧明文列，迁移后置 NULL';
--
-- 注意第三条：passwd 从 NOT NULL 改成了 NULL。
-- 不改的话新注册写 NULL 会被数据库拒绝，而"注册就存明文"是错误的退路。
-- 这一版走的是"首次登录顺手迁移"：明文比对成功 -> 写散列 -> 同一语句把 passwd 置 NULL。
-- 它的固有残留是：从未登录过的账号，明文会一直留在库里 ——
-- 服务端不掌握明文，无法为这些账号预先算散列。
-- 这也是下一条 ALTER 的原因。
--
-- 第三阶段（换 bcrypt，并把明文彻底从 schema 里删掉），已执行：
-- ALTER TABLE user DROP COLUMN passwd, DROP COLUMN passwd_salt;
-- ALTER TABLE user MODIFY passwd_hash VARCHAR(100) NOT NULL;
--
-- 为什么可以直接 DROP 而不是再写一次迁移工具：库里的三个账号已经全部迁移成散列
-- （passwd 都是 NULL），确认没有明文可丢之后，这三个账号本身也被删掉了，
-- user 表清空。DROP COLUMN 是不可逆的，这一步之所以安全，前提是"先确认没有数据依赖它"。
-- 删列之后，"明文存进库里"这件事在 schema 层面不再可能，而不是靠代码里不写而已。
--
-- 另外订正过一条存量脏数据：老解析器从不做 URL 解码，
-- 导致某个用户名存成了 '%E9%91%AB%E5%93%A5'，已改回 '鑫哥'。
