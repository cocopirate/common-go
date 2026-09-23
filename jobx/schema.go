package jobx

import (
	"fmt"
	"regexp"
	"strings"
)

// schemaTemplate 是任务表的规范结构 (与 Task 的字段一一对应)。
//
// 与 lead_task 的现状完全一致 —— 那张表是这套列名的事实来源, 本包只是把它显式化,
// 让新服务不必再各自发明一份 (workorder 的 work_order_ai_analysis 就是各自发明的
// 结果: id 用 BIGSERIAL、状态叫 succeeded、没有任何进度列, 于是它的队列与导出的
// 队列无法共用一套查询与前端)。
//
// owner_uid 用 NOT NULL DEFAULT 空串而不是可空: Go 侧是 string, NULL 扫进 string
// 会报错; 而 PG 11+ 加一个带默认值的 NOT NULL 列不重写表。空串的语义是"无发起人"
// (系统任务), 与"有主但主人是空"不可能混淆。dedupe_key 同款 (空串 = 不参与去重)。
//
// 最后那条**部分唯一索引**是去重的全部实现 (见 Task.DedupeKey), 谓词的四段各挡一件事,
// 少一段都是线上事故:
//
//	dedupe_key <> ''   无 key 的任务不互相冲突 (少了它, 第二条无 key 的任务就插不进来,
//	                   队列当场写死)
//	status IN (...)    终态行退出索引 —— 少了它, 同一个 key 全局只能有一条, 跑完就再也
//	                   导不出来
//	UNIQUE             靠数据库而不是"先查后插"来去重 (并发提交只有一个能赢)
//	owner_uid 进列     两个人导出同一段时间不该互相顶掉 (做成结构, 而不是"请调用方把
//	                   owner 编进 key"的约定)
const schemaTemplate = `
CREATE TABLE IF NOT EXISTS %[1]s (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type          VARCHAR(64) NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'pending',
    payload       JSONB,
    error         TEXT,
    owner_uid     VARCHAR(64) NOT NULL DEFAULT '',
    dedupe_key    VARCHAR(128) NOT NULL DEFAULT '',
    attempts      INTEGER NOT NULL DEFAULT 0,
    total_count   INTEGER NOT NULL DEFAULT 0,
    done_count    INTEGER NOT NULL DEFAULT 0,
    failed_count  INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    summary       JSONB NOT NULL DEFAULT '{}'::jsonb,
    available_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_%[1]s_type ON %[1]s(type);
CREATE INDEX IF NOT EXISTS ix_%[1]s_status ON %[1]s(status);
CREATE INDEX IF NOT EXISTS ix_%[1]s_available_at ON %[1]s(available_at);
CREATE INDEX IF NOT EXISTS ix_%[1]s_owner_created_at ON %[1]s(owner_uid, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_%[1]s_dedupe_active ON %[1]s(type, owner_uid, dedupe_key) WHERE dedupe_key <> '' AND status IN ('pending', 'running');
`

// tableNameRe 限定表名只能是普通小写标识符。
//
// 表名会被插进 DDL 字符串, 所以它必须是编译期常量而不是配置项 —— 这里再挡一道,
// 免得将来有人把它接到环境变量上, 把一个 SQL 注入点开在建表路径里。
var tableNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// SchemaSQL 生成建表语句 (含索引), 表名替换进模板。
//
// 用法是两种: 贴进服务自己的 golang-migrate 迁移文件 (本仓惯例, 版本号归服务),
// 或启动时执行一次 —— 语句全是 IF NOT EXISTS, 重复执行无副作用。
//
// 已存在同名表的服务 (例如 lead 的 lead_task) **不要**执行它: 那些表由服务自己的
// 迁移管, 这里只是同一套结构的另一份表述。
func SchemaSQL(table string) (string, error) {
	if !tableNameRe.MatchString(table) {
		return "", fmt.Errorf("jobx: invalid table name %q (want [a-z_][a-z0-9_]*)", table)
	}
	return strings.TrimSpace(fmt.Sprintf(schemaTemplate, table)), nil
}
