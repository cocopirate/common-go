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
const schemaTemplate = `
CREATE TABLE IF NOT EXISTS %[1]s (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type          VARCHAR(64) NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'pending',
    payload       JSONB,
    error         TEXT,
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
