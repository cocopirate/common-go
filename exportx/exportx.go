// Package exportx 提供各服务导出文件时共用的机械部分:CSV 骨架(UTF-8 BOM、
// 行数上限与截断提示)、固定 +08:00 的时间渲染、日期文件名、Excel 文本包装。
// 业务行映射、查询、权限与数据范围规则一律留在业务服务,见 common-go README 的使用边界。
package exportx

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// BOM 是 UTF-8 字节序标记。写在 CSV 开头,Excel 才会按 UTF-8 打开而不是本地代码页。
const BOM = "\xEF\xBB\xBF"

// Zone 是控制台统一使用的固定 +08:00 时区。
//
// 固定偏移而不是 time.LoadLocation("Asia/Shanghai"):容器镜像通常不带 tzdata,
// LoadLocation 会静默回落到 UTC,于是每个导出时间戳整体差 8 小时,且没有任何报错。
var Zone = time.FixedZone("CST", 8*60*60)

const (
	dateLayout     = "20060102"
	dateTimeLayout = time.DateTime
)

// Time 把 unix 秒渲染成 Zone 时区的可读时间。nil 或 0 渲染成空串 ——
// "没有值"和"1970-01-01"必须能区分开。
func Time(v *int64) string {
	if v == nil || *v == 0 {
		return ""
	}
	return time.Unix(*v, 0).In(Zone).Format(dateTimeLayout)
}

// DatedFilename 生成 "<prefix>_<YYYYMMDD>.<ext>",日期取 Zone 时区的今天,ext 不带点。
//
// 用 Zone 而不是本地时区:UTC 时钟会把 08:00 之前发起的导出命名成前一天。
func DatedFilename(prefix, ext string) string {
	return DatedFilenameAt(time.Now(), prefix, ext)
}

// DatedFilenameAt 同 DatedFilename,但由调用方给定时刻 —— 存在的意义是"只算一次":
// 上传与制品描述必须用同一个名字,两次调用跨零点会得到两个。
func DatedFilenameAt(t time.Time, prefix, ext string) string {
	return prefix + "_" + t.In(Zone).Format(dateLayout) + "." + ext
}

// Text 把文本包成 Excel 公式字符串,使手机号、订单号以及以 = + - @ 开头的自由文本
// 既不被当成公式执行(CSV 注入),也不被显示成科学计数法。空串保持空串。
func Text(v string) string {
	if v == "" {
		return ""
	}
	return `="` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

// DefaultTruncationNotice 是截断提示行的默认文案,%d 会被替换成行数上限。
const DefaultTruncationNotice = "已达单次导出上限 %d 条,如需完整数据请缩小筛选条件后重新导出"

// ErrRowLimit 由 WriteRow 在已达上限时返回。
//
// 它是哨兵而不是失败:调用方据此停止遍历游标,Close 会补上截断提示行。
var ErrRowLimit = errors.New("exportx: 已达单次导出行数上限")

// ErrClosed 表示对已 Close 的 Writer 继续写入。
var ErrClosed = errors.New("exportx: Writer 已关闭")

// Writer 写一个带 BOM 的 CSV:表头 + 数据行 + (可选)截断提示行。
//
// 它不碰数据库也不碰对象存储 —— 调用方把行喂进来,拿到字节(或以后直接喂 io.Writer)
// 之后自己决定怎么存。
type Writer struct {
	// Notice 是截断提示行的文案模板,%d 替换成行数上限;留空用 DefaultTruncationNotice。
	Notice string

	cw        *csv.Writer
	header    []string
	limit     int
	rows      int
	truncated bool
	closed    bool
}

// NewWriter 构造 Writer,写入 BOM 与表头。limit <= 0 表示不限制行数。
func NewWriter(w io.Writer, header []string, limit int) (*Writer, error) {
	if _, err := io.WriteString(w, BOM); err != nil {
		return nil, err
	}
	ew := &Writer{cw: csv.NewWriter(w), header: header, limit: limit}
	if err := ew.cw.Write(header); err != nil {
		return nil, err
	}
	return ew, nil
}

// WriteRow 写一行数据。已写满 limit 行时返回 ErrRowLimit,且该行不写入。
func (w *Writer) WriteRow(row []string) error {
	if w.closed {
		return ErrClosed
	}
	if w.limit > 0 && w.rows >= w.limit {
		w.truncated = true
		return ErrRowLimit
	}
	if err := w.cw.Write(row); err != nil {
		return err
	}
	w.rows++
	return nil
}

// Rows 返回已写入的数据行数(不含表头与提示行)。
func (w *Writer) Rows() int { return w.rows }

// Truncated 表示本次写入撞到了行数上限。
func (w *Writer) Truncated() bool { return w.truncated }

// Close 补上截断提示行并 flush。可重复调用。
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.truncated && len(w.header) > 0 {
		// 补齐到表头的列数:短记录也是合法 CSV,但严格读取器(Go 的 encoding/csv 默认
		// FieldsPerRecord,以及若干 Java/Python 严格模式)会因此拒掉整个文件 ——
		// 那就把一条截断提示变成了"导出文件损坏"。
		notice := make([]string, len(w.header))
		tpl := w.Notice
		if tpl == "" {
			tpl = DefaultTruncationNotice
		}
		notice[0] = fmt.Sprintf(tpl, w.limit)
		if err := w.cw.Write(notice); err != nil {
			return err
		}
	}
	w.cw.Flush()
	return w.cw.Error()
}
