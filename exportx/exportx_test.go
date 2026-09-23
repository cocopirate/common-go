package exportx

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTime(t *testing.T) {
	// 1700000000 = 2023-11-14 22:13:20 UTC = 2023-11-15 06:13:20 +08:00.
	// 断言的是 +08:00 那一侧:容器里没有 tzdata,RST 时区一旦被用上就会差 8 小时。
	ts := int64(1700000000)
	zero := int64(0)
	cases := []struct {
		name string
		in   *int64
		want string
	}{
		{"nil", nil, ""},
		{"zero", &zero, ""},
		{"value", &ts, "2023-11-15 06:13:20"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Time(c.in); got != c.want {
				t.Fatalf("Time = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDatedFilenameAt(t *testing.T) {
	// 20:00 UTC 已经是次日 04:00 (+08:00) —— 文件名必须跟控制台看到的日期一致,
	// 否则 08:00 之前发起的导出会以"昨天"命名。
	at := time.Date(2026, 9, 22, 20, 0, 0, 0, time.UTC)
	if got, want := DatedFilenameAt(at, "客资申诉", "csv"), "客资申诉_20260923.csv"; got != want {
		t.Fatalf("DatedFilenameAt = %q, want %q", got, want)
	}
}

func TestText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"plain text is wrapped", "张三", `="张三"`},
		{"quotes are doubled", `说"你好"`, `="说""你好"""`},
		// 以 = 开头的自由文本必须被包住,否则 Excel 会把它当公式执行。
		{"formula is neutralised", `=1+1`, `="=1+1"`},
		// 手机号包成公式后不会被显示成科学计数法。
		{"phone", "13800138000", `="13800138000"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Text(c.in); got != c.want {
				t.Fatalf("Text(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func readCSV(t *testing.T, b []byte) [][]string {
	t.Helper()
	if !bytes.HasPrefix(b, []byte(BOM)) {
		t.Fatalf("output does not start with the UTF-8 BOM: %q", b[:min(8, len(b))])
	}
	rows, err := csv.NewReader(bytes.NewReader(b[len(BOM):])).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	return rows
}

func TestWriterHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []string{"ID", "备注"}, 0)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteRow([]string{"1", "含,逗号"}); err != nil {
		t.Fatalf("WriteRow: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rows := readCSV(t, buf.Bytes())
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want header + 1", len(rows))
	}
	if rows[0][0] != "ID" || rows[1][1] != "含,逗号" {
		t.Fatalf("unexpected content: %v", rows)
	}
	if w.Rows() != 1 || w.Truncated() {
		t.Fatalf("Rows = %d, Truncated = %v; want 1, false", w.Rows(), w.Truncated())
	}
}

func TestWriterRowLimit(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []string{"ID", "名称"}, 2)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i, id := range []string{"1", "2", "3"} {
		err := w.WriteRow([]string{id, "x"})
		if i < 2 && err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		// 第三行是"多出来的那一行":它触发截断,但自己不写入。
		if i == 2 && !errors.Is(err, ErrRowLimit) {
			t.Fatalf("row %d: err = %v, want ErrRowLimit", i, err)
		}
	}
	if !w.Truncated() || w.Rows() != 2 {
		t.Fatalf("Truncated = %v, Rows = %d; want true, 2", w.Truncated(), w.Rows())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rows := readCSV(t, buf.Bytes())
	if len(rows) != 4 { // 表头 + 2 行 + 提示行
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	notice := rows[3]
	// 提示行必须补齐到表头列数,否则严格读取器会拒掉整个文件。
	if len(notice) != 2 {
		t.Fatalf("notice has %d columns, want 2 (padded): %v", len(notice), notice)
	}
	if !strings.Contains(notice[0], "2") || notice[1] != "" {
		t.Fatalf("unexpected notice: %v", notice)
	}
}

func TestWriterNoticeOverride(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []string{"ID"}, 1)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.Notice = "上限 %d"
	if err := w.WriteRow([]string{"1"}); err != nil {
		t.Fatalf("WriteRow: %v", err)
	}
	if err := w.WriteRow([]string{"2"}); !errors.Is(err, ErrRowLimit) {
		t.Fatalf("err = %v, want ErrRowLimit", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rows := readCSV(t, buf.Bytes()); rows[2][0] != "上限 1" {
		t.Fatalf("notice = %q, want 上限 1", rows[2][0])
	}
}

func TestWriterAfterClose(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []string{"ID"}, 0)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
	if err := w.WriteRow([]string{"1"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

// 上限为 0 表示不限:唯一合法的用法是"这次导出本来就不封顶",不能退化成"一行都不给"。
func TestWriterUnlimited(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []string{"ID"}, 0)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < 100; i++ {
		if err := w.WriteRow([]string{"x"}); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if w.Truncated() || w.Rows() != 100 {
		t.Fatalf("Truncated = %v, Rows = %d; want false, 100", w.Truncated(), w.Rows())
	}
}
