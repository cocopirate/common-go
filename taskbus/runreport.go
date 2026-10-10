package taskbus

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"go.uber.org/zap"
)

// RunResultPublisher 是"回报一次 run 结束"所需要的**全部** taskbus 能力, 刻意只取这一个
// 方法而不是整个 *Publisher: EnsureQueue / Close 属于进程生命周期, 业务 handler 不拥有
// 它们。副作用是单测可以塞一个假 publisher, 不必起 broker。
//
// *Publisher 满足这个接口。
type RunResultPublisher interface {
	PublishRunResult(ctx context.Context, runID, taskID int64, res RunResult) error
}

// 运行状态字面量。scheduler 侧的 scheduled_task_run.status 是同一套词, 但不导出到
// 那份 model 里 —— 两处各自持有常量, 这里只服务回报方。
const (
	StatusSuccess = "success"
	StatusFailed  = "failed"
)

// ErrorCode 是 run 失败的**机器可读**分类, 经 RunResult 落进 scheduled_task_run.error_code。
//
// 它是一张闭集, 但分类的依据只有一个: **操作者下一步该做什么**。每个码对应一个明确的
// 动作 —— 这就是码存在的全部意义。细分到"哪个调用、哪一行"是 error_message 与日志的事,
// 不是码的事: 码一旦按实现细节分裂, 控制台与告警就没法用它做一概而论的展示和判断。
//
// 用命名类型而不是裸 string: 调用方必须引用下面的常量 (或写下显式转换, 那是一次刻意的
// 决定), 名字拼错编译不过 —— 这是这些码能被下游信任的前提。
type ErrorCode string

const (
	// ErrCodeParamInvalid: params 畸形 / 值非法 / 必填缺失 / 区间配错 / 超出上限。
	// 操作者该做的是改任务 params。
	ErrCodeParamInvalid ErrorCode = "param_invalid"
	// ErrCodeNotConfigured: 本服务未接线 (缺 DSN / 缺上游地址 / 功能开关关掉)。
	// 操作者该做的是补部署配置。
	ErrCodeNotConfigured ErrorCode = "not_configured"
	// ErrCodeUpstreamFailed: 上游服务或旧库调用失败。操作者该做的是查上游。
	ErrCodeUpstreamFailed ErrorCode = "upstream_failed"
	// ErrCodeDBFailed: 本服务数据库读写失败。操作者该做的是查本服务库。
	ErrCodeDBFailed ErrorCode = "db_failed"
	// ErrCodeBusy: 已有轮次在跑 (被锁 / 并发策略挡下)。操作者稍后重跑即可, 不用急着捞。
	ErrCodeBusy ErrorCode = "busy"
	// ErrCodeRejected: 业务规则拒绝 (防重复申报 / 拒绝清库 / 候选超限这类"数据状态不对")。
	// 重跑同样的参数结果一样, 需要人看数据再决定。
	ErrCodeRejected ErrorCode = "rejected"
	// ErrCodePartial: 部分类型/天没拿到结论 (赢家通吃式成败: 全部拿到才算成功)。
	// 操作者该做的是看明细决定补跑范围。
	ErrCodePartial ErrorCode = "partial"
	// ErrCodeTimeout: 超预算, 或被 scheduler 的 timeoutExpiredRuns 标成超时。
	// 操作者该做的是加大 timeout_seconds 或把任务排前。
	ErrCodeTimeout ErrorCode = "timeout"
	// ErrCodeCancelled: 人为取消。无需动作。
	ErrCodeCancelled ErrorCode = "cancelled"
	// ErrCodeInternal: panic / 空结果 / 实现被改坏。操作者该做的是提 bug。
	ErrCodeInternal ErrorCode = "internal"
)

// ResultShell 是每个任务类型的 result 都该带的两个**统一键**。
//
// 它解决的是同一个概念被写成七八种拼法的问题 (count / scanned+deleted / item_total /
// generated_count / summary{ok,busy,...}): 控制台面对一坨自由形状的 JSON, 做不了"这次
// 动了几个"的通用展示与告警。
//
// **不许改动类型自己的键**: 消费方 (控制台、历史 run) 按 `result.scanned` 这类路径直接
// 读值, 重命名等于一次静默的契约变更。所以外壳是**加在旁边的兄弟键**, 走匿名嵌入
// (encoding/json 会把嵌入结构体的字段展平, 于是 summary/counts 与类型专属键同级)。
type ResultShell struct {
	// Summary 是一句话人话, 给控制台预览行、日志与通知用。
	// 成功也可以有 (例如"本轮无可申报商户, 未生成批次"—— 那是成功带附言, 不是错误)。
	Summary string `json:"summary,omitempty"`
	// Counts 只填该类型**真有意义**的项: 拿不准的留空 (omitempty) 而不是硬塞 0。
	// 0 与"不适用"在展示和告警里是两回事。
	Counts *Counts `json:"counts,omitempty"`
}

// Counts 是归一化的执行计数。四个格子的含义对所有任务类型一致, 具体对应关系由各类型的
// 生产点决定 (例如 download 的 changed 是"删除", workorder 的 changed 是"提交")。
type Counts struct {
	Scanned int `json:"scanned,omitempty"` // 扫到 / 候选
	Changed int `json:"changed,omitempty"` // 真正写入 / 删除 / 提交 / 生成
	Skipped int `json:"skipped,omitempty"` // 因幂等或业务规则放过
	Failed  int `json:"failed,omitempty"`  // 逐项失败: 整批 un 成功但这里有非零, 就是"成功带伤"
}

// Merge 把外壳并进一个 map 形状的 payload (finance 的几个任务用 map 攒 result)。
// 与结构体嵌入路径产出**语义相同**的 JSON —— 单测钉住这一点, 两种写法不许漂移。
//
// 没有东西可并时原样返回 (可能为 nil), 保住 marshalPayload 那条"nil 即整条消失"的约定:
// 凭空造一个空 map 会让 "没有 result 键" 变成 "result": {}。
func (s ResultShell) Merge(payload map[string]any) map[string]any {
	if s.Summary == "" && s.Counts == nil {
		return payload
	}
	if payload == nil {
		payload = map[string]any{}
	}
	if s.Summary != "" {
		payload["summary"] = s.Summary
	}
	if s.Counts != nil {
		payload["counts"] = s.Counts
	}
	return payload
}

// OK 由一次成功的执行拼出 RunResult。成功也可以带 payload —— 想说明什么就放进 ResultShell
// 的 Summary/Counts, 不要让控制台从自由形状的键里猜。
func OK(durationMS int64, payload any) RunResult {
	return RunResult{Status: StatusSuccess, DurationMS: durationMS, Result: marshalPayload(payload)}
}

// Failed 由一次失败的执行拼出 RunResult。code 必填 —— 用 ErrCode* 常量, 这是下游
// (控制台筛选、告警、值班手册) 唯一能程序化依赖的东西; err 是给人看的原因, 顺手也进日志。
//
// err 为 nil 时写一句兜底文案而不是空串: 空 error_message 在控制台里表现为"没有原因"。
func Failed(code ErrorCode, err error, durationMS int64, payload any) RunResult {
	msg := "unknown failure"
	if err != nil {
		msg = err.Error()
	}
	if code == "" {
		// 保住"failed 必有码"这条下游可以依赖的约束: 调用点漏填是**实现被改坏**,
		// 归到 internal 比留空诚实 —— 留空与"老生产者发的回执"无法区分。
		code = ErrCodeInternal
	}
	return RunResult{
		Status:       StatusFailed,
		ErrorCode:    code,
		ErrorMessage: &msg,
		DurationMS:   durationMS,
		Result:       marshalPayload(payload),
	}
}

// marshalPayload 把结果的 nil 映射成**不存在的字段**而不是 JSON 字面量 null。
//
// scheduler 侧是 datatypes.JSON(payload.Result): len==0 落库是 SQL NULL, 而字面量 null
// 是 4 字节, 落成 jsonb 的 'null' —— API 响应会从"没有 result 键"变成 "result": null,
// 是一次安静发生的契约变更。
//
// **不能只判 payload == nil**: 指针 / map / 切片一旦装进 interface 就不再是 nil interface,
// 而 json.Marshal 对这些 typed nil 一律写出 "null" 而不是报错 —— 静悄悄地绕过这道检查。
// 调用方写 `var m map[string]any …` 再传 m 是最常见的一种 (空 result 的自然写法),
// 所以这里用 reflect 把同类都兜住, 而不是只挡最容易想到的指针。
func marshalPayload(payload any) json.RawMessage {
	if payload == nil {
		return nil
	}
	switch v := reflect.ValueOf(payload); v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Chan, reflect.Func:
		if v.IsNil() {
			return nil
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return raw
}

// Publish 回报一次 run 的完成结果, **永远不返回错误**。
//
// 发不出去不该让整条命令重投: 重投的是命令本身, call-check 会重新逐单外呼 voice-service、
// rake sync 会重新全量翻页拉 legacy-bff、批量分析会重新跑一遍大模型。一次 broker 抖动换
// 三轮外部调用是净损失。丢了靠 scheduler 的 timeoutExpiredRuns 兜底 —— run 会占到
// timeout_seconds 被标成 timeout, 这是既有的"回执尽力而为"语义, MQ 化刻意没有改变它。
//
// 代价是失去了 HTTP 时代的状态码: "scheduler 拒了" 现在看不到了。所以发布失败必须是
// ERROR 且带全上下文 —— 排查"run 一直 running 直到超时"时要能一眼看出是没发出去, 而不是
// 发了没收 (后者在 scheduler 侧有一条 run_result_rejected)。
func Publish(ctx context.Context, pub RunResultPublisher, log *zap.Logger, runID, taskID int64, res RunResult) {
	if pub == nil {
		return
	}
	if log == nil {
		log = zap.NewNop()
	}
	if res.Status == StatusFailed {
		log.Error("scheduled run failed, reporting to scheduler",
			zap.Int64("run_id", runID), zap.String("error_code", string(res.ErrorCode)), zap.String("error_message", deref(res.ErrorMessage)))
	}

	// 短退避重试只吃"broker 瞬断 / 连接被回收"这类一次性失败 —— 真正的本地 outbox 在这里
	// 是过度设计: 批处理的写入是几十上百次独立写, 做不出"同事务落 outbox"的原子性。
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
		}
		if err = pub.PublishRunResult(ctx, runID, taskID, res); err == nil {
			log.Info("reported run result to scheduler",
				zap.Int64("run_id", runID), zap.String("status", res.Status), zap.Int64("duration_ms", res.DurationMS))
			return
		}
	}
	log.Error("publish run result failed",
		zap.Int64("run_id", runID), zap.Int64("task_id", taskID),
		zap.String("status", res.Status), zap.String("error_code", string(res.ErrorCode)),
		zap.Int64("duration_ms", res.DurationMS), zap.Error(err))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
