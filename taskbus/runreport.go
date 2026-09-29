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

// Result 由一次执行的结果拼出 RunResult: 成功 / 失败由 runErr 判定, payload 为 nil
// (含 typed nil 指针) 时不带 result 字段。
func Result(runErr error, durationMS int64, payload any) RunResult {
	res := RunResult{Status: "success", DurationMS: durationMS}
	if runErr != nil {
		msg := runErr.Error()
		res.Status = "failed"
		res.ErrorMessage = &msg
	}
	res.Result = marshalPayload(payload)
	return res
}

// marshalPayload 把结果的 nil 映射成**不存在的字段**而不是 JSON 字面量 null。
//
// scheduler 侧是 datatypes.JSON(payload.Result): len==0 落库是 SQL NULL, 而字面量 null
// 是 4 字节, 落成 jsonb 的 'null' —— API 响应会从"没有 result 键"变成 "result": null,
// 是一次安静发生的契约变更。typed nil 指针走的是 interface 非 nil 分支, 是最容易漏的一种,
// 所以这里用 reflect 兜而不是只判 payload == nil。
func marshalPayload(payload any) json.RawMessage {
	if payload == nil {
		return nil
	}
	if v := reflect.ValueOf(payload); v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
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
	if res.Status == "failed" {
		log.Error("scheduled run failed, reporting to scheduler", zap.Int64("run_id", runID), zap.String("error_message", deref(res.ErrorMessage)))
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
		zap.String("status", res.Status), zap.Int64("duration_ms", res.DurationMS), zap.Error(err))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
