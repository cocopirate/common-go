// Package taskbus contains the small, shared RabbitMQ contract used by
// scheduler and business-service workers.
//
// RabbitMQ is deliberately kept behind this package. Services exchange a
// stable JSON command and do not need to know about exchange declarations,
// publisher confirms, retry queues, or dead-letter routing.
package taskbus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const (
	DefaultExchange      = "opengo.tasks"
	DefaultRetryExchange = "opengo.tasks.retry"
	DefaultDeadExchange  = "opengo.tasks.dead"

	// 命令队列: scheduler 出站 (outbox) → 业务服务消费。
	WorkorderQueue = "opengo.workorder.tasks"
	LeadQueue      = "opengo.lead.tasks"
	// LeadRakeQueue 单独一条队列, 而不是并进 LeadQueue:
	//
	//  1. 同一个队列上的多个消费者是 **load-balance 而不是广播** —— 一条消息只投给其中
	//     一个。而消费循环是同步的 (见 Consumer.handleDelivery), 所以 rake sync 那种
	//     全量翻页拉 legacy-bff 的长跑会把 call-check 的命令堵在队头;
	//  2. 两类失败分开: rake 的失败风暴不会污染 call-check 的重试计数与 DLQ。
	LeadRakeQueue = "opengo.lead.rake.tasks"
	// DownloadQueue 只承载 download.export_artifact.cleanup 这一个任务类型, 所以不另拆
	// (lead 拆 rake 是因为 call-check 会被长跑堵住, 这里没有并列的第二类命令)。
	//
	// 它清理的是**未脱敏**的导出产物 (CSV 里有姓名/手机号/地址), 而对象存储不会自己过期 ——
	// 这条队列必须有人消费, 否则每次导出都在桶里留一份永久数据副本。
	DownloadQueue = "opengo.download.tasks"
	// MerchantQueue 承载申报与营收两个任务类型, 不拆开:
	//
	//  1. 两者都是**每月一次**的重活。营收是全平台唯一去旧库订单大表聚合的地方, 申报要跨
	//     旧库 + PG 筛完所有候选 —— 同队列串行, 旧库同一时刻只挨一次重查询;
	//  2. 营收快照是申报报文里上月营收与额度标识的**唯一来源**, 所以营收必须跑在申报前。
	//     同队列 FIFO 把这个数据依赖变成结构性保证, 而不是靠 crontab 的时间差。
	//
	// 与 LeadRakeQueue 的拆分理由 (长跑堵住并列命令) 不冲突: 那两个是并列的同类命令、其中
	// 一个长跑会堵住另一个; 这里两者本就该一前一后, 串行是想要的语义而不是代价。
	MerchantQueue = "opengo.merchant.tasks"
	// FinanceQueue 承载客资抽佣日账单与易宝资金账单两条日结命令, 不拆开:
	//
	//  1. 两条都是"受理/生成"型 —— 一个按网点生成账单, 一个只是把易宝的取数登记成
	//     一行任务 (真正的同步由易宝回调触发), 秒级到分钟级, 没有长跑堵队头的问题;
	//  2. 两者之间没有顺序依赖, 也不抢同一个下游 —— 与 MerchantQueue 的"故意串行"
	//     不同, 这里共享只是省一条队列, 代价是后到的那条要等前面跑完,
	//     所以两条任务的 timeout_seconds 都要把排队时间算进去。
	FinanceQueue = "opengo.finance.tasks"
	// FinanceReconQueue 只承载平安对账同步一条命令, 单独一条队列:
	//
	//  1. 它是**分钟级串行 sweep** (六类逐类查文件 + SFTP 下载解密解压 + 逐行入库,
	//     总预算 300 秒, 见 finance-service 的 pingan.SweepBudget), 而消费循环是同步的 ——
	//     并进 FinanceQueue 会把那两条日结命令堵在队头, 同 LeadRakeQueue 的拆分理由;
	//  2. 它的失败模式 (银行侧 / SFTP / 凭据) 与另外两条 (上游服务 / DB) 完全不同,
	//     分开让重试计数与 DLQ 互不污染。
	FinanceReconQueue = "opengo.finance.recon.tasks"
	// FinanceReconBackfillQueue 只承载平安对账多日补账一条命令, 与 FinanceReconQueue 分家:
	//
	//  1. 它是**批量**命令 —— 一次最多 31 天, 每天都把日结那条的串行 sweep (300 秒预算)
	//     完整走一遍, 小时级。并进 FinanceReconQueue 会让每天 01:00 的日结命令堵在队头,
	//     一直堵到自己的 timeout_seconds 超时 —— 那是一条"日结超时"的假故障,
	//     同 LeadRakeQueue 的拆分理由;
	//  2. 两者的失败模式也不同: 日结失败=今天的账没结 (要立刻知道), 补账失败=某段历史
	//     没补齐 (可以慢慢重跑), 分开让重试计数与 DLQ 互不污染。
	//
	// 两条队列**消费的是同一把全局 Redis 锁** (finance-service 的
	// finance:pingan:recon:sync_lock), 所以补账与日结之间仍然是串行的 —— 分队列解决的是
	// 排队导致的假超时, 不是并发。
	FinanceReconBackfillQueue = "opengo.finance.recon.backfill.tasks"
	// DashboardQueue 只承载数据来源渠道同步一条命令, 所以不另拆。
	DashboardQueue = "opengo.dashboard.tasks"
	// 结果队列: 业务服务回报 → scheduler 消费, 方向与上面相反。正因为它反向,
	// **发起 run 的业务服务也要在启动时 EnsureQueue 它**: exchange 上还没有绑定时,
	// publisher confirm 依然 ACK, 消息会被静默丢弃 (见 Publisher.EnsureQueue)。
	SchedulerQueue = "opengo.scheduler.tasks"

	WorkorderAIAnalysisBatch      = "workorder.ai_analysis.batch"
	LeadTextCallCheck             = "lead.text_parse.call_check"
	LeadKeziRakeOrderSync         = "lead.kezi_rake_order.sync"
	DownloadExportArtifactCleanup = "download.export_artifact.cleanup"
	MerchantMarketDeclareSubmit   = "merchant.market_declare.submit"
	MerchantStoreRevenueCompute   = "merchant.store_revenue.compute"

	FinanceKeziRakeBillDailyGenerate = "finance.kezi_rake_bill.daily.generate"
	FinanceYeepayFundBillSync        = "finance.yeepay.fundbill.sync"
	// FinancePinganReconSync 的成败判定不看 Sync 返回的 error —— 六类全失败它也可能返回
	// nil, 只有缺参数 / 未配置 / 已有一轮在跑三种情况才有 error。真正的结论逐类型算:
	// no_file/skipped 是正常业务事实, failed/not_delivered/pending 才算没拿到结论。
	// 判定实现在 finance-service 的 internal/pingan (状态词表的归属地)。
	FinancePinganReconSync = "finance.pingan.recon.sync"
	// FinancePinganReconBackfill 是同一个 sweep 的**多日**版本: 按天循环调用
	// pingan.RunSweep, 每天独立 run_id、独立日志、单独拿锁放锁 (不跨天持锁 —— 锁 TTL
	// 30 分钟, 长批次跨天持锁会在中途失效)。参数与 workorder.ai_analysis.batch 同形:
	// days 与 start_time/end_time 互斥, 跨度上限 31 天; 差别是 days:N 以**昨天**为终点
	// (银行当天不生成当天文件)。逐日容错、互不影响, 整轮成败 = 所有天都拿到结论。
	FinancePinganReconBackfill = "finance.pingan.recon.backfill"
	DashboardSourceOptionSync  = "dashboard.source_option.sync"
	// RunFinished 是唯一一条"回执"方向的消息: 其余 task type 都是 scheduler 发出的命令。
	RunFinished = "scheduler.run.finished"
)

// Message is the durable command envelope. Params is a snapshot from the
// scheduler row; consumers must not re-read mutable scheduler configuration
// to decide what a historical run was supposed to do.
type Message struct {
	MessageID   string          `json:"message_id"`
	RunID       int64           `json:"run_id"`
	TaskID      int64           `json:"task_id"`
	TaskType    string          `json:"task_type"`
	Params      json.RawMessage `json:"params"`
	Attempt     int             `json:"attempt"`
	ScheduledAt *time.Time      `json:"scheduled_at,omitempty"`
	TraceID     string          `json:"trace_id,omitempty"`
}

func NewMessage(runID, taskID int64, taskType string, params json.RawMessage, scheduledAt *time.Time) Message {
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	return Message{
		MessageID:   newID(),
		RunID:       runID,
		TaskID:      taskID,
		TaskType:    taskType,
		Params:      append(json.RawMessage(nil), params...),
		Attempt:     1,
		ScheduledAt: scheduledAt,
	}
}

// RunResult 是一次调度运行的完成结果, 是 RunFinished 消息的 params。
//
// 它从前还要同时充当 POST /internal/runs/:id/finish 的 body —— 那条 HTTP 回执通道随
// merchant-service (最后一个调用方) 迁移而删除, 现在只剩 MQ 一条路。
type RunResult struct {
	Status       string          `json:"status"` // success | failed
	ErrorMessage *string         `json:"error_message"`
	DurationMS   int64           `json:"duration_ms"`
	Result       json.RawMessage `json:"result,omitempty"`
}

// NewRunResultMessage 构造业务服务回报 run 结束的信封。taskID 回显触发本次运行的命令
// 消息的 Message.TaskID, 让 scheduler 侧的日志不经 run 表就能对上任务。
func NewRunResultMessage(runID, taskID int64, res RunResult) (Message, error) {
	params, err := json.Marshal(res)
	if err != nil {
		// 只有 Result 携带非法 JSON 时才会走到这里。
		return Message{}, fmt.Errorf("encode run result: %w", err)
	}
	return NewMessage(runID, taskID, RunFinished, params, nil), nil
}

func (m Message) Validate() error {
	if strings.TrimSpace(m.MessageID) == "" {
		return errors.New("message_id is required")
	}
	if m.RunID <= 0 {
		return errors.New("run_id must be positive")
	}
	if strings.TrimSpace(m.TaskType) == "" {
		return errors.New("task_type is required")
	}
	if m.Attempt <= 0 {
		return errors.New("attempt must be positive")
	}
	if len(m.Params) == 0 || !json.Valid(m.Params) {
		return errors.New("params must be valid json")
	}
	return nil
}

func (m Message) Marshal() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func Decode(body []byte) (Message, error) {
	var m Message
	if err := json.Unmarshal(body, &m); err != nil {
		return Message{}, fmt.Errorf("decode task message: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Message{}, fmt.Errorf("invalid task message: %w", err)
	}
	return m, nil
}

type Config struct {
	URL            string
	Exchange       string
	RetryExchange  string
	DeadExchange   string
	RetryDelay     time.Duration
	MaxAttempts    int
	Prefetch       int
	ConfirmTimeout time.Duration
}

func (c Config) normalized() Config {
	if strings.TrimSpace(c.Exchange) == "" {
		c.Exchange = DefaultExchange
	}
	if strings.TrimSpace(c.RetryExchange) == "" {
		c.RetryExchange = DefaultRetryExchange
	}
	if strings.TrimSpace(c.DeadExchange) == "" {
		c.DeadExchange = DefaultDeadExchange
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 5 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.Prefetch <= 0 {
		c.Prefetch = 1
	}
	if c.ConfirmTimeout <= 0 {
		c.ConfirmTimeout = 5 * time.Second
	}
	return c
}

// Publisher uses one AMQP channel at a time. amqp channels are not safe for
// concurrent use, so the mutex also makes the reconnect path deterministic.
type Publisher struct {
	cfg Config
	log *zap.Logger

	mu       sync.Mutex
	conn     *amqp.Connection
	ch       *amqp.Channel
	confirms chan amqp.Confirmation
}

func NewPublisher(cfg Config, log *zap.Logger) (*Publisher, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("rabbitmq url is required")
	}
	if log == nil {
		log = zap.NewNop()
	}
	p := &Publisher{cfg: cfg.normalized(), log: log}
	if err := p.connectLocked(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Publisher) connectLocked() error {
	if p.conn != nil && !p.conn.IsClosed() && p.ch != nil {
		return nil
	}
	p.closeLocked()
	conn, err := amqp.Dial(p.cfg.URL)
	if err != nil {
		return fmt.Errorf("connect rabbitmq: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("open rabbitmq channel: %w", err)
	}
	if err := declareTopology(ch, p.cfg, nil); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return err
	}
	if err := ch.Confirm(false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return fmt.Errorf("enable rabbitmq confirms: %w", err)
	}
	p.conn, p.ch = conn, ch
	p.confirms = ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	return nil
}

func (p *Publisher) Publish(ctx context.Context, routingKey string, msg Message) error {
	return p.publish(ctx, p.cfg.Exchange, routingKey, msg)
}

func (p *Publisher) PublishRetry(ctx context.Context, routingKey string, msg Message) error {
	return p.publish(ctx, p.cfg.RetryExchange, routingKey, msg)
}

// PublishRunResult 回报一次 run 的完成结果。路由键固定在包里, 不交给调用方 ——
// 三个业务服务各拼一遍就等于三处都能拼错, 而拼错的后果是消息被静默丢弃。
func (p *Publisher) PublishRunResult(ctx context.Context, runID, taskID int64, res RunResult) error {
	msg, err := NewRunResultMessage(runID, taskID, res)
	if err != nil {
		return err
	}
	return p.Publish(ctx, RunFinished, msg)
}

// EnsureQueue declares the durable queue and its retry/dead-letter topology
// before a publisher starts draining an outbox. Without this startup step, a
// broker can confirm a message published to an exchange that has no consumer
// binding yet, which would silently drop the message.
func (p *Publisher) EnsureQueue(queue string, routingKeys []string) error {
	if strings.TrimSpace(queue) == "" {
		return errors.New("rabbitmq queue is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.connectLocked(); err != nil {
		return err
	}
	if err := declareTopology(p.ch, p.cfg, &queueSpec{queue: queue, routingKeys: routingKeys}); err != nil {
		p.resetLocked()
		return err
	}
	return nil
}

func (p *Publisher) publish(ctx context.Context, exchange, routingKey string, msg Message) error {
	body, err := msg.Marshal()
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.connectLocked(); err != nil {
		return err
	}
	err = p.ch.PublishWithContext(ctx, exchange, routingKey, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		MessageId:    msg.MessageID,
		Type:         msg.TaskType,
		Body:         body,
		Timestamp:    time.Now().UTC(),
	})
	if err != nil {
		p.resetLocked()
		return fmt.Errorf("publish task message: %w", err)
	}
	confirmTimeout := time.NewTimer(p.cfg.ConfirmTimeout)
	defer confirmTimeout.Stop()
	select {
	case <-ctx.Done():
		p.resetLocked()
		return ctx.Err()
	case <-confirmTimeout.C:
		p.resetLocked()
		return errors.New("rabbitmq publisher confirm timeout")
	case confirmation, ok := <-p.confirms:
		if !ok || !confirmation.Ack {
			p.resetLocked()
			return errors.New("rabbitmq publisher rejected message")
		}
		return nil
	}
}

func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

func (p *Publisher) closeLocked() error {
	var err error
	if p.ch != nil {
		err = p.ch.Close()
	}
	if p.conn != nil {
		if closeErr := p.conn.Close(); err == nil {
			err = closeErr
		}
	}
	p.ch, p.conn, p.confirms = nil, nil, nil
	return err
}

func (p *Publisher) resetLocked() {
	_ = p.closeLocked()
}

// Consumer reconnects after a broker or channel failure. A successful
// handler ack removes the command; failed commands are republished to the
// TTL retry queue with an incremented attempt, and only the final failure is
// rejected into the queue's dead-letter queue.
type Consumer struct {
	cfg Config
	log *zap.Logger
	pub *Publisher
}

func NewConsumer(cfg Config, log *zap.Logger) (*Consumer, error) {
	if log == nil {
		log = zap.NewNop()
	}
	pub, err := NewPublisher(cfg, log)
	if err != nil {
		return nil, err
	}
	return &Consumer{cfg: cfg.normalized(), log: log, pub: pub}, nil
}

func (c *Consumer) Close() error {
	if c == nil || c.pub == nil {
		return nil
	}
	return c.pub.Close()
}

type Handler func(context.Context, Message) error

func (c *Consumer) Run(ctx context.Context, queue string, routingKeys []string, handler Handler) error {
	if strings.TrimSpace(queue) == "" {
		return errors.New("rabbitmq queue is required")
	}
	if handler == nil {
		return errors.New("rabbitmq handler is required")
	}
	for ctx.Err() == nil {
		if err := c.consumeOnce(ctx, queue, routingKeys, handler); err != nil && ctx.Err() == nil {
			c.log.Warn("taskbus consumer disconnected", zap.String("queue", queue), zap.Error(err))
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
	return ctx.Err()
}

func (c *Consumer) consumeOnce(ctx context.Context, queue string, routingKeys []string, handler Handler) error {
	conn, err := amqp.Dial(c.cfg.URL)
	if err != nil {
		return fmt.Errorf("connect consumer: %w", err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("open consumer channel: %w", err)
	}
	defer ch.Close()
	if err := declareTopology(ch, c.cfg, &queueSpec{queue: queue, routingKeys: routingKeys}); err != nil {
		return err
	}
	if err := ch.Qos(c.cfg.Prefetch, 0, false); err != nil {
		return fmt.Errorf("set consumer prefetch: %w", err)
	}
	deliveries, err := ch.Consume(queue, "", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("start consumer: %w", err)
	}
	closeCh := make(chan *amqp.Error, 1)
	conn.NotifyClose(closeCh)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case closeErr := <-closeCh:
			if closeErr == nil {
				return errors.New("rabbitmq connection closed")
			}
			return closeErr
		case delivery, ok := <-deliveries:
			if !ok {
				return errors.New("rabbitmq delivery channel closed")
			}
			c.handleDelivery(ctx, queue, delivery, handler)
		}
	}
}

func (c *Consumer) handleDelivery(ctx context.Context, queue string, delivery amqp.Delivery, handler Handler) {
	msg, err := Decode(delivery.Body)
	if err != nil {
		c.log.Error("rejecting malformed task message", zap.String("queue", queue), zap.Error(err))
		_ = delivery.Reject(false)
		return
	}
	if err := handler(ctx, msg); err == nil {
		_ = delivery.Ack(false)
		return
	} else if msg.Attempt < c.cfg.MaxAttempts {
		msg.Attempt++
		retryCtx, cancel := context.WithTimeout(context.Background(), c.cfg.ConfirmTimeout)
		retryErr := c.pub.PublishRetry(retryCtx, msg.TaskType, msg)
		cancel()
		if retryErr == nil {
			_ = delivery.Ack(false)
			c.log.Warn("task message scheduled for retry", zap.String("task_type", msg.TaskType), zap.Int64("run_id", msg.RunID), zap.Int("attempt", msg.Attempt))
			return
		}
		c.log.Error("failed to schedule task retry; requeueing original", zap.String("task_type", msg.TaskType), zap.Int64("run_id", msg.RunID), zap.Error(retryErr))
		_ = delivery.Nack(false, true)
		return
	}

	c.log.Error("task message exhausted retries", zap.String("task_type", msg.TaskType), zap.Int64("run_id", msg.RunID), zap.Int("attempt", msg.Attempt))
	_ = delivery.Reject(false)
}

type queueSpec struct {
	queue       string
	routingKeys []string
}

func declareTopology(ch *amqp.Channel, cfg Config, spec *queueSpec) error {
	if err := ch.ExchangeDeclare(cfg.Exchange, "topic", true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare task exchange: %w", err)
	}
	if err := ch.ExchangeDeclare(cfg.RetryExchange, "direct", true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare retry exchange: %w", err)
	}
	if err := ch.ExchangeDeclare(cfg.DeadExchange, "direct", true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare dead-letter exchange: %w", err)
	}
	if spec == nil {
		return nil
	}
	mainArgs := amqp.Table{
		"x-dead-letter-exchange":    cfg.DeadExchange,
		"x-dead-letter-routing-key": spec.queue,
	}
	if _, err := ch.QueueDeclare(spec.queue, true, false, false, false, mainArgs); err != nil {
		return fmt.Errorf("declare task queue %s: %w", spec.queue, err)
	}
	deadQueue := spec.queue + ".dead"
	if _, err := ch.QueueDeclare(deadQueue, true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare dead-letter queue %s: %w", deadQueue, err)
	}
	if err := ch.QueueBind(deadQueue, spec.queue, cfg.DeadExchange, false, nil); err != nil {
		return fmt.Errorf("bind dead-letter queue %s: %w", deadQueue, err)
	}
	retryQueue := spec.queue + ".retry"
	retryArgs := amqp.Table{
		"x-message-ttl":          int32(cfg.RetryDelay.Milliseconds()),
		"x-dead-letter-exchange": cfg.Exchange,
	}
	if _, err := ch.QueueDeclare(retryQueue, true, false, false, false, retryArgs); err != nil {
		return fmt.Errorf("declare retry queue %s: %w", retryQueue, err)
	}
	for _, key := range spec.routingKeys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		if err := ch.QueueBind(spec.queue, key, cfg.Exchange, false, nil); err != nil {
			return fmt.Errorf("bind task queue %s with %s: %w", spec.queue, key, err)
		}
		if err := ch.QueueBind(retryQueue, key, cfg.RetryExchange, false, nil); err != nil {
			return fmt.Errorf("bind retry queue %s with %s: %w", retryQueue, key, err)
		}
	}
	return nil
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
