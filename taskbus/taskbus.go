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
	DefaultExchange = "opengo.tasks"
	// Retry 改为共享 exchange/queue（2026-11）。旧版本的 `opengo.tasks.retry`
	// 与每条队列的 `<queue>.retry` 不再由新代码声明；升级并排空旧队列后删除。
	DefaultRetryExchange = "opengo.tasks.retry.shared"
	DefaultDeadExchange  = "opengo.tasks.dead"

	// SharedRetryQueue / SharedDeadQueue 是整个环境共享的两条辅助队列。
	// 共享 retry 队列的 x-message-ttl 来自各进程的 RetryDelay，所有服务必须配置
	// 相同的 TASKBUS_RETRY_DELAY_SECONDS，否则 QueueDeclare 会 406。
	SharedRetryQueue = "opengo.tasks.shared.retry"
	SharedDeadQueue  = "opengo.tasks.shared.dead"

	// 命令队列: scheduler 出站 (outbox) → 业务服务消费。
	WorkorderQueue = "opengo.workorder.tasks"
	LeadQueue      = "opengo.lead.tasks"
	// LeadLongQueue 收纳 lead 的长跑命令：抽佣同步 + 申诉同步/检测/批量处置。
	// 它们与短命令（通话检测）分开，避免小时级任务堵住队头；长任务之间按 FIFO 串行，
	// 这是用一条长队列换掉原来 rake/complaint 两条队列时接受的代价。
	//
	// 批量同意/拒绝会经 legacy-bff 回写旧系统，排在长队列里时 timeout_seconds
	// 必须把前面长任务的排队时间算进去。
	LeadLongQueue = "opengo.lead.long.tasks"
	// DownloadQueue 只承载 download.export_artifact.cleanup 这一个任务类型, 所以不另拆
	// (lead 拆 long 是因为 call-check 会被长跑堵住, 这里没有并列的第二类命令)。
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
	// 与 LeadLongQueue 的拆分理由 (长跑堵住并列命令) 不冲突: 这里两者本就该一前一后,
	// 串行是想要的语义而不是代价。
	MerchantQueue = "opengo.merchant.tasks"
	// FinanceQueue 承载客资抽佣日账单与易宝资金账单两条日结命令, 不拆开:
	//
	//  1. 两条都是"受理/生成"型 —— 一个按网点生成账单, 一个只是把易宝的取数登记成
	//     一行任务 (真正的同步由易宝回调触发), 秒级到分钟级, 没有长跑堵队头的问题;
	//  2. 两者之间没有顺序依赖, 也不抢同一个下游 —— 与 MerchantQueue 的"故意串行"
	//     不同, 这里共享只是省一条队列, 代价是后到的那条要等前面跑完,
	//     所以两条任务的 timeout_seconds 都要把排队时间算进去。
	FinanceQueue = "opengo.finance.tasks"
	// FinanceLongQueue 是 finance 的长任务队列（当前只有平安对账 sweep）。
	// 与 FinanceQueue 分开：平安对账是分钟级串行 sweep，不能堵住两条日结命令；
	// 多日补账是小时级，和每日那次在同一条长队列里 FIFO。
	FinanceLongQueue = "opengo.finance.long.tasks"
	// OrderQueue 承载旧订单域的同步命令 (当前只有 order.ruku_kezi_audit.sync)。
	//
	// 单独一条队列而不是与别的服务共用: 全量同步 (days=0) 要顺序扫旧库 5000 万行
	// order 表, 是小时级长跑, 而消费循环是同步的 —— 与 LeadLongQueue 的拆分理由
	// 相同。同时它也把"旧 MySQL 慢/不可用"的失败与重试计数与其他服务隔开。
	OrderQueue = "opengo.order.tasks"
	// VoiceQueue 承载 voice-service 的旧库通话记录同步 (voice.call_record.sync)。
	//
	// 首次回填要按主键扫旧库 1200 万行 vircall_record (每轮有预算、断点续传),
	// 是小时级长跑; 消费循环是同步的, 与 OrderQueue 的拆分理由相同 —— 不能让它
	// 堵住 voice 后续新增的其它命令, 也把"旧 MySQL 慢/不可用"的重试计数单独隔开。
	VoiceQueue = "opengo.voice.tasks"
	// MetadataQueue 只承载 metadata.amap_region.sync 这一个任务类型, 所以不另拆。
	//
	// 它是**每周一次**的全量抓取 (省/市/区 + 逐区拉街道, 约 2900 次串行 HTTP), 一次要跑
	// 分钟级到十几分钟, 而消费循环是同步的 —— 但这条队列上没有并列的第二类命令, 拆分的
	// 理由 (长跑堵住队头, 见 LeadLongQueue) 在这里不存在。
	//
	// 结果落 common_administrative_regions, 是**唯一**一份行政区划数据: 没有它, 依赖
	// 区划的地址选择器就是一张空表, 而高德的配额 (个人认证每月十几万次) 撑得住每周全量。
	MetadataQueue = "opengo.metadata.tasks"
	// 结果队列: 业务服务回报 → scheduler 消费, 方向与上面相反。正因为它反向,
	// **发起 run 的业务服务也要在启动时 EnsureQueue 它**: exchange 上还没有绑定时,
	// publisher confirm 依然 ACK, 消息会被静默丢弃 (见 Publisher.EnsureQueue)。
	SchedulerQueue = "opengo.scheduler.tasks"

	// **任务类型字面量不在这里**。它们一度是本包的一组常量, 但那让"给某个服务加一个定时
	// 任务"变成一次 common-go 发版 + 全部消费方抬版本 —— 而 task type 是业务词汇, 不是
	// 总线机制: 命名、参数、成败判定都只有拥有它的那个服务说了算 (2026-10 改)。
	//
	// 现在每个类型住在**消费它的服务**里 (声明在 handler 所在包, 名字统一 TaskType*),
	// 调度侧 (scheduler-service 的 internal/task) 留一份副本 —— 它要在注册表与路由表里
	// 引用这些值, 名字是调度侧的叫法, **值必须一致**。两份副本之间没有编译器, 由
	// tools/routecheck 的 taskbus 检查比对:
	// scheduler 路由表里的每个类型都要有且只有一个消费方, 消费方绑的队列也要与队列表一致。
	//
	// 本包只留**两端必须逐字一致、且与业务无关**的东西: exchange、队列名 (含 retry/dead
	// 的派生规则)、回执类型 RunFinished、以及下面的信封与错误码。队列名留着是因为它是
	// 拓扑: 两个方向都在声明它, 放在共享模块里改名是编译错误, 挪进服务就只剩工具在管。
	//
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
	// Deadline 是这一轮 run 的绝对截止时间 (scheduler 用 started_at + timeout_seconds
	// 算出)。它让消费方知道"调度台什么时候会把这轮标成 timeout":
	//
	//   - 消费到时已经过期: 这轮注定是 timeout, 再执行只会占住长队列 (FIFO), 直接 ack 丢弃;
	//   - 未过期: 用这个截止时间约束 handler 的 context, 到点让 DB/HTTP 调用返回。
	//
	// 老 scheduler 不发这个字段 (nil) 时行为与从前一致: 不丢弃、不设截止时间。
	Deadline *time.Time `json:"deadline,omitempty"`
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
	Status string `json:"status"` // success | failed
	// ErrorCode 只在 failed 时有值, 是错误分类的唯一机器可读出口 (见 ErrorCode 与 ErrCode*)。
	// 老生产者不填, 于是历史回执与灰度期的回执都是空串, 落库为 NULL。
	ErrorCode    ErrorCode       `json:"error_code,omitempty"`
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
	// SharedQueuePrefix 可选：给共享 retry/dead 队列名加前缀。生产留空；
	// 集成测试用唯一前缀，避免和正在运行的服务共用 TTL/队列声明。
	SharedQueuePrefix string
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

func (c Config) sharedQueueNames() (retry, dead string) {
	if prefix := strings.TrimSpace(c.SharedQueuePrefix); prefix != "" {
		return prefix + ".retry", prefix + ".dead"
	}
	return SharedRetryQueue, SharedDeadQueue
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

// EnsureQueue declares the durable queue and binds the shared retry/dead-letter
// topology before a publisher starts draining an outbox. Without this startup step,
// a broker can confirm a message published to an exchange that has no consumer
// binding yet, which would silently drop the message.
//
// 2026-11 起不再为每条队列声明 `<queue>.retry` / `<queue>.dead`；所有队列共用
// SharedRetryQueue / SharedDeadQueue。旧队列在全部服务升级后需要排空并删除。
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
// shared TTL retry queue with an incremented attempt, and only the final
// failure is rejected into the shared dead-letter queue. Both auxiliary
// queues are shared by every task queue in the environment (2026-11) so
// queue occupancy does not grow by two queues per task type.
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

// expired 报告这一轮 run 是否已经过了调度台给的截止时间。
func (m Message) expired(now time.Time) bool {
	return m.Deadline != nil && !now.Before(*m.Deadline)
}

func (c *Consumer) handleDelivery(ctx context.Context, queue string, delivery amqp.Delivery, handler Handler) {
	msg, err := Decode(delivery.Body)
	if err != nil {
		c.log.Error("rejecting malformed task message", zap.String("queue", queue), zap.Error(err))
		_ = delivery.Reject(false)
		return
	}
	// 投递到消费之间的排队时间。scheduler 的 timeout_seconds 量的是 run 的寿命 (含排队),
	// 长队列 FIFO 时这一行是判断"超时是排队还是执行"的第一手证据。
	if !delivery.Timestamp.IsZero() {
		if delay := time.Since(delivery.Timestamp); delay > 60*time.Second {
			c.log.Warn("task message waited in queue",
				zap.String("queue", queue),
				zap.String("task_type", msg.TaskType),
				zap.Int64("run_id", msg.RunID),
				zap.Duration("queue_delay", delay),
			)
		}
	}
	handlerCtx := ctx
	if msg.Deadline != nil {
		if msg.expired(time.Now()) {
			// 这轮 run 在调度台已经/即将被标 timeout, 再执行一次只会继续占住队列 ——
			// 长队列 FIFO, 后面的命令会跟着一起超时。直接 ack: 不重投, 也不回报
			// (run 已是终态, 回执会被丢弃)。
			c.log.Warn("dropping expired task message",
				zap.String("queue", queue),
				zap.String("task_type", msg.TaskType),
				zap.Int64("run_id", msg.RunID),
				zap.Duration("overdue", time.Since(*msg.Deadline)),
			)
			_ = delivery.Ack(false)
			return
		}
		var cancel context.CancelFunc
		handlerCtx, cancel = context.WithDeadline(ctx, *msg.Deadline)
		defer cancel()
	}
	if err := handler(handlerCtx, msg); err == nil {
		_ = delivery.Ack(false)
		return
	} else if errors.Is(err, context.DeadlineExceeded) {
		// 到点后 handler 的错误多半是 DB/HTTP 调用被 ctx 取消的连带结果。重投只会
		// 再占一轮队列, 而 run 的终态由 scheduler 负责。
		c.log.Warn("task message deadline exceeded; not retrying",
			zap.String("task_type", msg.TaskType),
			zap.Int64("run_id", msg.RunID),
			zap.Error(err),
		)
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
	retryQueue, deadQueue := cfg.sharedQueueNames()

	// 共享 dead 队列：每条主队列的 DLX 仍指向 cfg.DeadExchange，用 queue 名做
	// 路由键；这里只绑一次共享队列，不再为每条主队列声明 `<queue>.dead`。
	if _, err := ch.QueueDeclare(deadQueue, true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare shared dead-letter queue %s: %w", deadQueue, err)
	}
	if err := ch.QueueBind(deadQueue, spec.queue, cfg.DeadExchange, false, nil); err != nil {
		return fmt.Errorf("bind shared dead-letter queue %s: %w", deadQueue, err)
	}

	mainArgs := amqp.Table{
		"x-dead-letter-exchange":    cfg.DeadExchange,
		"x-dead-letter-routing-key": spec.queue,
	}
	if _, err := ch.QueueDeclare(spec.queue, true, false, false, false, mainArgs); err != nil {
		return fmt.Errorf("declare task queue %s: %w", spec.queue, err)
	}

	// 共享 retry 队列：所有长/短任务共用同一 TTL。消息过期后按原 routing key
	// 回到主 exchange，由对应的主队列消费。所有服务的 RetryDelay 必须一致，
	// 否则同一个队列的 x-message-ttl 声明冲突（406）。
	retryArgs := amqp.Table{
		"x-message-ttl":          int32(cfg.RetryDelay.Milliseconds()),
		"x-dead-letter-exchange": cfg.Exchange,
	}
	if _, err := ch.QueueDeclare(retryQueue, true, false, false, false, retryArgs); err != nil {
		return fmt.Errorf("declare shared retry queue %s: %w", retryQueue, err)
	}
	for _, key := range spec.routingKeys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		if err := ch.QueueBind(spec.queue, key, cfg.Exchange, false, nil); err != nil {
			return fmt.Errorf("bind task queue %s with %s: %w", spec.queue, key, err)
		}
		if err := ch.QueueBind(retryQueue, key, cfg.RetryExchange, false, nil); err != nil {
			return fmt.Errorf("bind shared retry queue %s with %s: %w", retryQueue, key, err)
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
