package taskbus

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func TestRabbitMQRoundTrip(t *testing.T) {
	url := os.Getenv("TASKBUS_INTEGRATION_URL")
	if url == "" {
		t.Skip("set TASKBUS_INTEGRATION_URL to run the RabbitMQ integration test")
	}

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	queue := "opengo.taskbus.test." + suffix
	routingKey := "taskbus.test." + suffix
	cfg := Config{URL: url, RetryDelay: 100 * time.Millisecond}

	consumer, err := NewConsumer(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewConsumer() error = %v", err)
	}
	defer consumer.Close()
	publisher, err := NewPublisher(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	defer publisher.Close()
	if err := publisher.EnsureQueue(queue, []string{routingKey}); err != nil {
		t.Fatalf("EnsureQueue() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := make(chan Message, 1)
	retryAttempts := make(chan int, 3)
	want := NewMessage(1, 2, routingKey, json.RawMessage(`{"smoke":true}`), nil)
	retryWant := NewMessage(3, 4, routingKey, json.RawMessage(`{"retry":true}`), nil)
	consumerDone := make(chan error, 1)
	go func() {
		consumerDone <- consumer.Run(ctx, queue, []string{routingKey}, func(_ context.Context, msg Message) error {
			if msg.MessageID == retryWant.MessageID {
				retryAttempts <- msg.Attempt
				if msg.Attempt < 3 {
					return errors.New("integration retry")
				}
			}
			received <- msg
			return nil
		})
	}()

	if !waitForQueue(url, queue, 5*time.Second) {
		t.Fatal("consumer queue was not declared")
	}

	if err := publisher.Publish(context.Background(), routingKey, want); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	select {
	case got := <-received:
		if got.MessageID != want.MessageID || got.RunID != want.RunID || string(got.Params) != string(want.Params) {
			t.Fatalf("received = %+v, want = %+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for task message")
	}
	if err := publisher.Publish(context.Background(), routingKey, retryWant); err != nil {
		t.Fatalf("Publish() retry candidate error = %v", err)
	}
	for expected := 1; expected <= 3; expected++ {
		select {
		case attempt := <-retryAttempts:
			if attempt != expected {
				t.Fatalf("retry attempt = %d, want %d", attempt, expected)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for retry attempt %d", expected)
		}
	}
	select {
	case got := <-received:
		if got.MessageID != retryWant.MessageID || got.Attempt != 3 {
			t.Fatalf("retried message = %+v, want message_id=%s attempt=3", got, retryWant.MessageID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for successful retry")
	}

	cancel()
	select {
	case err := <-consumerDone:
		if err != nil && err != context.Canceled {
			t.Fatalf("consumer.Run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("consumer did not stop after cancellation")
	}

	deleteTestQueues(t, url, queue)
}

func waitForQueue(url, queue string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := amqp.Dial(url)
		if err == nil {
			ch, channelErr := conn.Channel()
			if channelErr == nil {
				_, channelErr = ch.QueueDeclarePassive(queue, true, false, false, false, nil)
				_ = ch.Close()
			}
			_ = conn.Close()
			if channelErr == nil {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func deleteTestQueues(t *testing.T, url, queue string) {
	t.Helper()
	conn, err := amqp.Dial(url)
	if err != nil {
		t.Logf("cleanup connection error = %v", err)
		return
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		t.Logf("cleanup channel error = %v", err)
		return
	}
	defer ch.Close()
	for _, name := range []string{queue, queue + ".retry", queue + ".dead"} {
		if _, err := ch.QueueDelete(name, false, false, false); err != nil {
			t.Logf("delete queue %s: %v", name, err)
		}
	}
}
