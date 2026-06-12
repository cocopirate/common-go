package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRunRejectsNilServer(t *testing.T) {
	err := Run(context.Background(), nil, time.Second)
	if !errors.Is(err, ErrNilServer) {
		t.Fatalf("Run() error = %v, want %v", err, ErrNilServer)
	}
}

func TestRunReturnsListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen occupied port: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		ReadHeaderTimeout: time.Second,
	}

	err = Run(context.Background(), srv, time.Second)
	if err == nil {
		t.Fatal("Run() error = nil, want listen error")
	}
}

func TestRunShutsDownWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{
		Addr:              "127.0.0.1:0",
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		ReadHeaderTimeout: time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, srv, time.Second)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after context cancellation")
	}
}
