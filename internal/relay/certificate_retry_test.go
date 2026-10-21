package relay

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// A relay that cannot get its certificate keeps running and tries again later.
// It used to return the error, the process exited, the supervisor restarted it
// at once, and each restart was another order with the certificate authority,
// so a broken DNS record spent the account's rate limits in minutes.
func TestAFailedCertificateIsRetriedNotFatal(t *testing.T) {
	first, last := firstRetry, lastRetry
	firstRetry, lastRetry = 10*time.Millisecond, 40*time.Millisecond
	defer func() { firstRetry, lastRetry = first, last }()

	var attempts atomic.Int32
	w := &wildcardCert{apex: "relay.test", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.obtain = func() error {
		if attempts.Add(1) < 3 {
			return errors.New("the DNS record went somewhere else")
		}
		return nil
	}
	stop := make(chan struct{})
	defer close(stop)

	if err := w.keep(stop); err != nil {
		t.Fatalf("keep returned %v; a failed attempt must not stop the relay", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for attempts.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := attempts.Load(); n < 3 {
		t.Fatalf("tried %d times; a failure must be retried until it succeeds", n)
	}
	time.Sleep(100 * time.Millisecond)
	if n := attempts.Load(); n != 3 {
		t.Fatalf("tried %d times; once it succeeds it must wait for the next renewal check", n)
	}
}
