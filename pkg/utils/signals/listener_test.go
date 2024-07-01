package signals

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestOnSignal(t *testing.T) {
	// Number of actions to attach.
	actionCount := 10

	// Channel to help verify action invocations.
	actionChan := make(chan struct{}, actionCount)
	defer close(actionChan)

	// Add actions. Their invocations will be verified.
	for i := 0; i < actionCount; i++ {
		OnSignal(func(_ os.Signal) {
			actionChan <- struct{}{}
		})
	}

	// Send a SIGINT manually.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Errorf("unexpected error in syscall.Kill call: %v", err)
		return
	}

	// Verifying if all actions got called.
	for i := 0; i < actionCount; i++ {
		select {
		case <-actionChan:
		case <-time.After(1 * time.Second):
			t.Errorf("action was not called until 1 second of passing the signal")
			return
		}
	}
}
