package signals

import (
	"os"
	"testing"
)

func TestOnSignal(t *testing.T) {
	// Number of actions to attach.
	actionCount := 10

	// Channel to help verify action invocations.
	actionChan := make(chan struct{}, actionCount)
	defer close(actionChan)

	// Add actions. Their invocations will be verified.
	for i := 0; i < actionCount; i++ {
		OnSignal(func(_ os.Signal) { actionChan <- struct{}{} })
	}

	// Trigger actions manually.
	Manual()
	// Wait until all actions execute.
	Wait()

	// Verifying if all actions got called.
	for i := 0; i < actionCount; i++ {
		select {
		case <-actionChan:
		default:
			t.Errorf("action channel expected to have %d elements, found %d", actionCount, i)
		}
	}
}
