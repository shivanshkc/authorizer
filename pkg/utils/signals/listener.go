package signals

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// globalListener is a convenience as in most cases we only need to handle SIGINT and SIGTERM.
// This allows users to directly call the "signals.OnSignal" function without having to create a listener first.
// This is similar to what the net/http package does by creating a global http client.
var globalListener = NewListener(syscall.SIGINT, syscall.SIGTERM)

// OnSignal accepts an action function that will be executed whenever a signal is detected.
// It can be called multiple times to add more functions. The action functions will be called concurrently.
func OnSignal(action func(os.Signal)) {
	globalListener.OnSignal(action)
}

// Listener listens to signals and allows actions to be called whenever a signal is received.
type Listener struct {
	// sigChan is where signals are originally received.
	sigChan chan os.Signal
	// actions is the list of actions to be called.
	actions []func(os.Signal)
	// actionsMutex keeps the actions slice thread safe to use.
	actionsMutex *sync.RWMutex
}

// NewListener creates a new Listener instance with the given signals.
func NewListener(sigs ...os.Signal) *Listener {
	if len(sigs) == 0 {
		panic("no signals provided")
	}

	// Instantiate the listener.
	listener := &Listener{
		sigChan:      make(chan os.Signal, 1),
		actions:      nil,
		actionsMutex: &sync.RWMutex{},
	}

	// Listen to the required signals.
	signal.Notify(listener.sigChan, sigs...)

	// This goroutine makes sure that all actions are called upon signal reception.
	go func() {
		var sig os.Signal

		// Block until a signal is detected.
		<-listener.sigChan

		// Read lock.
		listener.actionsMutex.RLock()
		defer listener.actionsMutex.RUnlock()

		// Call actions.
		for _, action := range listener.actions {
			go action(sig)
		}
	}()

	return listener
}

// OnSignal accepts an action function that will be executed whenever a signal is detected.
// It can be called multiple times to add more functions. The action functions will be called concurrently.
func (l *Listener) OnSignal(action func(os.Signal)) {
	// Write lock.
	l.actionsMutex.Lock()
	defer l.actionsMutex.Unlock()

	// Add the action.
	if action != nil {
		l.actions = append(l.actions, action)
	}
}
