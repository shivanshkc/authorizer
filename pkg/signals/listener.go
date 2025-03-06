package signals

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// defaultListener is a convenience as in most cases we only need to handle SIGINT and SIGTERM.
// This allows users to directly call the "signals.OnSignal" function without having to create a listener first.
// This is similar to what the net/http package does by creating a global HTTP client.
var defaultListener = NewListener(syscall.SIGINT, syscall.SIGTERM)

// OnSignal accepts an action function that will be executed whenever a signal is detected.
// It can be called multiple times to add more functions. The action functions will be called concurrently.
func OnSignal(action func(os.Signal)) {
	defaultListener.OnSignal(action)
}

// Wait blocks until all actions have been executed.
func Wait() {
	defaultListener.Wait()
}

// Manual trigger for action execution.
//
// Note that this will have no effect in case a signal has already been detected.
func Manual() {
	defaultListener.Manual()
}

// Listener listens to signals and allows actions to be called whenever a signal is received.
type Listener struct {
	// sigChan is where signals are originally received.
	sigChan chan os.Signal
	// actions is the list of actions to be called.
	actions []func(os.Signal)
	// actionsMutex keeps the actions slice thread safe to use.
	actionsMutex *sync.RWMutex
	// actionsWaitChan receives an event as soon as all actions are done executing.
	actionsWaitChan chan struct{}
}

// NewListener creates a new Listener instance with the given signals.
func NewListener(sigs ...os.Signal) *Listener {
	if len(sigs) == 0 {
		panic("no signals provided")
	}

	// Instantiate the listener.
	listener := &Listener{
		// If the Manual method is called *after* an interruption is received, then sigChan may receive two elements.
		// The first would be through signal.Notify and the second may be through the Manual method. In this case, the
		// second element should be ignored and that's why sigChan has a length of 1, to accommodate the extra element.
		sigChan:         make(chan os.Signal, 1),
		actions:         nil,
		actionsMutex:    &sync.RWMutex{},
		actionsWaitChan: make(chan struct{}),
	}

	// Listen to the required signals.
	signal.Notify(listener.sigChan, sigs...)

	// Wait-group to wait until all actions have been executed.
	actionWG := sync.WaitGroup{}

	// This goroutine schedules action execution.
	go func() {
		var sig os.Signal

		// Wait for a signal.
		<-listener.sigChan
		// No need to listen for further signals.
		signal.Stop(listener.sigChan)

		// Read lock.
		listener.actionsMutex.RLock()
		defer listener.actionsMutex.RUnlock()

		// Add delta for all actions.
		actionWG.Add(len(listener.actions))

		// Call actions.
		for _, action := range listener.actions {
			// Call the action and mark the wait-group done.
			go func() {
				defer actionWG.Done()
				action(sig)
			}()
		}

		// Wait for all actions to complete.
		actionWG.Wait()
		// Let the caller know that actions have been executed.
		listener.actionsWaitChan <- struct{}{}
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

// Wait blocks until all actions have been executed.
//
// The listener instance is no longer usable once this method is called.
func (l *Listener) Wait() {
	<-l.actionsWaitChan
	close(l.sigChan)
	close(l.actionsWaitChan)
}

// Manual trigger for action execution.
// This can be deferred in the main function to run cleanup actions even if no interruptions are detected.
//
// Note that this will have no effect in case a signal has already been detected.
func (l *Listener) Manual() {
	l.sigChan <- syscall.SIGINT
}
