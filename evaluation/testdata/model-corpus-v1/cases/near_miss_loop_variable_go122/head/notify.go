// Package notify fans messages out to subscribers.
package notify

import "sync"

// Subscriber receives notifications.
type Subscriber interface {
	Notify(message string) error
}

// NotifyAll sends message to every subscriber concurrently. The error for
// subscribers[i] is stored at index i of the result.
func NotifyAll(subscribers []Subscriber, message string) []error {
	errs := make([]error, len(subscribers))
	var wg sync.WaitGroup
	for i, sub := range subscribers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = sub.Notify(message)
		}()
	}
	wg.Wait()
	return errs
}
