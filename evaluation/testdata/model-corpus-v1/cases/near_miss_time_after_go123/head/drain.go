// Package queue consumes event channels.
package queue

import "time"

// Event is one queued notification.
type Event struct {
	Name string
}

// Drain passes events from in to handle until in is closed or no event has
// arrived for idle, and returns how many events it handled.
func Drain(in <-chan Event, idle time.Duration, handle func(Event)) int {
	count := 0
	for {
		select {
		case ev, ok := <-in:
			if !ok {
				return count
			}
			handle(ev)
			count++
		case <-time.After(idle):
			return count
		}
	}
}
