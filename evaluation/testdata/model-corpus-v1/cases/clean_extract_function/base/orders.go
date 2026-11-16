// Package orders accepts customer orders.
package orders

import (
	"errors"
	"fmt"
)

// ErrInvalid reports an order that fails validation.
var ErrInvalid = errors.New("orders: invalid order")

// Order is one customer order.
type Order struct {
	Customer string
	SKU      string
	Quantity int
}

// Queue collects accepted orders.
type Queue struct {
	accepted []Order
}

// Submit validates o and queues it.
func (q *Queue) Submit(o Order) error {
	if o.Customer == "" {
		return fmt.Errorf("%w: missing customer", ErrInvalid)
	}
	if o.SKU == "" {
		return fmt.Errorf("%w: missing SKU", ErrInvalid)
	}
	if o.Quantity < 1 || o.Quantity > 100 {
		return fmt.Errorf("%w: quantity %d outside 1-100", ErrInvalid, o.Quantity)
	}
	q.accepted = append(q.accepted, o)
	return nil
}

// Len returns the number of queued orders.
func (q *Queue) Len() int {
	return len(q.accepted)
}
