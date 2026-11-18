package checksandbox

import "sync"

// capture keeps at most limit bytes of a stream and calls exceeded once
// when more arrive, so the caller can kill the process tree.
type capture struct {
	mu       sync.Mutex
	limit    int
	data     []byte
	over     bool
	exceeded func()
}

func newCapture(limit int, exceeded func()) *capture {
	return &capture{limit: limit, exceeded: exceeded}
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	room := c.limit - len(c.data)
	if len(p) <= room {
		c.data = append(c.data, p...)
		c.mu.Unlock()
		return len(p), nil
	}
	c.data = append(c.data, p[:max(room, 0)]...)
	first := !c.over
	c.over = true
	c.mu.Unlock()
	if first && c.exceeded != nil {
		c.exceeded()
	}
	return len(p), nil
}

func (c *capture) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.data...)
}

func (c *capture) exceededLimit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.over
}
