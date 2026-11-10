// Package fetch measures remote resources.
package fetch

import "sync"

// Size reports the size in bytes of the resource at url.
type Size func(url string) (int, error)

// First returns the size of the first url whose size can be read.
func First(urls []string, size Size) (int, bool) {
	for _, u := range urls {
		if n, err := size(u); err == nil {
			return n, true
		}
	}
	return 0, false
}

// All returns the sizes of every url whose size can be read, reading them
// concurrently. The order of the result is unspecified.
func All(urls []string, size Size) []int {
	var sizes []int
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := size(u); err == nil {
				sizes = append(sizes, n)
			}
		}()
	}
	wg.Wait()
	return sizes
}
